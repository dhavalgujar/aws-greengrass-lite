// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifdef GGL_PORTABLE_CORE

#include "portable.h"
#include "subscriptions.h"
#include <gg/buffer.h>
#include <gg/error.h>
#include <gg/log.h>
#include <gg/map.h>
#include <gg/object.h>
#include <gg/utils.h>
#include <ggl/core_bus/server.h>
#include <ggl/nucleus/constants.h>
#include <ggl/socket_server.h>
#include <ggl/svc.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef GGHEALTHD_MAX_SUBSCRIPTIONS
#define GGHEALTHD_MAX_SUBSCRIPTIONS 10
#endif

// SoA subscription layout, as in the systemd backend.
static uint32_t handles[GGHEALTHD_MAX_SUBSCRIPTIONS];
static size_t component_names_len[GGHEALTHD_MAX_SUBSCRIPTIONS];
static uint8_t component_names[GGHEALTHD_MAX_SUBSCRIPTIONS]
                              [GGL_COMPONENT_NAME_MAX_LEN];

// Single all-component subscriber (ggdeploymentd), as in the systemd backend.
static uint32_t broadcast_handle;

static int watch_fd = -1;

static bool is_terminal_state(GgBuffer status) {
    return gg_buffer_eq(GG_STR("BROKEN"), status)
        || gg_buffer_eq(GG_STR("FINISHED"), status)
        || gg_buffer_eq(GG_STR("RUNNING"), status);
}

static void respond_state_change(
    uint32_t handle, GgBuffer component_name, GgBuffer status
) {
    ggl_sub_respond(
        handle,
        gg_obj_map(GG_MAP(
            gg_kv(GG_STR("component_name"), gg_obj_buf(component_name)),
            gg_kv(GG_STR("lifecycle_state"), gg_obj_buf(status))
        ))
    );
}

static void dispatch_state_change(char *line) {
    char *unit = NULL;
    GgBuffer status = GG_STR("");
    if (portable_parse_unit_line(line, &unit, &status) != GG_ERR_OK) {
        return;
    }
    uint8_t name_bytes[GGL_COMPONENT_NAME_MAX_LEN];
    GgBuffer component_name = GG_BUF(name_bytes);
    if (portable_component_of_unit(unit, &component_name) != GG_ERR_OK) {
        return;
    }
    if (!is_terminal_state(status)) {
        GG_LOGD(
            "%.*s changed to non-terminal state %.*s.",
            (int) component_name.len,
            component_name.data,
            (int) status.len,
            status.data
        );
        return;
    }

    for (int i = 0; i < GGHEALTHD_MAX_SUBSCRIPTIONS; ++i) {
        if ((handles[i] != 0)
            && gg_buffer_eq(
                component_name,
                gg_buffer_substr(
                    GG_BUF(component_names[i]), 0, component_names_len[i]
                )
            )) {
            GG_LOGI(
                "%.*s finished their lifecycle (status=%.*s)",
                (int) component_name.len,
                component_name.data,
                (int) status.len,
                status.data
            );
            respond_state_change(handles[i], component_name, status);
        }
    }

    // Core nucleus services are internal daemons; not broadcast.
    if ((broadcast_handle != 0)
        && !gg_buffer_has_prefix(component_name, GG_STR("core."))) {
        GG_LOGI(
            "Broadcasting component state change: %.*s -> %.*s",
            (int) component_name.len,
            component_name.data,
            (int) status.len,
            status.data
        );
        respond_state_change(broadcast_handle, component_name, status);
    }
}

static void watch_callback(void) {
    char line[GGL_COMPONENT_NAME_MAX_LEN + 128];
    if (ggl_svc_read_line(watch_fd, line, sizeof(line)) < 0) {
        // ggl-svcd went away. It supervises gghealthd, so exiting gets a
        // fresh process with a fresh watch once it is back.
        GG_LOGE("Lost the ggl-svcd state stream; exiting.");
        _Exit(1);
    }
    dispatch_state_change(line);
}

void init_health_events(void) {
    while (true) {
        watch_fd = ggl_svc_connect();
        if (watch_fd >= 0) {
            char resp[64];
            if ((write(watch_fd, "watch\n", 6) == 6)
                && (ggl_svc_read_line(watch_fd, resp, sizeof(resp)) >= 0)
                && (strncmp(resp, "ok", 2) == 0)) {
                break;
            }
            (void) close(watch_fd);
        }
        GG_LOGE("Failed to watch ggl-svcd unit states.");
        (void) gg_sleep(1);
    }
    ggl_socket_server_ext_fd = watch_fd;
    ggl_socket_server_ext_handler = watch_callback;
    GG_LOGD("ggl-svcd watch fd %d", watch_fd);
}

// core-bus functions //

GgError gghealthd_register_lifecycle_subscription(
    GgBuffer component_name, uint32_t handle
) {
    int index = 0;
    for (; index < GGHEALTHD_MAX_SUBSCRIPTIONS; ++index) {
        if (handles[index] == 0) {
            break;
        }
    }
    if (index == GGHEALTHD_MAX_SUBSCRIPTIONS) {
        GG_LOGE("Unable to find open subscription slot.");
        return GG_ERR_NOMEM;
    }
    if (component_name.len > GGL_COMPONENT_NAME_MAX_LEN) {
        return GG_ERR_RANGE;
    }
    memcpy(component_names[index], component_name.data, component_name.len);
    component_names_len[index] = component_name.len;
    handles[index] = handle;
    ggl_sub_accept(handle, gghealthd_unregister_lifecycle_subscription, NULL);
    return GG_ERR_OK;
}

void gghealthd_unregister_lifecycle_subscription(void *ctx, uint32_t handle) {
    (void) ctx;
    for (int index = 0; index < GGHEALTHD_MAX_SUBSCRIPTIONS; ++index) {
        if (handles[index] == handle) {
            handles[index] = 0;
            component_names_len[index] = 0;
        }
    }
}

GgError gghealthd_register_all_component_state_changes_subscription(
    uint32_t handle
) {
    if (broadcast_handle != 0) {
        GG_LOGW(
            "Replacing existing all-component state-change subscriber "
            "(old handle=%" PRIu32 ", new handle=%" PRIu32 ").",
            broadcast_handle,
            handle
        );
    }
    broadcast_handle = handle;
    ggl_sub_accept(
        handle,
        gghealthd_unregister_all_component_state_changes_subscription,
        NULL
    );
    return GG_ERR_OK;
}

void gghealthd_unregister_all_component_state_changes_subscription(
    void *ctx, uint32_t handle
) {
    (void) ctx;
    if (broadcast_handle == handle) {
        broadcast_handle = 0;
    }
}

#endif
