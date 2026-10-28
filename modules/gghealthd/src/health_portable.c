// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifdef GGL_PORTABLE_CORE

#include "bus_client.h"
#include "health.h"
#include "portable.h"
#include "subscriptions.h"
#include <gg/arena.h>
#include <gg/buffer.h>
#include <gg/error.h>
#include <gg/list.h>
#include <gg/log.h>
#include <gg/map.h>
#include <gg/object.h>
#include <ggl/nucleus/constants.h>
#include <ggl/svc.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define UNIT_NAME_MAX_LEN \
    (sizeof(SERVICE_PREFIX) - 1 + GGL_COMPONENT_NAME_MAX_LEN \
     + sizeof(SERVICE_SUFFIX) - 1)

GgError portable_component_of_unit(const char *unit, GgBuffer *component) {
    GgBuffer id = gg_buffer_from_null_term((char *) unit);
    if (!gg_buffer_remove_prefix(&id, GG_STR(SERVICE_PREFIX))
        || !gg_buffer_remove_suffix(&id, GG_STR(SERVICE_SUFFIX))
        || (id.len == 0) || (id.len > component->len)) {
        return GG_ERR_NOENTRY;
    }
    memcpy(component->data, id.data, id.len);
    component->len = id.len;
    return GG_ERR_OK;
}

GgError portable_parse_unit_line(char *line, char **unit, GgBuffer *state) {
    char *save = NULL;
    char *name = strtok_r(line, " ", &save);
    char *active = strtok_r(NULL, " ", &save);
    char *result = strtok_r(NULL, " ", &save);
    char *restarts = strtok_r(NULL, " ", &save);
    char *inactive_ts = strtok_r(NULL, " ", &save);
    if ((name == NULL) || (active == NULL) || (result == NULL)
        || (restarts == NULL) || (inactive_ts == NULL)) {
        GG_LOGE("Malformed ggl-svcd unit status.");
        return GG_ERR_PARSE;
    }
    *unit = name;

    // Same mapping as the systemd backend (sd_bus.c get_lifecycle_state).
    if (strcmp(active, "activating") == 0) {
        *state = GG_STR("STARTING");
    } else if (strcmp(active, "active") == 0) {
        *state = GG_STR("RUNNING");
    } else if (strcmp(active, "deactivating") == 0) {
        *state = GG_STR("STOPPING");
    } else if (strtoull(inactive_ts, NULL, 10) == 0) {
        // inactive or failed but never ran
        *state = GG_STR("INSTALLED");
    } else if (strtoul(restarts, NULL, 10) >= 3) {
        GG_LOGE("Component is broken (Exceeded retry limit)");
        *state = GG_STR("BROKEN");
    } else if (strcmp(result, "success") == 0) {
        *state = GG_STR("FINISHED");
    } else {
        *state = GG_STR("ERRORED");
    }
    return GG_ERR_OK;
}

static GgError unit_name(GgBuffer component_name, char *out, size_t len) {
    if (component_name.len > GGL_COMPONENT_NAME_MAX_LEN) {
        GG_LOGE("component name too long");
        return GG_ERR_RANGE;
    }
    int n = snprintf(
        out,
        len,
        SERVICE_PREFIX "%.*s" SERVICE_SUFFIX,
        (int) component_name.len,
        component_name.data
    );
    return ((n > 0) && ((size_t) n < len)) ? GG_ERR_OK : GG_ERR_RANGE;
}

static GgError svc_call(const char *verb, const char *unit, char *resp) {
    char request[UNIT_NAME_MAX_LEN + 32];
    (void) snprintf(request, sizeof(request), "%s %s", verb, unit);
    char local[UNIT_NAME_MAX_LEN + 96];
    int ret = ggl_svc_call(
        request,
        (resp != NULL) ? resp : local,
        (resp != NULL) ? UNIT_NAME_MAX_LEN + 96 : sizeof(local)
    );
    if (ret < 0) {
        GG_LOGE("Cannot reach ggl-svcd for %s %s.", verb, unit);
        return GG_ERR_NOCONN;
    }
    if (ret > 0) {
        GG_LOGE(
            "ggl-svcd %s %s failed: %s",
            verb,
            unit,
            (resp != NULL) ? resp : local
        );
        return GG_ERR_FAILURE;
    }
    return GG_ERR_OK;
}

GgError gghealthd_get_status(GgBuffer component_name, GgBuffer *status) {
    if (component_name.len > GGL_COMPONENT_NAME_MAX_LEN) {
        GG_LOGE("component_name too long");
        return GG_ERR_RANGE;
    }
    if (gg_buffer_eq(component_name, GG_STR("gghealthd"))) {
        // report own status even if the orchestrator is unreachable
        int fd = ggl_svc_connect();
        if (fd >= 0) {
            (void) close(fd);
            *status = GG_STR("RUNNING");
        } else {
            *status = GG_STR("ERRORED");
        }
        return GG_ERR_OK;
    }

    // only relay lifecycle state for configured components
    GgError err = verify_component_exists(component_name);
    if (err != GG_ERR_OK) {
        return err;
    }

    char unit[UNIT_NAME_MAX_LEN + 1];
    err = unit_name(component_name, unit, sizeof(unit));
    if (err != GG_ERR_OK) {
        return GG_ERR_FAILURE;
    }
    char resp[UNIT_NAME_MAX_LEN + 96];
    err = svc_call("show", unit, resp);
    if (err != GG_ERR_OK) {
        return GG_ERR_FAILURE;
    }
    char *name = NULL;
    return portable_parse_unit_line(resp, &name, status);
}

GgError gghealthd_update_status(GgBuffer component_name, GgBuffer status) {
    const GgMap STATUS_MAP = GG_MAP(
        gg_kv(GG_STR("NEW"), GG_OBJ_NULL),
        gg_kv(GG_STR("INSTALLED"), GG_OBJ_NULL),
        gg_kv(GG_STR("STARTING"), gg_obj_buf(GG_STR("RELOADING"))),
        gg_kv(GG_STR("RUNNING"), gg_obj_buf(GG_STR("READY"))),
        gg_kv(GG_STR("ERRORED"), GG_OBJ_NULL),
        gg_kv(GG_STR("BROKEN"), GG_OBJ_NULL),
        gg_kv(GG_STR("STOPPING"), gg_obj_buf(GG_STR("STOPPING"))),
        gg_kv(GG_STR("FINISHED"), GG_OBJ_NULL)
    );

    GgObject *status_obj = NULL;
    if (!gg_map_get(STATUS_MAP, status, &status_obj)) {
        GG_LOGE("Invalid lifecycle_state");
        return GG_ERR_INVALID;
    }

    GgError err = verify_component_exists(component_name);
    if (err != GG_ERR_OK) {
        return err;
    }
    char unit[UNIT_NAME_MAX_LEN + 1];
    err = unit_name(component_name, unit, sizeof(unit));
    if (err != GG_ERR_OK) {
        return err;
    }
    if (gg_obj_type(*status_obj) == GG_TYPE_NULL) {
        return GG_ERR_OK;
    }

    // Equivalent of systemd-notify --ready|--reloading|--stopping in the
    // component's unit.
    char what[16];
    GgBuffer notify = gg_obj_into_buf(*status_obj);
    (void) snprintf(what, sizeof(what), "%.*s", (int) notify.len, notify.data);
    char request[UNIT_NAME_MAX_LEN + 32];
    (void) snprintf(request, sizeof(request), "%s %s", unit, what);
    err = svc_call("notify", request, NULL);
    if (err != GG_ERR_OK) {
        GG_LOGE("Failed to notify status");
    }

    GG_LOGD(
        "Component %.*s reported state updating to %.*s (%s)",
        (int) component_name.len,
        (const char *) component_name.data,
        (int) status.len,
        status.data,
        what
    );
    return GG_ERR_OK;
}

GgError gghealthd_get_health(GgBuffer *status) {
    int fd = ggl_svc_connect();
    if (fd < 0) {
        *status = GG_STR("UNHEALTHY");
        return GG_ERR_OK;
    }
    (void) close(fd);
    // TODO: check all root components (as the systemd backend)
    *status = GG_STR("HEALTHY");
    return GG_ERR_OK;
}

GgError gghealthd_restart_component(GgBuffer component_name) {
    GgError err = verify_component_exists(component_name);
    if (err != GG_ERR_OK) {
        return err;
    }
    char unit[UNIT_NAME_MAX_LEN + 1];
    err = unit_name(component_name, unit, sizeof(unit));
    if (err != GG_ERR_OK) {
        return GG_ERR_FAILURE;
    }

    // As the systemd backend: IPC-requested restarts do not count towards
    // the burst limit.
    (void) svc_call("reset-failed", unit, NULL);
    err = svc_call("restart", unit, NULL);
    if (err != GG_ERR_OK) {
        return err;
    }
    (void) svc_call("reset-failed", unit, NULL);

    GG_LOGI(
        "Successfully restarted component %.*s",
        (int) component_name.len,
        component_name.data
    );
    return GG_ERR_OK;
}

static bool is_nucleus_component(GgBuffer component_name) {
    static const char *const NUCLEUS[]
        = { "DeploymentService",
            "FleetStatusService",
            "UpdateSystemPolicyService",
            "TelemetryAgent",
            "main",
            "aws.greengrass.fleet_provisioning" };
    for (size_t i = 0; i < sizeof(NUCLEUS) / sizeof(NUCLEUS[0]); i++) {
        if (gg_buffer_eq(
                component_name, gg_buffer_from_null_term((char *) NUCLEUS[i])
            )) {
            return true;
        }
    }
    return is_nucleus_component_type(component_name);
}

static void reset_failed_components(void) {
    static uint8_t component_list_buf[4096];
    GgArena alloc = gg_arena_init(GG_BUF(component_list_buf));
    GgList components;
    GgError ret = get_root_component_list(&alloc, &components);
    if (ret != GG_ERR_OK) {
        GG_LOGW("Failed to get component list.");
        return;
    }
    size_t reset_count = 0;
    GG_LIST_FOREACH (component, components) {
        GgBuffer component_name = gg_obj_into_buf(*component);
        if (is_nucleus_component(component_name)) {
            continue;
        }
        char unit[UNIT_NAME_MAX_LEN + 1];
        if (unit_name(component_name, unit, sizeof(unit)) != GG_ERR_OK) {
            continue;
        }
        ++reset_count;
        (void) svc_call("reset-failed", unit, NULL);
    }
    GG_LOGD("Processed reset-failed for %zu components", reset_count);
}

GgError gghealthd_init(void) {
    reset_failed_components();
    init_health_events();
    return GG_ERR_OK;
}

#endif
