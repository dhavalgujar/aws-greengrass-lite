// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// systemctl for the systemd-free portable core: forwards the subset of
// commands ggdeploymentd issues to ggl-svcd. As with systemd, start, restart
// and stop wait until the unit has settled unless --no-block is given, and
// fail if the start failed.

#include <ggl/svc.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>

// Upper bound for a blocking job; ggl-svcd enforces the unit's own
// TimeoutStartSec/TimeoutStopSec within it.
#define JOB_WAIT_S 600

static int call(const char *verb, const char *arg) {
    char request[768];
    char resp[1024];
    if (arg != NULL) {
        (void) snprintf(request, sizeof(request), "%s %s", verb, arg);
    } else {
        (void) snprintf(request, sizeof(request), "%s", verb);
    }
    int ret = ggl_svc_call(request, resp, sizeof(resp));
    if (ret < 0) {
        perror("systemctl: cannot reach ggl-svcd");
        return 1;
    }
    if (ret != 0) {
        fprintf(stderr, "systemctl %s: %s\n", verb, resp);
    } else if (resp[0] != '\0') {
        printf("%s\n", resp); // show
    }
    return ret;
}

static bool show(
    const char *unit, char *state, size_t state_len, bool *queued
) {
    char request[512];
    char resp[512];
    (void) snprintf(request, sizeof(request), "show %s", unit);
    if (ggl_svc_call(request, resp, sizeof(resp)) != 0) {
        return false;
    }
    char st[32] = "";
    char job[16] = "";
    (void) sscanf(resp, "%*s %31s %*s %*s %*s %15s", st, job);
    (void) snprintf(state, state_len, "%s", st);
    *queued = (strcmp(job, "queued") == 0);
    return true;
}

// Waits until the unit is no longer queued, activating or deactivating.
// For a start, fails if the unit ended failed; a oneshot unit that ran to
// completion ends inactive, which is a success.
static int wait_job(const char *unit, bool start) {
    time_t deadline = time(NULL) + JOB_WAIT_S;
    char state[32];
    bool queued = false;
    while (time(NULL) < deadline) {
        if (!show(unit, state, sizeof(state), &queued)) {
            return 1;
        }
        if (!queued && (strcmp(state, "activating") != 0)
            && (strcmp(state, "deactivating") != 0)) {
            return (start && (strcmp(state, "failed") == 0)) ? 1 : 0;
        }
        (void) usleep(200000);
    }
    fprintf(stderr, "systemctl: timed out waiting for %s\n", unit);
    return 1;
}

// systemd accepts a unit file path (enable links it first) and a unit name
// without the .service suffix; ggl-svcd only takes unit names.
static const char *unit_arg(
    const char *cmd, const char *arg, char *buf, size_t len
) {
    const char *base = strrchr(arg, '/');
    if (base != NULL) {
        if (strcmp(cmd, "enable") == 0) {
            (void) call("link", arg);
        }
        arg = base + 1;
    }
    const char *dot = strrchr(arg, '.');
    if ((dot != NULL)
        && ((strcmp(dot, ".service") == 0) || (strcmp(dot, ".target") == 0))) {
        return arg;
    }
    (void) snprintf(buf, len, "%s.service", arg);
    return buf;
}

int main(int argc, char **argv) {
    // Options may appear anywhere ("systemctl start --no-block unit").
    bool no_block = false;
    const char *args[64];
    int n = 0;
    for (int i = 1; (i < argc) && (n < 64); i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--no-block") == 0) {
                no_block = true;
            }
            // Other options (--quiet, ...) do not change what ggl-svcd does.
            continue;
        }
        args[n++] = argv[i];
    }
    if (n == 0) {
        fprintf(stderr, "usage: systemctl <command> [unit|path ...]\n");
        return 2;
    }
    const char *cmd = args[0];

    if (strcmp(cmd, "reboot") == 0) {
        execl("/sbin/reboot", "reboot", (char *) NULL);
        perror("systemctl: reboot");
        return 1;
    }
    if (strcmp(cmd, "daemon-reload") == 0) {
        return call("daemon-reload", NULL);
    }
    if ((strcmp(cmd, "reset-failed") == 0) && (n == 1)) {
        return call("reset-failed", NULL);
    }
    if ((strcmp(cmd, "start") == 0) && (n > 1)
        && (strcmp(args[1], "greengrass-lite.target") == 0)) {
        return call("start-target", NULL);
    }

    static const char *const per_unit[]
        = { "start",  "stop",    "restart", "reset-failed", "link",
            "enable", "disable", "show",    "is-active" };
    for (size_t v = 0; v < sizeof(per_unit) / sizeof(per_unit[0]); v++) {
        if (strcmp(cmd, per_unit[v]) != 0) {
            continue;
        }
        if (n < 2) {
            fprintf(stderr, "systemctl %s: missing argument\n", cmd);
            return 2;
        }
        int status = 0;
        for (int i = 1; i < n; i++) {
            char name[512];
            const char *arg = args[i];
            if (strcmp(cmd, "link") != 0) {
                arg = unit_arg(cmd, args[i], name, sizeof(name));
            }
            if (strcmp(cmd, "is-active") == 0) {
                char state[32];
                bool queued;
                if (!show(arg, state, sizeof(state), &queued)) {
                    return 3;
                }
                printf("%s\n", state);
                status |= (strcmp(state, "active") == 0) ? 0 : 3;
                continue;
            }
            int ret = call(cmd, arg);
            bool starts
                = (strcmp(cmd, "start") == 0) || (strcmp(cmd, "restart") == 0);
            if ((ret == 0) && !no_block && starts) {
                ret = wait_job(arg, true);
            } else if ((ret == 0) && !no_block && (strcmp(cmd, "stop") == 0)) {
                ret = wait_job(arg, false);
            }
            status |= ret;
        }
        return status;
    }

    fprintf(stderr, "systemctl: unsupported command %s\n", cmd);
    return 1;
}
