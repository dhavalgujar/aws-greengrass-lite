// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// systemd-notify for the systemd-free portable core. recipe-runner ends
// every startup phase script with "systemd-notify --ready" and
// "systemd-notify --stopping"; ggl-svcd applies the notification to the
// unit the calling process belongs to.

#include <ggl/svc.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int status = 0;
    for (int i = 1; i < argc; i++) {
        const char *what = NULL;
        if ((strcmp(argv[i], "--ready") == 0)
            || (strcmp(argv[i], "READY=1") == 0)) {
            what = "READY";
        } else if (
            (strcmp(argv[i], "--reloading") == 0)
            || (strcmp(argv[i], "RELOADING=1") == 0)
        ) {
            what = "RELOADING";
        } else if (
            (strcmp(argv[i], "--stopping") == 0)
            || (strcmp(argv[i], "STOPPING=1") == 0)
        ) {
            what = "STOPPING";
        } else {
            // --status=, --pid=, ... carry nothing ggl-svcd tracks.
            continue;
        }
        char request[32];
        char resp[128];
        (void) snprintf(request, sizeof(request), "sd-notify %s", what);
        int ret = ggl_svc_call(request, resp, sizeof(resp));
        if (ret != 0) {
            fprintf(
                stderr,
                "systemd-notify: %s\n",
                (ret < 0) ? "cannot reach ggl-svcd" : resp
            );
            status = 1;
        }
    }
    return status;
}
