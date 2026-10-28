// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef GGL_SVC_H
#define GGL_SVC_H

// Client side of ggl-svcd, the service manager that stands in for systemd
// in the systemd-free portable core (GGL_PORTABLE_CORE).
//
// Protocol: one request line, one response line, over a Unix stream socket.
//   request:  <verb> [arg ...]\n
//   response: ok [payload]\n | err <message>\n
// Verbs: start, stop, restart, reset-failed, link, enable, disable,
// daemon-reload, start-target, show, whois, notify, sd-notify, watch.
// "show <unit>" answers
//   "ok <unit> <ActiveState> <Result> <NRestarts> <InactiveEnterUsec> <job>"
// where <job> is "queued" while a start waits for its dependencies, else
// "idle"; "watch" answers "ok" and then streams one line in the same format
// for every ActiveState change. "whois <pid>" answers "ok <unit>" for the unit
// the process belongs to (by its cgroup). "sd-notify READY|RELOADING|STOPPING"
// applies to the caller's own unit, if it is a Type=notify unit whose
// NotifyAccess= admits the caller. Non-root peers may only use show, whois and
// sd-notify.

#include <stddef.h>

// Outside /run/greengrass, which belongs to the core daemons' user.
#define GGL_SVC_SOCKET "/run/ggl-svc.sock"

/// Connect to ggl-svcd. Returns a socket fd, or -1 with errno set.
int ggl_svc_connect(void);

/// Send one request (without trailing newline) and read the response line
/// into resp (NUL-terminated, without newline). Returns 0 for "ok", 1 for
/// "err", -1 on a transport error (including no answer within 10 s).
int ggl_svc_call(const char *request, char *resp, size_t resp_len);

/// Read one newline-terminated line from fd into buf (NUL-terminated,
/// without newline). Returns the line length, or -1 on EOF/error.
int ggl_svc_read_line(int fd, char *buf, size_t len);

#endif
