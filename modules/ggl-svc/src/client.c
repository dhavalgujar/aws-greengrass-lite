// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <ggl/svc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

// How long a call waits for ggl-svcd, which serves one request at a time:
// systemctl's D-Bus default, also overridden by $SYSTEMD_BUS_TIMEOUT
// (seconds, or a number with a unit: us, ms, s, min, h; "infinity"; unset or
// 0 for the default). Callers fail instead of hanging on a stalled daemon.
#define CALL_TIMEOUT_DEFAULT_US (25ULL * 1000000ULL)

static uint64_t call_timeout_us(void) {
    const char *value = getenv("SYSTEMD_BUS_TIMEOUT");
    if ((value == NULL) || (*value == '\0')) {
        return CALL_TIMEOUT_DEFAULT_US;
    }
    if (strcmp(value, "infinity") == 0) {
        return 0;
    }
    char *end;
    errno = 0;
    double number = strtod(value, &end);
    if ((errno != 0) || (end == value) || !(number >= 0)) {
        return CALL_TIMEOUT_DEFAULT_US;
    }
    while (*end == ' ') {
        end++;
    }
    static const struct {
        const char *unit;
        double us;
    } UNITS[] = {
        { "", 1e6 },
        { "s", 1e6 },
        { "sec", 1e6 },
        { "second", 1e6 },
        { "seconds", 1e6 },
        { "us", 1 },
        { "usec", 1 },
        { "ms", 1e3 },
        { "msec", 1e3 },
        { "m", 60e6 },
        { "min", 60e6 },
        { "minute", 60e6 },
        { "minutes", 60e6 },
        { "h", 3600e6 },
        { "hr", 3600e6 },
        { "hour", 3600e6 },
        { "hours", 3600e6 },
    };
    for (size_t i = 0; i < sizeof(UNITS) / sizeof(UNITS[0]); i++) {
        if (strcmp(end, UNITS[i].unit) == 0) {
            double us = number * UNITS[i].us;
            if ((us < 1) || (us >= 1e15)) {
                return CALL_TIMEOUT_DEFAULT_US;
            }
            return (uint64_t) us;
        }
    }
    return CALL_TIMEOUT_DEFAULT_US;
}

int ggl_svc_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, GGL_SVC_SOCKET, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        int saved = errno;
        (void) close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int ggl_svc_read_line(int fd, char *buf, size_t len) {
    size_t used = 0;
    while (used + 1 < len) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        if (c == '\n') {
            break;
        }
        buf[used++] = c;
    }
    buf[used] = '\0';
    return (int) used;
}

static int write_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        data += n;
        len -= (size_t) n;
    }
    return 0;
}

int ggl_svc_call(const char *request, char *resp, size_t resp_len) {
    int fd = ggl_svc_connect();
    if (fd < 0) {
        return -1;
    }
    // A zero timeval waits without limit ("infinity").
    uint64_t timeout_us = call_timeout_us();
    struct timeval timeout = {
        .tv_sec = (time_t) (timeout_us / 1000000U),
        .tv_usec = (suseconds_t) (timeout_us % 1000000U),
    };
    (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    char line[1024];
    size_t req_len = strlen(request);
    if (req_len + 2 > sizeof(line)) {
        (void) close(fd);
        errno = EMSGSIZE;
        return -1;
    }
    memcpy(line, request, req_len);
    line[req_len] = '\n';
    int ret = write_all(fd, line, req_len + 1);
    if (ret == 0) {
        ret = ggl_svc_read_line(fd, line, sizeof(line));
    }
    (void) close(fd);
    if (ret < 0) {
        return -1;
    }

    int status;
    const char *payload;
    if (strncmp(line, "ok", 2) == 0) {
        status = 0;
        payload = line + 2;
    } else if (strncmp(line, "err", 3) == 0) {
        status = 1;
        payload = line + 3;
    } else {
        errno = EPROTO;
        return -1;
    }
    while (*payload == ' ') {
        payload++;
    }
    if ((resp != NULL) && (resp_len > 0)) {
        strncpy(resp, payload, resp_len - 1);
        resp[resp_len - 1] = '\0';
    }
    return status;
}
