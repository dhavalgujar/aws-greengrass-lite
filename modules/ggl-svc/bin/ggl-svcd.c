// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// ggl-svcd: a small service manager that stands in for systemd in the
// systemd-free portable core (GGL_PORTABLE_CORE).
//
// It runs the unit files Greengrass Lite generates (recipe2unit) and the
// core daemon units in GGL_SVC_CORE_DIR, honouring the subset of systemd
// semantics they use: Type=exec|simple|oneshot|notify, NotifyAccess,
// ExecStart, User, Group, WorkingDirectory, Environment, Restart, RestartSec,
// RemainAfterExit, SuccessExitStatus, StartLimitIntervalSec/StartLimitBurst,
// TimeoutStartSec/TimeoutStopSec/TimeoutSec, After=/Wants= ordering and
// BindsTo= (a unit is stopped, or restarted, with the unit it is bound to).
// It tracks the unit properties gghealthd derives lifecycle states from
// (ActiveState, Result, NRestarts, InactiveEnterTimestampMonotonic) and
// serves them, plus start/stop control, over GGL_SVC_SOCKET (see ggl/svc.h).
//
// As under systemd, each unit runs in its own cgroup (process grouping only,
// no controllers). A process cannot leave it for another unit's, so
// "whois <pid>" maps a process to its unit by its cgroup, for as long as the
// process lives; ggipc-auth uses that in place of systemd's
// sd_pid_get_unit(). Stopping a unit signals every process in its cgroup
// (KillMode=control-group): SIGTERM, then SIGKILL after TimeoutStopSec.
// Requests that change state are only accepted from root (SO_PEERCRED); a
// unit's own processes may also send "sd-notify", the systemd-notify
// equivalent, for their unit.
//
// Extension: X-GGL-ReadySocket=<path> keeps a unit "activating" until the
// path exists as a socket; it replaces systemd socket activation for the
// core daemons.
//
// Unit output goes to syslog, one message per line tagged with the unit
// (as the journal would hold it), so its size stays bounded by syslogd's
// rotation instead of growing in a tmpfs.
//
// State that must survive a reboot lives in STATE_DIR, which only root can
// write: the units linked and enabled by deployments, and a copy of each
// linked unit file taken when it is linked. Units run from the copy, so a
// unit file left in a directory writable by the core daemons' user cannot
// later be swapped for one that runs as root.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ggl/svc.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef GGL_SVC_CORE_DIR
#define GGL_SVC_CORE_DIR "/usr/lib/ggl-svc"
#endif
// Overridable for tests.
#ifndef STATE_DIR
#define STATE_DIR "/var/lib/ggl-svc"
#endif
#ifndef CGROUP_ROOT
#define CGROUP_ROOT "/sys/fs/cgroup"
#endif
#define CGROUP_DIR CGROUP_ROOT "/ggl-svc"
#define CGROUP2_MAGIC 0x63677270
#define LOG_LINE_MAX 480
#define LOG_DRAIN_MAX 4096
#define UNIT_FILE_MAX 8192

#define MAX_UNITS 128
#define MAX_DEPS 8
#define MAX_ENV 8
#define MAX_WATCHERS 8
#define MAX_PENDING 16
#define MAX_PENDING_PER_UID 4
#define MAX_STARTS 16
#define NAME_LEN 160
#define PATH_LEN 256
#define REQUEST_MAX 768
#define REQUEST_TIMEOUT_MS 2000

// systemd defaults
#define DEFAULT_START_TIMEOUT_S 90
#define DEFAULT_STOP_TIMEOUT_S 90
#define DEFAULT_START_LIMIT_INTERVAL_S 10
#define DEFAULT_START_LIMIT_BURST 5

typedef enum {
    T_EXEC,
    T_ONESHOT,
    T_NOTIFY
} UnitType;

typedef enum {
    N_DEFAULT,
    N_NONE,
    N_MAIN,
    N_ALL
} NotifyAccess;

typedef enum {
    R_NO,
    R_ON_FAILURE,
    R_ALWAYS
} RestartPolicy;

typedef enum {
    S_INACTIVE,
    S_ACTIVATING,
    S_ACTIVE,
    S_DEACTIVATING,
    S_FAILED
} UnitState;

static const char *const STATE_NAMES[]
    = { "inactive", "activating", "active", "deactivating", "failed" };

typedef struct {
    char name[NAME_LEN];
    char path[PATH_LEN]; // the unit file parsed
    char source[PATH_LEN]; // the file it was linked from
    bool loaded;
    bool core;

    UnitType type;
    NotifyAccess notify_access;
    char exec[512];
    char user[64];
    char group[64];
    char workdir[PATH_LEN];
    char env[MAX_ENV][256];
    int n_env;
    RestartPolicy restart;
    unsigned restart_sec;
    bool remain;
    int success_status[4];
    int n_success;
    unsigned start_limit_interval_s;
    unsigned start_limit_burst;
    unsigned start_timeout_s; // 0: none
    unsigned stop_timeout_s;
    char after[MAX_DEPS][NAME_LEN];
    int n_after;
    char wants[MAX_DEPS][NAME_LEN];
    int n_wants;
    char binds[MAX_DEPS][NAME_LEN];
    int n_binds;
    char ready_socket[PATH_LEN];

    UnitState state;
    char result[32];
    pid_t pid; // main process
    unsigned n_restarts;
    uint64_t inactive_enter_usec;
    uint64_t starts_ms[MAX_STARTS];
    unsigned n_starts;
    bool start_pending;
    bool stop_requested;
    bool restart_after_stop;
    bool stopping_notified;
    bool timed_out;
    uint64_t restart_at_ms;
    uint64_t start_deadline_ms;
    uint64_t kill_at_ms; // SIGKILL the cgroup if the main process remains
    uint64_t leftover_kill_at_ms; // SIGKILL the cgroup if it is not empty

    int log_fd;
    char log_buf[LOG_LINE_MAX + 1];
    size_t log_len;
} Unit;

static Unit units[MAX_UNITS];
static int n_units;

static int watchers[MAX_WATCHERS];
static int n_watchers;

typedef struct {
    int fd;
    uid_t uid;
    pid_t pid;
    char buf[REQUEST_MAX];
    size_t len;
    uint64_t deadline_ms;
} Pending;

static Pending pending[MAX_PENDING];
static int n_pending;

// Set while a unit is being restarted rather than stopped, so that the
// units bound to it are restarted too.
static bool restarting;

static volatile sig_atomic_t terminate;

static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(LOG_NOTICE, fmt, ap);
    va_end(ap);
}

static uint64_t now_usec(void) {
    struct timespec ts;
    (void) clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t) ts.tv_sec * 1000000U) + ((uint64_t) ts.tv_nsec / 1000U);
}

static uint64_t now_ms(void) {
    return now_usec() / 1000U;
}

static Unit *find_unit(const char *name) {
    for (int i = 0; i < n_units; i++) {
        if (strcmp(units[i].name, name) == 0) {
            return &units[i];
        }
    }
    return NULL;
}

// Unit cgroups //

static void cgroup_path(const Unit *u, const char *file, char *buf, size_t len) {
    (void) snprintf(
        buf,
        len,
        CGROUP_DIR "/%s%s%s",
        u->name,
        (file != NULL) ? "/" : "",
        (file != NULL) ? file : ""
    );
}

static bool write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    size_t len = strlen(data);
    bool ok = (write(fd, data, len) == (ssize_t) len);
    (void) close(fd);
    return ok;
}

// Signals every process in the unit's cgroup; returns how many there were.
// SIGKILL uses cgroup.kill, which also catches processes forking meanwhile.
static int signal_cgroup(const Unit *u, int sig) {
    // A main process that was just forked may not have joined the cgroup
    // yet (exec_unit does so first): signal it directly as well.
    if ((u->pid > 0) && (sig != 0)) {
        (void) kill(u->pid, sig);
    }
    char path[NAME_LEN + 64];
    if (sig == SIGKILL) {
        cgroup_path(u, "cgroup.kill", path, sizeof(path));
        (void) write_file(path, "1");
    }
    cgroup_path(u, "cgroup.procs", path, sizeof(path));
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        return 0;
    }
    int count = 0;
    long pid;
    while (fscanf(f, "%ld", &pid) == 1) {
        if ((sig != SIGKILL) && (pid > 1)) {
            (void) kill((pid_t) pid, sig);
        }
        count++;
    }
    (void) fclose(f);
    return count;
}

// Terminates the processes a unit left behind once its main process is
// gone, as systemd does with a unit's cgroup: SIGTERM now, SIGKILL after
// TimeoutStopSec (see process_timers).
static void kill_leftovers(Unit *u) {
    if (signal_cgroup(u, SIGTERM) == 0) {
        u->leftover_kill_at_ms = 0;
        return;
    }
    if ((u->leftover_kill_at_ms == 0) && (u->stop_timeout_s > 0)) {
        u->leftover_kill_at_ms
            = now_ms() + ((uint64_t) u->stop_timeout_s * 1000U);
    }
}

// The unit a process belongs to: the unit whose cgroup it is in. Processes
// cannot move themselves into a unit's cgroup (it belongs to root), and stay
// in it when they fork, change session or are reparented.
static Unit *unit_of_pid(pid_t pid) {
    char path[64];
    (void) snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long) pid);
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        return NULL;
    }
    char line[NAME_LEN + 64];
    Unit *u = NULL;
    while (fgets(line, sizeof(line), f) != NULL) {
        // cgroup v2: "0::/ggl-svc/<unit>"
        static const char prefix[] = "0::/ggl-svc/";
        if (strncmp(line, prefix, sizeof(prefix) - 1) != 0) {
            continue;
        }
        char *name = line + sizeof(prefix) - 1;
        name[strcspn(name, "\n")] = '\0';
        if (strchr(name, '/') == NULL) {
            u = find_unit(name);
        }
        break;
    }
    (void) fclose(f);
    return u;
}

// State notifications //

static void format_unit(const Unit *u, char *buf, size_t len) {
    (void) snprintf(
        buf,
        len,
        "%s %s %s %u %llu %s",
        u->name,
        STATE_NAMES[u->state],
        u->result,
        u->n_restarts,
        (unsigned long long) u->inactive_enter_usec,
        u->start_pending ? "queued" : "idle"
    );
}

static void broadcast(const Unit *u) {
    char line[NAME_LEN + 96];
    format_unit(u, line, sizeof(line) - 1);
    size_t len = strlen(line);
    line[len++] = '\n';
    for (int i = 0; i < n_watchers;) {
        ssize_t n = send(watchers[i], line, len, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n != (ssize_t) len) {
            (void) close(watchers[i]);
            watchers[i] = watchers[--n_watchers];
            continue;
        }
        i++;
    }
}

static void stop_bound_units(const Unit *u);

static void set_state(Unit *u, UnitState state) {
    if (u->state == state) {
        return;
    }
    if ((state == S_INACTIVE) || (state == S_FAILED)) {
        u->inactive_enter_usec = now_usec();
    }
    u->state = state;
    logmsg("%s: %s (%s)", u->name, STATE_NAMES[state], u->result);
    broadcast(u);
    if ((state == S_INACTIVE) || (state == S_FAILED)) {
        stop_bound_units(u);
    }
}

static void set_result(Unit *u, const char *result) {
    (void) snprintf(u->result, sizeof(u->result), "%s", result);
}

// Unit file parsing //

static char *trim(char *s) {
    while ((*s == ' ') || (*s == '\t')) {
        s++;
    }
    size_t n = strlen(s);
    while ((n > 0)
           && ((s[n - 1] == ' ') || (s[n - 1] == '\t') || (s[n - 1] == '\n')
               || (s[n - 1] == '\r'))) {
        s[--n] = '\0';
    }
    return s;
}

static void add_deps(char list[][NAME_LEN], int *count, const char *value) {
    char copy[768];
    (void) snprintf(copy, sizeof(copy), "%s", value);
    char *save = NULL;
    for (char *tok = strtok_r(copy, " ", &save); tok != NULL;
         tok = strtok_r(NULL, " ", &save)) {
        if ((*count < MAX_DEPS) && (strncmp(tok, "ggl.", 4) == 0)) {
            (void) snprintf(list[(*count)++], NAME_LEN, "%s", tok);
        }
    }
}

// Seconds; "infinity" (and 0) mean no timeout.
static unsigned parse_seconds(const char *val) {
    if (strcmp(val, "infinity") == 0) {
        return 0;
    }
    return (unsigned) strtoul(val, NULL, 10);
}

static void reset_config(Unit *u) {
    u->type = T_EXEC;
    u->notify_access = N_DEFAULT;
    u->exec[0] = '\0';
    u->user[0] = '\0';
    u->group[0] = '\0';
    u->workdir[0] = '\0';
    u->n_env = 0;
    u->restart = R_NO;
    u->restart_sec = 1;
    u->remain = false;
    u->n_success = 0;
    u->start_limit_interval_s = DEFAULT_START_LIMIT_INTERVAL_S;
    u->start_limit_burst = DEFAULT_START_LIMIT_BURST;
    u->start_timeout_s = DEFAULT_START_TIMEOUT_S;
    u->stop_timeout_s = DEFAULT_STOP_TIMEOUT_S;
    u->n_after = 0;
    u->n_wants = 0;
    u->n_binds = 0;
    u->ready_socket[0] = '\0';
}

static bool parse_unit(Unit *u) {
    FILE *f = fopen(u->path, "re");
    if (f == NULL) {
        logmsg("%s: cannot read %s: %s", u->name, u->path, strerror(errno));
        return false;
    }
    reset_config(u);
    bool start_timeout_set = false;
    char line[768];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *l = trim(line);
        if ((*l == '#') || (*l == ';') || (*l == '[') || (*l == '\0')) {
            continue;
        }
        char *eq = strchr(l, '=');
        if (eq == NULL) {
            continue;
        }
        *eq = '\0';
        char *key = trim(l);
        char *val = trim(eq + 1);

        if (strcmp(key, "Type") == 0) {
            if (strcmp(val, "oneshot") == 0) {
                u->type = T_ONESHOT;
            } else if (strcmp(val, "notify") == 0) {
                u->type = T_NOTIFY;
            } else {
                u->type = T_EXEC;
            }
        } else if (strcmp(key, "NotifyAccess") == 0) {
            u->notify_access = (strcmp(val, "all") == 0) ? N_ALL
                : (strcmp(val, "main") == 0)             ? N_MAIN
                                                         : N_NONE;
        } else if (strcmp(key, "ExecStart") == 0) {
            (void) snprintf(u->exec, sizeof(u->exec), "%s", val);
        } else if (strcmp(key, "User") == 0) {
            (void) snprintf(u->user, sizeof(u->user), "%s", val);
        } else if (strcmp(key, "Group") == 0) {
            (void) snprintf(u->group, sizeof(u->group), "%s", val);
        } else if (strcmp(key, "WorkingDirectory") == 0) {
            (void) snprintf(u->workdir, sizeof(u->workdir), "%s", val);
        } else if (strcmp(key, "Environment") == 0) {
            if (u->n_env < MAX_ENV) {
                size_t n = strlen(val);
                if ((n >= 2) && (val[0] == '"') && (val[n - 1] == '"')) {
                    val[n - 1] = '\0';
                    val++;
                }
                (void) snprintf(u->env[u->n_env++], 256, "%s", val);
            }
        } else if (strcmp(key, "Restart") == 0) {
            u->restart = (strcmp(val, "always") == 0) ? R_ALWAYS
                : (strcmp(val, "on-failure") == 0)    ? R_ON_FAILURE
                                                      : R_NO;
        } else if (strcmp(key, "RestartSec") == 0) {
            u->restart_sec = (unsigned) strtoul(val, NULL, 10);
        } else if (strcmp(key, "RemainAfterExit") == 0) {
            u->remain = (strcmp(val, "true") == 0) || (strcmp(val, "yes") == 0);
        } else if (strcmp(key, "SuccessExitStatus") == 0) {
            char *save = NULL;
            for (char *tok = strtok_r(val, " ", &save);
                 (tok != NULL) && (u->n_success < 4);
                 tok = strtok_r(NULL, " ", &save)) {
                u->success_status[u->n_success++] = atoi(tok);
            }
        } else if (
            (strcmp(key, "StartLimitInterval") == 0)
            || (strcmp(key, "StartLimitIntervalSec") == 0)
        ) {
            u->start_limit_interval_s = parse_seconds(val);
        } else if (strcmp(key, "StartLimitBurst") == 0) {
            u->start_limit_burst = (unsigned) strtoul(val, NULL, 10);
        } else if (strcmp(key, "TimeoutStartSec") == 0) {
            u->start_timeout_s = parse_seconds(val);
            start_timeout_set = true;
        } else if (strcmp(key, "TimeoutStopSec") == 0) {
            u->stop_timeout_s = parse_seconds(val);
        } else if (strcmp(key, "TimeoutSec") == 0) {
            u->start_timeout_s = parse_seconds(val);
            u->stop_timeout_s = u->start_timeout_s;
            start_timeout_set = true;
        } else if (strcmp(key, "After") == 0) {
            add_deps(u->after, &u->n_after, val);
        } else if (strcmp(key, "Wants") == 0) {
            add_deps(u->wants, &u->n_wants, val);
        } else if (strcmp(key, "BindsTo") == 0) {
            // BindsTo= also pulls the unit in, as Requires= does.
            add_deps(u->wants, &u->n_wants, val);
            add_deps(u->binds, &u->n_binds, val);
        } else if (strcmp(key, "X-GGL-ReadySocket") == 0) {
            (void) snprintf(
                u->ready_socket, sizeof(u->ready_socket), "%s", val
            );
        }
    }
    (void) fclose(f);
    if ((u->type == T_ONESHOT) && !start_timeout_set) {
        // As systemd: no start timeout for oneshot services by default.
        u->start_timeout_s = 0;
    }
    if (u->notify_access == N_DEFAULT) {
        // As systemd: notifications are only read from Type=notify units.
        u->notify_access = (u->type == T_NOTIFY) ? N_MAIN : N_NONE;
    }
    if (u->exec[0] == '\0') {
        logmsg("%s: no ExecStart", u->name);
        return false;
    }
    return true;
}

static Unit *load_unit(
    const char *name, const char *path, const char *source, bool core
) {
    Unit *u = find_unit(name);
    if (u == NULL) {
        if (n_units == MAX_UNITS) {
            logmsg("too many units, ignoring %s", name);
            return NULL;
        }
        u = &units[n_units++];
        memset(u, 0, sizeof(*u));
        u->log_fd = -1;
        (void) snprintf(u->name, sizeof(u->name), "%s", name);
        set_result(u, "success");
    }
    (void) snprintf(u->path, sizeof(u->path), "%s", path);
    (void) snprintf(u->source, sizeof(u->source), "%s", source);
    u->core = core;
    u->loaded = parse_unit(u);
    return u;
}

static void forget_unit(Unit *u) {
    if (u->log_fd >= 0) {
        (void) close(u->log_fd);
    }
    char path[NAME_LEN + 64];
    cgroup_path(u, NULL, path, sizeof(path));
    (void) rmdir(path);
    *u = units[--n_units];
}

static bool is_enabled(const Unit *u) {
    if (u->core) {
        return true;
    }
    char path[PATH_LEN + NAME_LEN];
    (void) snprintf(
        path, sizeof(path), STATE_DIR "/enabled/%.*s", NAME_LEN - 1, u->name
    );
    return access(path, F_OK) == 0;
}

// Removes what link created for a unit.
static void unlink_unit(const char *name) {
    char path[PATH_LEN + NAME_LEN];
    (void) snprintf(path, sizeof(path), STATE_DIR "/links/%s", name);
    (void) unlink(path);
    (void) snprintf(path, sizeof(path), STATE_DIR "/units/%s", name);
    (void) unlink(path);
}

static void load_core_units(void) {
    DIR *d = opendir(GGL_SVC_CORE_DIR);
    if (d == NULL) {
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if ((n < 9) || (n >= NAME_LEN)
            || (strcmp(e->d_name + n - 8, ".service") != 0)) {
            continue;
        }
        char path[PATH_LEN + NAME_LEN];
        (void) snprintf(path, sizeof(path), GGL_SVC_CORE_DIR "/%s", e->d_name);
        (void) load_unit(e->d_name, path, path, true);
    }
    (void) closedir(d);
}

// Linked units: STATE_DIR/links/<unit> points at the file the unit was
// linked from, STATE_DIR/units/<unit> is the copy that runs.
static void load_linked_units(void) {
    DIR *d = opendir(STATE_DIR "/links");
    if (d == NULL) {
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if ((n < 9) || (n >= NAME_LEN)
            || (strcmp(e->d_name + n - 8, ".service") != 0)) {
            continue;
        }
        char link[PATH_LEN + NAME_LEN];
        (void) snprintf(link, sizeof(link), STATE_DIR "/links/%s", e->d_name);
        char source[PATH_LEN];
        ssize_t len = readlink(link, source, sizeof(source) - 1);
        if (len <= 0) {
            continue;
        }
        source[len] = '\0';
        if (access(source, F_OK) != 0) {
            // The unit file was removed (ggdeploymentd deletes a removed
            // component's files but only disables its run unit).
            if (find_unit(e->d_name) == NULL) {
                unlink_unit(e->d_name);
            }
            continue;
        }
        char copy[PATH_LEN + NAME_LEN];
        (void) snprintf(copy, sizeof(copy), STATE_DIR "/units/%s", e->d_name);
        if (access(copy, F_OK) != 0) {
            logmsg("%s: linked but has no copy; link it again", e->d_name);
            continue;
        }
        (void) load_unit(e->d_name, copy, source, false);
    }
    (void) closedir(d);
}

static void load_all(void) {
    load_core_units();
    load_linked_units();
}

// At startup: removes the copies of units that are no longer linked
// (disabled, or removed by a deployment).
static void prune_copies(void) {
    DIR *d = opendir(STATE_DIR "/units");
    if (d == NULL) {
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if ((e->d_name[0] != '.') && (find_unit(e->d_name) == NULL)) {
            unlink_unit(e->d_name);
        } else if (
            (e->d_name[0] == '.') && (strcmp(e->d_name, ".") != 0)
            && (strcmp(e->d_name, "..") != 0)
        ) {
            // A copy interrupted before its rename.
            char path[PATH_LEN + NAME_LEN];
            (void) snprintf(
                path, sizeof(path), STATE_DIR "/units/%s", e->d_name
            );
            (void) unlink(path);
        }
    }
    (void) closedir(d);
}

// Process management //

static bool real_home(const char *dir) {
    return (dir != NULL) && (dir[0] == '/') && (strcmp(dir, "/") != 0)
        && (strcmp(dir, "/nonexistent") != 0);
}

static bool login_shell(const char *shell) {
    if ((shell == NULL) || (shell[0] != '/')) {
        return false;
    }
    const char *base = strrchr(shell, '/') + 1;
    return (strcmp(base, "nologin") != 0) && (strcmp(base, "false") != 0);
}

static void build_env(
    const Unit *u, char **envp, char storage[][320], int max
) {
    int n = 0;
    (void) snprintf(
        storage[n],
        320,
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:"
        "/usr/bin:/sbin:/bin"
    );
    envp[n] = storage[n];
    n++;
    // As systemd: USER always; LOGNAME, HOME and SHELL only for units with
    // User=, and neither a home directory that is no real one nor a shell
    // that refuses logins.
    struct passwd *pw = (u->user[0] != '\0') ? getpwnam(u->user) : NULL;
    if (pw == NULL) {
        struct passwd *self = getpwuid(geteuid());
        if (self != NULL) {
            (void) snprintf(storage[n], 320, "USER=%s", self->pw_name);
            envp[n] = storage[n];
            n++;
        }
    } else {
        (void) snprintf(storage[n], 320, "USER=%s", pw->pw_name);
        envp[n] = storage[n];
        n++;
        (void) snprintf(storage[n], 320, "LOGNAME=%s", pw->pw_name);
        envp[n] = storage[n];
        n++;
        if (real_home(pw->pw_dir)) {
            (void) snprintf(storage[n], 320, "HOME=%s", pw->pw_dir);
            envp[n] = storage[n];
            n++;
        }
        if (login_shell(pw->pw_shell)) {
            (void) snprintf(storage[n], 320, "SHELL=%s", pw->pw_shell);
            envp[n] = storage[n];
            n++;
        }
    }
    for (int i = 0; (i < u->n_env) && (n < max - 1); i++) {
        (void) snprintf(storage[n], 320, "%s", u->env[i]);
        envp[n] = storage[n];
        n++;
    }
    envp[n] = NULL;
}

// Runs in the child, with SIGTERM and SIGINT blocked; never returns.
static void exec_unit(const Unit *u, int log_fd) {
    // ggl-svcd's own handlers must not catch a stop meant for the unit:
    // restore the defaults before anything can unblock them.
    (void) signal(SIGTERM, SIG_DFL);
    (void) signal(SIGINT, SIG_DFL);
    // Join the unit's cgroup before anything else runs (exit status 219 is
    // systemd's EXIT_CGROUP).
    char procs[NAME_LEN + 64];
    cgroup_path(u, "cgroup.procs", procs, sizeof(procs));
    if (!write_file(procs, "0")) {
        _exit(219);
    }
    (void) setsid();
    sigset_t none;
    (void) sigemptyset(&none);
    (void) sigprocmask(SIG_SETMASK, &none, NULL);
    (void) signal(SIGPIPE, SIG_DFL);

    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        (void) dup2(devnull, STDIN_FILENO);
        (void) close(devnull);
    }
    if (log_fd >= 0) {
        (void) dup2(log_fd, STDOUT_FILENO);
        (void) dup2(log_fd, STDERR_FILENO);
        (void) close(log_fd);
    }

    const char *dir = (u->workdir[0] != '\0') ? u->workdir : "/";
    if (chdir(dir) != 0) {
        (void) fprintf(stderr, "chdir %s: %s\n", dir, strerror(errno));
        _exit(200);
    }

    if ((u->user[0] != '\0') || (u->group[0] != '\0')) {
        struct passwd *pw = getpwnam((u->user[0] != '\0') ? u->user : "root");
        if (pw == NULL) {
            (void) fprintf(stderr, "unknown user %s\n", u->user);
            _exit(217);
        }
        gid_t gid = pw->pw_gid;
        if (u->group[0] != '\0') {
            struct group *gr = getgrnam(u->group);
            if (gr == NULL) {
                (void) fprintf(stderr, "unknown group %s\n", u->group);
                _exit(216);
            }
            gid = gr->gr_gid;
        }
        if ((initgroups(pw->pw_name, gid) != 0) || (setgid(gid) != 0)
            || (setuid(pw->pw_uid) != 0)) {
            (void) fprintf(stderr, "cannot switch to %s\n", pw->pw_name);
            _exit(217);
        }
    }

    static char storage[MAX_ENV + 8][320];
    char *envp[MAX_ENV + 8];
    build_env(u, envp, storage, MAX_ENV + 8);

    // systemd splits ExecStart itself; the generated lines need no more
    // than the shell's word splitting and quoting.
    static char sh[] = "/bin/sh";
    static char dash_c[] = "-c";
    char cmd[600];
    (void) snprintf(cmd, sizeof(cmd), "exec %s", u->exec);
    char *argv[] = { sh, dash_c, cmd, NULL };
    (void) execve("/bin/sh", argv, envp);
    _exit(203);
}

// Unit output: forward complete lines to syslog, tagged with the unit name
// without its ggl. prefix and .service suffix.
static void emit_line(Unit *u) {
    char tag[NAME_LEN];
    (void) snprintf(tag, sizeof(tag), "%s", u->name);
    size_t n = strlen(tag);
    if ((n > 8) && (strcmp(tag + n - 8, ".service") == 0)) {
        tag[n - 8] = '\0';
    }
    const char *t = (strncmp(tag, "ggl.", 4) == 0) ? tag + 4 : tag;
    u->log_buf[u->log_len] = '\0';
    if (u->log_len > 0) {
        syslog(LOG_INFO, "%s: %s", t, u->log_buf);
    }
    u->log_len = 0;
}

// Reads at most LOG_DRAIN_MAX bytes per call so that a unit writing
// continuously cannot keep the main loop here.
static void drain_log(Unit *u) {
    char chunk[512];
    ssize_t n = 0;
    size_t total = 0;
    while ((total < LOG_DRAIN_MAX)
           && ((n = read(u->log_fd, chunk, sizeof(chunk))) > 0)) {
        total += (size_t) n;
        for (ssize_t i = 0; i < n; i++) {
            if (chunk[i] == '\n') {
                emit_line(u);
            } else if (u->log_len == LOG_LINE_MAX) {
                emit_line(u);
                u->log_buf[u->log_len++] = chunk[i];
            } else {
                u->log_buf[u->log_len++] = chunk[i];
            }
        }
    }
    if ((n == 0) || ((n < 0) && (errno != EAGAIN) && (errno != EINTR))) {
        emit_line(u);
        (void) close(u->log_fd);
        u->log_fd = -1;
    }
}

// Start limit over StartLimitIntervalSec, as systemd: true when another
// start is allowed now, and records it.
static bool start_allowed(Unit *u) {
    uint64_t now = now_ms();
    uint64_t window = (uint64_t) u->start_limit_interval_s * 1000U;
    unsigned recent = 0;
    for (unsigned i = 0; i < u->n_starts; i++) {
        if ((window == 0) || (now - u->starts_ms[i] < window)) {
            u->starts_ms[recent++] = u->starts_ms[i];
        }
    }
    u->n_starts = recent;
    if ((u->start_limit_burst > 0) && (window > 0)
        && (u->n_starts >= u->start_limit_burst)) {
        return false;
    }
    if (u->n_starts == MAX_STARTS) {
        (void) memmove(
            &u->starts_ms[0],
            &u->starts_ms[1],
            (MAX_STARTS - 1) * sizeof(u->starts_ms[0])
        );
        u->n_starts--;
    }
    u->starts_ms[u->n_starts++] = now;
    return true;
}

static void spawn(Unit *u) {
    if (!u->loaded) {
        set_result(u, "resources");
        set_state(u, S_FAILED);
        return;
    }
    if (!start_allowed(u)) {
        // As systemd: the start limit only replaces a successful result; a
        // restart refused after a failure keeps that failure's result.
        if (strcmp(u->result, "success") == 0) {
            set_result(u, "start-limit-hit");
        }
        set_state(u, S_FAILED);
        return;
    }
    if (u->ready_socket[0] != '\0') {
        // A socket left by a previous instance must not count as ready.
        (void) unlink(u->ready_socket);
    }
    char cgroup[NAME_LEN + 64];
    cgroup_path(u, NULL, cgroup, sizeof(cgroup));
    if ((mkdir(cgroup, 0755) != 0) && (errno != EEXIST)) {
        logmsg("%s: cgroup: %s", u->name, strerror(errno));
        set_result(u, "resources");
        set_state(u, S_FAILED);
        return;
    }
    // Processes a previous run left behind do not belong to this one.
    (void) signal_cgroup(u, SIGKILL);
    u->leftover_kill_at_ms = 0;
    if (u->log_fd >= 0) {
        // Output of a previous run not read yet: forward it first.
        drain_log(u);
        if (u->log_fd >= 0) {
            (void) close(u->log_fd);
            u->log_fd = -1;
        }
    }
    int pipefd[2] = { -1, -1 };
    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        logmsg("%s: pipe: %s", u->name, strerror(errno));
    }
    // Until exec_unit has restored the default handlers, a SIGTERM for the
    // unit would run ggl-svcd's handler in the child: hold it back.
    sigset_t stop_signals;
    sigset_t old_mask;
    (void) sigemptyset(&stop_signals);
    (void) sigaddset(&stop_signals, SIGTERM);
    (void) sigaddset(&stop_signals, SIGINT);
    (void) sigprocmask(SIG_BLOCK, &stop_signals, &old_mask);
    pid_t pid = fork();
    if (pid != 0) {
        (void) sigprocmask(SIG_SETMASK, &old_mask, NULL);
    }
    if (pid < 0) {
        logmsg("%s: fork: %s", u->name, strerror(errno));
        (void) close(pipefd[0]);
        (void) close(pipefd[1]);
        set_result(u, "resources");
        set_state(u, S_FAILED);
        return;
    }
    if (pid == 0) {
        exec_unit(u, pipefd[1]);
    }
    if (pipefd[1] >= 0) {
        (void) close(pipefd[1]);
    }
    u->log_fd = pipefd[0];
    if (u->log_fd >= 0) {
        (void) fcntl(u->log_fd, F_SETFL, O_NONBLOCK);
    }
    u->pid = pid;
    u->stop_requested = false;
    u->stopping_notified = false;
    u->timed_out = false;
    u->kill_at_ms = 0;
    set_result(u, "success");
    bool ready = (u->type == T_EXEC) && (u->ready_socket[0] == '\0');
    u->start_deadline_ms = (!ready && (u->start_timeout_s > 0))
        ? now_ms() + ((uint64_t) u->start_timeout_s * 1000U)
        : 0;
    set_state(u, ready ? S_ACTIVE : S_ACTIVATING);
}

// A dependency is settled once it is neither starting nor stopping: active,
// finished, or failed (dependents then start and report their own state,
// as under systemd's After= ordering).
static bool dep_settled(const char *name) {
    Unit *d = find_unit(name);
    if ((d == NULL) || !d->loaded) {
        return true;
    }
    if (d->start_pending || (d->restart_at_ms != 0)) {
        return false;
    }
    return (d->state != S_ACTIVATING) && (d->state != S_DEACTIVATING);
}

// manual: an explicit start (not an automatic restart), which resets the
// restart counter as systemd does.
static void request_start(Unit *u, bool manual) {
    if ((u->state == S_ACTIVE) || u->start_pending) {
        return;
    }
    if ((u->state == S_ACTIVATING) && (u->restart_at_ms == 0)) {
        return;
    }
    if (manual) {
        u->n_restarts = 0;
    }
    u->restart_at_ms = 0;
    u->start_pending = true;
    for (int i = 0; i < u->n_wants; i++) {
        Unit *d = find_unit(u->wants[i]);
        if (d != NULL) {
            request_start(d, manual);
        }
    }
}

static void process_pending(void) {
    for (int i = 0; i < n_units; i++) {
        Unit *u = &units[i];
        if (!u->start_pending || (u->pid > 0)) {
            continue;
        }
        bool ready = true;
        for (int d = 0; d < u->n_after; d++) {
            if (!dep_settled(u->after[d])) {
                ready = false;
                break;
            }
        }
        if (ready) {
            u->start_pending = false;
            spawn(u);
        }
    }
}

static void request_stop(Unit *u) {
    u->start_pending = false;
    u->restart_at_ms = 0;
    u->restart_after_stop = false;
    if (u->pid > 0) {
        if (!u->stop_requested) {
            u->stop_requested = true;
            u->kill_at_ms = (u->stop_timeout_s > 0)
                ? now_ms() + ((uint64_t) u->stop_timeout_s * 1000U)
                : 0;
            (void) signal_cgroup(u, SIGTERM);
        }
        set_state(u, S_DEACTIVATING);
    } else {
        kill_leftovers(u);
        if ((u->state == S_ACTIVE) || (u->state == S_ACTIVATING)) {
            set_result(u, "success");
            set_state(u, S_INACTIVE);
        }
    }
}

// Stops the unit and starts it again once it has stopped; the units bound
// to it follow.
static void restart_unit(Unit *u) {
    bool saved = restarting;
    restarting = true;
    bool running = (u->pid > 0);
    request_stop(u);
    if (running) {
        u->restart_after_stop = true;
    } else {
        request_start(u, true);
    }
    restarting = saved;
}

// BindsTo=: when a unit stops or fails, the units bound to it are stopped
// too, or restarted with it.
static void stop_bound_units(const Unit *u) {
    bool restart = restarting || u->restart_after_stop;
    for (int i = 0; i < n_units; i++) {
        Unit *b = &units[i];
        if ((b->state != S_ACTIVE) && (b->state != S_ACTIVATING)
            && !b->start_pending) {
            continue;
        }
        for (int d = 0; d < b->n_binds; d++) {
            if (strcmp(b->binds[d], u->name) != 0) {
                continue;
            }
            logmsg("%s: bound to %s", b->name, u->name);
            if (restart) {
                restart_unit(b);
            } else {
                request_stop(b);
            }
            break;
        }
    }
}

static bool exit_is_success(const Unit *u, int status) {
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            return true;
        }
        for (int i = 0; i < u->n_success; i++) {
            if (u->success_status[i] == code) {
                return true;
            }
        }
        return false;
    }
    return u->stop_requested && WIFSIGNALED(status)
        && ((WTERMSIG(status) == SIGTERM) || (WTERMSIG(status) == SIGKILL));
}

static void unit_exited(Unit *u, int status) {
    u->pid = 0;
    u->start_deadline_ms = 0;
    bool success = exit_is_success(u, status) && !u->timed_out;

    if (u->stop_requested) {
        u->stop_requested = false;
        // The stop's deadline also applies to what the unit left behind.
        u->leftover_kill_at_ms = u->kill_at_ms;
        u->kill_at_ms = 0;
        kill_leftovers(u);
        set_result(u, u->timed_out ? "timeout" : "success");
        set_state(u, u->timed_out ? S_FAILED : S_INACTIVE);
        if (u->restart_after_stop) {
            u->restart_after_stop = false;
            request_start(u, true);
        }
        return;
    }
    u->kill_at_ms = 0;

    if (success) {
        set_result(u, "success");
        if (u->remain && !u->stopping_notified
            && ((u->type == T_ONESHOT)
                || ((u->type == T_NOTIFY) && (u->state == S_ACTIVE)))) {
            // Remains active; its other processes keep running.
            set_state(u, S_ACTIVE);
            return;
        }
        if ((u->type == T_NOTIFY) && (u->state == S_ACTIVATING)) {
            // Exited without ever reporting READY.
            set_result(u, "protocol");
            success = false;
        } else if (u->restart != R_ALWAYS) {
            kill_leftovers(u);
            set_state(u, S_INACTIVE);
            return;
        }
    } else if (u->timed_out) {
        set_result(u, "timeout");
    } else {
        set_result(
            u,
            !WIFSIGNALED(status)  ? "exit-code"
                : WCOREDUMP(status) ? "core-dump"
                                    : "signal"
        );
    }
    kill_leftovers(u);

    if ((u->restart == R_NO) || (success && (u->restart != R_ALWAYS))) {
        set_state(u, success ? S_INACTIVE : S_FAILED);
        return;
    }
    u->n_restarts++;
    u->restart_at_ms = now_ms() + ((uint64_t) u->restart_sec * 1000U);
    // systemd reports a unit waiting to auto-restart as activating.
    set_state(u, S_ACTIVATING);
}

static void reap_children(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int i = 0; i < n_units; i++) {
            if (units[i].pid == pid) {
                unit_exited(&units[i], status);
                break;
            }
        }
    }
}

static void process_timers(void) {
    uint64_t now = now_ms();
    for (int i = 0; i < n_units; i++) {
        Unit *u = &units[i];
        if ((u->restart_at_ms != 0) && (now >= u->restart_at_ms)) {
            u->restart_at_ms = 0;
            if (u->pid == 0) {
                spawn(u);
            }
        }
        if ((u->start_deadline_ms != 0) && (now >= u->start_deadline_ms)
            && (u->pid > 0) && (u->state == S_ACTIVATING)) {
            // TimeoutStartSec: the start failed.
            logmsg("%s: start timed out", u->name);
            u->start_deadline_ms = 0;
            u->timed_out = true;
            u->kill_at_ms = now + ((uint64_t) u->stop_timeout_s * 1000U);
            (void) signal_cgroup(u, SIGTERM);
        }
        if ((u->kill_at_ms != 0) && (now >= u->kill_at_ms) && (u->pid > 0)) {
            // TimeoutStopSec: as systemd, a stop that needs SIGKILL fails.
            u->kill_at_ms = 0;
            u->timed_out = true;
            (void) signal_cgroup(u, SIGKILL);
        }
        if ((u->leftover_kill_at_ms != 0) && (now >= u->leftover_kill_at_ms)) {
            u->leftover_kill_at_ms = 0;
            if (u->pid == 0) {
                (void) signal_cgroup(u, SIGKILL);
            }
        }
        if ((u->state == S_ACTIVATING) && (u->pid > 0) && !u->timed_out
            && (u->ready_socket[0] != '\0')) {
            struct stat st;
            if ((stat(u->ready_socket, &st) == 0) && S_ISSOCK(st.st_mode)) {
                u->start_deadline_ms = 0;
                set_state(u, S_ACTIVE);
            }
        }
    }
}

// Control protocol //

static void reply(int fd, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }
    if ((size_t) n > sizeof(buf) - 2) {
        n = (int) sizeof(buf) - 2;
    }
    buf[n++] = '\n';
    (void) send(fd, buf, (size_t) n, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static bool valid_unit_name(const char *name) {
    return (name != NULL) && (name[0] != '\0') && (strchr(name, '/') == NULL)
        && (name[0] != '.') && (strlen(name) < NAME_LEN);
}

// Copies a unit file into STATE_DIR/units: what runs is what was linked.
static bool copy_unit_file(const char *src, const char *name) {
    // O_NONBLOCK: opening a FIFO must not block; only a regular file is
    // accepted below.
    int in = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (in < 0) {
        return false;
    }
    static char data[UNIT_FILE_MAX];
    struct stat st;
    ssize_t len = -1;
    if ((fstat(in, &st) == 0) && S_ISREG(st.st_mode)
        && (st.st_size < (off_t) sizeof(data))) {
        len = read(in, data, sizeof(data));
    }
    (void) close(in);
    if ((len < 0) || (len >= (ssize_t) sizeof(data))) {
        return false;
    }
    char tmp[PATH_LEN + NAME_LEN];
    char dst[PATH_LEN + NAME_LEN];
    (void) snprintf(tmp, sizeof(tmp), STATE_DIR "/units/.%s", name);
    (void) snprintf(dst, sizeof(dst), STATE_DIR "/units/%s", name);
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0) {
        return false;
    }
    bool ok = (write(out, data, (size_t) len) == len) && (fsync(out) == 0);
    ok = (close(out) == 0) && ok;
    if (ok && (rename(tmp, dst) == 0)) {
        return true;
    }
    (void) unlink(tmp);
    return false;
}

static void cmd_link(int fd, const char *path) {
    const char *base = strrchr(path, '/');
    base = (base != NULL) ? base + 1 : path;
    size_t n = strlen(base);
    if ((path[0] != '/') || !valid_unit_name(base) || (n < 9)
        || (strcmp(base + n - 8, ".service") != 0)
        || (strlen(path) >= PATH_LEN)) {
        reply(fd, "err invalid unit path %s", path);
        return;
    }
    Unit *prev = find_unit(base);
    if ((prev != NULL) && prev->core) {
        reply(fd, "err %s is a core unit", base);
        return;
    }
    if (!copy_unit_file(path, base)) {
        reply(fd, "err cannot copy %s", path);
        return;
    }
    // Load first: a unit that cannot be loaded must not be linked, or it
    // would take a slot at every boot.
    char copy[PATH_LEN];
    (void) snprintf(copy, sizeof(copy), STATE_DIR "/units/%s", base);
    bool existed = (prev != NULL);
    Unit *u = load_unit(base, copy, path, false);
    if ((u == NULL) || !u->loaded) {
        if ((u != NULL) && !existed) {
            forget_unit(u);
        }
        if (!existed) {
            unlink_unit(base);
        }
        reply(fd, "err cannot load %s", base);
        return;
    }
    char link[PATH_LEN + NAME_LEN];
    (void) snprintf(link, sizeof(link), STATE_DIR "/links/%s", base);
    (void) unlink(link);
    if (symlink(path, link) != 0) {
        reply(fd, "err link %s: %s", base, strerror(errno));
        return;
    }
    reply(fd, "ok");
}

static void cmd_enable(int fd, Unit *u, bool enable) {
    char path[PATH_LEN + NAME_LEN];
    (void) snprintf(path, sizeof(path), STATE_DIR "/enabled/%s", u->name);
    if (enable) {
        int f = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (f < 0) {
            reply(fd, "err enable %s: %s", u->name, strerror(errno));
            return;
        }
        (void) close(f);
    } else {
        (void) unlink(path);
        if (!u->core) {
            // systemctl disable also removes the link made by link; the
            // copy stays until the unit is forgotten.
            (void) snprintf(path, sizeof(path), STATE_DIR "/links/%s", u->name);
            (void) unlink(path);
        }
    }
    reply(fd, "ok");
}

static void reset_failed(Unit *u) {
    u->n_restarts = 0;
    u->n_starts = 0;
    if (u->state == S_FAILED) {
        set_result(u, "success");
        set_state(u, S_INACTIVE);
    }
}

// Equivalent of sd_notify READY=1 / RELOADING=1 / STOPPING=1, once the
// unit's NotifyAccess= admitted the sender. As under systemd, READY only
// completes the start of a Type=notify unit; STOPPING applies to any unit.
static void apply_notify(Unit *u, const char *what) {
    if ((strcmp(what, "READY") == 0) || (strcmp(what, "RELOADING") == 0)) {
        if ((u->type == T_NOTIFY) && (u->state == S_ACTIVATING) && (u->pid > 0)
            && !u->timed_out
            && (u->restart_at_ms == 0)) {
            u->start_deadline_ms = 0;
            set_state(u, S_ACTIVE);
        }
    } else if (strcmp(what, "STOPPING") == 0) {
        if (u->pid > 0) {
            u->stopping_notified = true;
            set_state(u, S_DEACTIVATING);
        }
    }
}

static bool unprivileged_verb(const char *verb) {
    return (strcmp(verb, "show") == 0) || (strcmp(verb, "whois") == 0)
        || (strcmp(verb, "sd-notify") == 0);
}

static void handle_request(int fd, char *line, uid_t peer_uid, pid_t peer_pid) {
    char *save = NULL;
    char *verb = strtok_r(line, " ", &save);
    char *arg = strtok_r(NULL, " ", &save);
    if (verb == NULL) {
        reply(fd, "err empty request");
        return;
    }
    if ((peer_uid != 0) && !unprivileged_verb(verb)) {
        reply(fd, "err permission denied");
        return;
    }

    if (strcmp(verb, "whois") == 0) {
        long pid = (arg != NULL) ? strtol(arg, NULL, 10) : 0;
        Unit *u = (pid > 1) ? unit_of_pid((pid_t) pid) : NULL;
        if (u == NULL) {
            reply(fd, "err no unit");
        } else {
            reply(fd, "ok %s", u->name);
        }
        return;
    }
    if (strcmp(verb, "sd-notify") == 0) {
        // From a unit's own processes, for that unit only, as its
        // NotifyAccess= allows.
        Unit *u = (peer_pid > 1) ? unit_of_pid(peer_pid) : NULL;
        if ((u == NULL) || (arg == NULL)) {
            reply(fd, "err no unit");
            return;
        }
        if ((u->notify_access == N_ALL)
            || ((u->notify_access == N_MAIN) && (peer_pid == u->pid))) {
            apply_notify(u, arg);
        }
        reply(fd, "ok");
        return;
    }
    if (strcmp(verb, "watch") == 0) {
        if (n_watchers == MAX_WATCHERS) {
            reply(fd, "err too many watchers");
            return;
        }
        reply(fd, "ok");
        watchers[n_watchers++] = fd;
        return;
    }
    if (strcmp(verb, "daemon-reload") == 0) {
        for (int i = 0; i < n_units;) {
            Unit *u = &units[i];
            if (!u->core && (u->pid == 0) && (access(u->source, F_OK) != 0)
                && (signal_cgroup(u, 0) == 0)) {
                // Removed by a deployment: forget it.
                unlink_unit(u->name);
                forget_unit(u);
                continue;
            }
            u->loaded = parse_unit(u);
            i++;
        }
        load_all();
        reply(fd, "ok");
        return;
    }
    if (strcmp(verb, "start-target") == 0) {
        for (int i = 0; i < n_units; i++) {
            if (is_enabled(&units[i])) {
                request_start(&units[i], true);
            }
        }
        process_pending();
        reply(fd, "ok");
        return;
    }
    if ((strcmp(verb, "reset-failed") == 0) && (arg == NULL)) {
        for (int i = 0; i < n_units; i++) {
            reset_failed(&units[i]);
        }
        reply(fd, "ok");
        return;
    }
    if (strcmp(verb, "link") == 0) {
        if (arg == NULL) {
            reply(fd, "err missing path");
            return;
        }
        cmd_link(fd, arg);
        return;
    }

    if (!valid_unit_name(arg)) {
        reply(fd, "err invalid unit name");
        return;
    }
    Unit *u = find_unit(arg);
    if (u == NULL) {
        if ((strcmp(verb, "stop") == 0) || (strcmp(verb, "disable") == 0)
            || (strcmp(verb, "reset-failed") == 0)) {
            // Nothing to do for a unit that does not exist, as with systemd
            // when the unit file has already been removed.
            reply(fd, "ok");
            return;
        }
        reply(fd, "err unit %s not found", arg);
        return;
    }

    if (strcmp(verb, "show") == 0) {
        char line_out[NAME_LEN + 96];
        format_unit(u, line_out, sizeof(line_out));
        reply(fd, "ok %s", line_out);
    } else if (strcmp(verb, "start") == 0) {
        request_start(u, true);
        process_pending();
        reply(fd, "ok");
    } else if (strcmp(verb, "stop") == 0) {
        request_stop(u);
        reply(fd, "ok");
    } else if (strcmp(verb, "restart") == 0) {
        restart_unit(u);
        process_pending();
        reply(fd, "ok");
    } else if (strcmp(verb, "reset-failed") == 0) {
        reset_failed(u);
        reply(fd, "ok");
    } else if (strcmp(verb, "enable") == 0) {
        cmd_enable(fd, u, true);
    } else if (strcmp(verb, "disable") == 0) {
        cmd_enable(fd, u, false);
    } else if (strcmp(verb, "notify") == 0) {
        // gghealthd relaying a component's reported state, as upstream runs
        // systemd-notify in the component's cgroup.
        char *what = strtok_r(NULL, " ", &save);
        if (what == NULL) {
            reply(fd, "err missing notification");
            return;
        }
        if (u->notify_access == N_ALL) {
            apply_notify(u, what);
        }
        reply(fd, "ok");
    } else {
        reply(fd, "err unknown verb %s", verb);
    }
}

static int open_listener(void) {
    (void) unlink(GGL_SVC_SOCKET);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, GGL_SVC_SOCKET, sizeof(addr.sun_path) - 1);
    // Anyone may connect (ggipcd runs as ggcore and asks "whois"); requests
    // that change state are checked against the peer's uid.
    mode_t old = umask(0011);
    int ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    (void) umask(old);
    if ((ret != 0) || (listen(fd, 16) != 0)) {
        (void) close(fd);
        return -1;
    }
    return fd;
}

// Requests are read without blocking the loop: each connection gets a
// buffer and REQUEST_TIMEOUT_MS to deliver one line. A non-root user may
// hold at most MAX_PENDING_PER_UID of the slots, so it cannot keep root or
// other users out.
static void accept_clients(int listener) {
    while (n_pending < MAX_PENDING) {
        int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0) {
            return;
        }
        struct ucred cred = { .uid = (uid_t) -1 };
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0) {
            (void) close(fd);
            continue;
        }
        int held = 0;
        for (int i = 0; i < n_pending; i++) {
            held += (pending[i].uid == cred.uid) ? 1 : 0;
        }
        if ((cred.uid != 0) && (held >= MAX_PENDING_PER_UID)) {
            (void) close(fd);
            continue;
        }
        pending[n_pending++] = (Pending) {
            .fd = fd,
            .uid = cred.uid,
            .pid = cred.pid,
            .len = 0,
            .deadline_ms = now_ms() + REQUEST_TIMEOUT_MS,
        };
    }
}

static void drop_pending(int i) {
    pending[i] = pending[--n_pending];
}

static void serve_pending(int i) {
    Pending *p = &pending[i];
    ssize_t n = recv(p->fd, p->buf + p->len, sizeof(p->buf) - 1 - p->len, 0);
    if ((n < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
        return;
    }
    if (n <= 0) {
        (void) close(p->fd);
        drop_pending(i);
        return;
    }
    p->len += (size_t) n;
    char *nl = memchr(p->buf, '\n', p->len);
    if (nl == NULL) {
        if (p->len == sizeof(p->buf) - 1) {
            (void) close(p->fd);
            drop_pending(i);
        }
        return;
    }
    *nl = '\0';

    int fd = p->fd;
    uid_t peer_uid = p->uid;
    pid_t peer_pid = p->pid;
    char line[REQUEST_MAX];
    (void) snprintf(line, sizeof(line), "%s", p->buf);
    drop_pending(i);

    int watchers_before = n_watchers;
    handle_request(fd, line, peer_uid, peer_pid);
    if (n_watchers == watchers_before) {
        (void) close(fd);
    }
}

static void expire_pending(void) {
    uint64_t now = now_ms();
    for (int i = 0; i < n_pending;) {
        if (now >= pending[i].deadline_ms) {
            (void) close(pending[i].fd);
            drop_pending(i);
            continue;
        }
        i++;
    }
}

static void on_signal(int sig) {
    (void) sig;
    terminate = 1;
}

static void stop_all(void) {
    for (int i = 0; i < n_units; i++) {
        units[i].start_pending = false;
        units[i].restart_at_ms = 0;
        units[i].restart_after_stop = false;
        if (units[i].pid > 0) {
            units[i].stop_requested = true;
        }
        (void) signal_cgroup(&units[i], SIGTERM);
    }
    uint64_t deadline = now_ms() + 10000U;
    while (now_ms() < deadline) {
        bool any = false;
        reap_children();
        for (int i = 0; i < n_units; i++) {
            any = any || (units[i].pid > 0);
        }
        if (!any) {
            break;
        }
        (void) usleep(100000);
    }
    for (int i = 0; i < n_units; i++) {
        (void) signal_cgroup(&units[i], SIGKILL);
    }
}

// Units need a cgroup2 hierarchy; mount it if init has not.
static bool setup_cgroups(void) {
    struct statfs fs;
    if ((statfs(CGROUP_ROOT, &fs) != 0) || (fs.f_type != CGROUP2_MAGIC)) {
        if (mount("cgroup2",
                  CGROUP_ROOT,
                  "cgroup2",
                  MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  NULL)
            != 0) {
            logmsg("cannot mount cgroup2 on %s: %s", CGROUP_ROOT, strerror(errno));
            return false;
        }
    }
    if ((mkdir(CGROUP_DIR, 0755) != 0) && (errno != EEXIST)) {
        logmsg("cannot create %s: %s", CGROUP_DIR, strerror(errno));
        return false;
    }
    return true;
}

int main(void) {
    openlog("ggl-svcd", LOG_NDELAY, LOG_DAEMON);
    (void) signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = { .sa_handler = on_signal };
    (void) sigaction(SIGTERM, &sa, NULL);
    (void) sigaction(SIGINT, &sa, NULL);

    (void) umask(0022);
    (void) mkdir(STATE_DIR, 0700);
    (void) mkdir(STATE_DIR "/links", 0700);
    (void) mkdir(STATE_DIR "/units", 0700);
    (void) mkdir(STATE_DIR "/enabled", 0700);
    struct stat st;
    if ((lstat(STATE_DIR, &st) != 0) || !S_ISDIR(st.st_mode) || (st.st_uid != 0)
        || ((st.st_mode & 022) != 0)) {
        logmsg("%s must be a directory only root can write", STATE_DIR);
        return 1;
    }
    if (!setup_cgroups()) {
        return 1;
    }

    int listener = open_listener();
    if (listener < 0) {
        logmsg("cannot listen on %s: %s", GGL_SVC_SOCKET, strerror(errno));
        return 1;
    }

    load_all();
    prune_copies();
    // Boot: start everything that is enabled, like greengrass-lite.target.
    for (int i = 0; i < n_units; i++) {
        if (is_enabled(&units[i])) {
            request_start(&units[i], true);
        }
    }
    logmsg("managing %d units", n_units);

    while (!terminate) {
        reap_children();
        process_timers();
        process_pending();
        expire_pending();

        struct pollfd pfds[1 + MAX_PENDING + MAX_UNITS];
        Unit *owners[1 + MAX_PENDING + MAX_UNITS];
        nfds_t nfds = 0;
        pfds[nfds]
            = (struct pollfd) { .fd = (n_pending < MAX_PENDING) ? listener : -1,
                                .events = POLLIN };
        owners[nfds++] = NULL;
        nfds_t first_pending = nfds;
        for (int i = 0; i < n_pending; i++) {
            pfds[nfds]
                = (struct pollfd) { .fd = pending[i].fd, .events = POLLIN };
            owners[nfds++] = NULL;
        }
        nfds_t first_log = nfds;
        for (int i = 0; i < n_units; i++) {
            if (units[i].log_fd >= 0) {
                pfds[nfds] = (struct pollfd) { .fd = units[i].log_fd,
                                               .events = POLLIN };
                owners[nfds++] = &units[i];
            }
        }
        int ret = poll(pfds, nfds, 250);
        if (ret <= 0) {
            continue;
        }
        for (nfds_t i = first_log; i < nfds; i++) {
            if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                drain_log(owners[i]);
            }
        }
        // Serve in reverse: drop_pending() moves the last entry into the
        // served slot, which has then already been handled.
        for (nfds_t i = first_log; i > first_pending; i--) {
            nfds_t k = i - 1;
            if (pfds[k].revents & (POLLIN | POLLHUP | POLLERR)) {
                serve_pending((int) (k - first_pending));
            }
        }
        if (pfds[0].revents & POLLIN) {
            accept_clients(listener);
        }
    }

    logmsg("stopping all units");
    stop_all();
    (void) unlink(GGL_SVC_SOCKET);
    return 0;
}
