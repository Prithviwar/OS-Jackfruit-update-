/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 8192
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)
#define STOP_TIMEOUT_SECS 5

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

/* child_config_t is declared before container_record_t so the record can
 * hold a pointer to it for deferred freeing after the child exits. */
typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    /* Signaled by the reaper when the container transitions to a terminal
     * state; guarded by the supervisor's metadata_lock. */
    pthread_cond_t exit_cond;
    int log_read_fd;            /* read end of the stdout/stderr capture pipe */
    pthread_t log_reader_tid;   /* thread draining the pipe into the log buffer */
    char *clone_stack;          /* stack allocated for clone(); freed after exit */
    child_config_t *child_cfg;  /* config allocated for clone(); freed after exit */
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    volatile int should_stop;
    pthread_t logger_thread;
    pthread_t reaper_thread_id;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* Per-container thread that reads stdout/stderr from a pipe and pushes
 * chunks into the shared bounded log buffer. */
typedef struct {
    int read_fd;
    char container_id[CONTAINER_ID_LEN];
    supervisor_ctx_t *ctx;
} log_reader_arg_t;

/* Per-client thread that dispatches a single control request. */
typedef struct {
    int client_fd;
    supervisor_ctx_t *ctx;
} client_handler_arg_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/* Producer-side insertion: blocks while the buffer is full (or returns -1 if
 * shutdown begins), then enqueues the item and wakes the consumer. */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    // Wait if buffer is full AND we aren't shutting down
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    }

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    // Insert item
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    // Wake up the logging thread
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/* Consumer-side removal: waits while the buffer is empty, returns -1 only
 * when both the buffer is empty and shutdown has been requested. */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    // Wait if buffer is empty AND we aren't shutting down
    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }

    // If empty and shutting down, exit
    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    // Remove item
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    // Wake up producers
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/* Logging consumer thread: drains the bounded log buffer and appends each
 * chunk to the appropriate per-container log file under LOG_DIR/. */
static void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    char path[PATH_MAX];

    mkdir(LOG_DIR, 0755);

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);

        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            if (write(fd, item.data, item.length) < (ssize_t)item.length)
                fprintf(stderr, "logging_thread: short write to %s\n", path);
            close(fd);
        }
    }
    return NULL;
}

/* Log-reader producer thread: reads raw bytes from a container's stdout/stderr
 * pipe and pushes LOG_CHUNK_SIZE-sized chunks into the bounded log buffer. */
static void *log_reader_thread_fn(void *arg)
{
    log_reader_arg_t *larg = (log_reader_arg_t *)arg;
    log_item_t item;
    ssize_t n;

    memset(item.container_id, 0, sizeof(item.container_id));
    snprintf(item.container_id, sizeof(item.container_id), "%s",
             larg->container_id);

    while ((n = read(larg->read_fd, item.data, LOG_CHUNK_SIZE)) > 0) {
        item.length = (size_t)n;
        if (bounded_buffer_push(&larg->ctx->log_buffer, &item) != 0)
            break;
    }

    close(larg->read_fd);
    free(larg);
    return NULL;
}

/* Clone child entrypoint.
 * Required outcomes: isolated PID/UTS/mount context, chroot into rootfs,
 * working /proc, stdout/stderr captured via log pipe, exec the command. */
int child_fn(void *arg)
{
    child_config_t *config = (child_config_t *)arg;

    /* 1. Isolate hostname (UTS namespace). */
    if (sethostname(config->id, strlen(config->id)) != 0) {
        perror("child: sethostname");
        return 1;
    }

    /* 2. Make all mounts private so they don't propagate to the host. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("child: mount propagation");
        return 1;
    }

    /* 3. Redirect stdout/stderr into the supervisor's log pipe before chroot
     *    so that error messages from the setup steps are also captured. */
    if (config->log_write_fd >= 0) {
        dup2(config->log_write_fd, STDOUT_FILENO);
        dup2(config->log_write_fd, STDERR_FILENO);
        close(config->log_write_fd);
        config->log_write_fd = -1;
    }

    /* 4. Chroot into the provided rootfs. */
    if (chroot(config->rootfs) != 0) {
        perror("child: chroot");
        return 1;
    }
    if (chdir("/") != 0) {
        perror("child: chdir");
        return 1;
    }

    /* 5. Mount /proc — required by the kernel monitor and standard tooling.
     *    Create the directory if it is absent in the rootfs. */
    if (mkdir("/proc", 0555) != 0 && errno != EEXIST) {
        perror("child: mkdir /proc");
    }
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("child: mount proc");
        return 1;
    }

    /* 6. Apply nice value (non-fatal on failure). */
    if (config->nice_value != 0) {
        errno = 0;
        if (nice(config->nice_value) == -1 && errno != 0)
            perror("child: nice");
    }

    /* 7. Execute the requested command via the shell. */
    char *argv[] = {"/bin/sh", "-c", config->command, NULL};

    if (execvp(argv[0], argv) == -1) {
        perror("child: execvp");
        return 1;
    }

    return 0;
}

static int register_with_monitor(int monitor_fd,
                                 const char *container_id,
                                 pid_t host_pid,
                                 unsigned long soft_limit_bytes,
                                 unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    snprintf(req.container_id, sizeof(req.container_id), "%s", container_id);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

static int unregister_from_monitor(int monitor_fd,
                                   const char *container_id,
                                   pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    snprintf(req.container_id, sizeof(req.container_id), "%s", container_id);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

/* -------------------------------------------------------------------------
 * Global supervisor context pointer — used only by signal handlers.
 * ------------------------------------------------------------------------- */
static supervisor_ctx_t *g_ctx = NULL;

static void handle_shutdown_signal(int sig)
{
    (void)sig;
    if (g_ctx)
        g_ctx->should_stop = 1;
}

/* -------------------------------------------------------------------------
 * Container record helpers (all called with metadata_lock held unless noted).
 * ------------------------------------------------------------------------- */

/* Returns the record whose id matches, or NULL. */
static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *c;
    for (c = ctx->containers; c != NULL; c = c->next) {
        if (strncmp(c->id, id, CONTAINER_ID_LEN) == 0)
            return c;
    }
    return NULL;
}

/* Returns the record whose host_pid matches, or NULL. */
static container_record_t *find_container_by_pid(supervisor_ctx_t *ctx, pid_t pid)
{
    container_record_t *c;
    for (c = ctx->containers; c != NULL; c = c->next) {
        if (c->host_pid == pid)
            return c;
    }
    return NULL;
}

/* Prepend a new record to the container list. */
static void add_container(supervisor_ctx_t *ctx, container_record_t *rec)
{
    rec->next = ctx->containers;
    ctx->containers = rec;
}

/* -------------------------------------------------------------------------
 * Reaper thread — reaps all child processes using WNOHANG polling so it
 * never blocks the supervisor indefinitely while still processing exits
 * promptly (≤100 ms latency). Updates container state and signals any
 * CMD_RUN handler threads waiting on exit_cond.
 * ------------------------------------------------------------------------- */
static void *reaper_thread_fn(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    struct timespec sleep_ts = {0, 100000000}; /* 100 ms */

    while (!ctx->should_stop) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid < 0) {
            if (errno == EINTR || errno == ECHILD) {
                nanosleep(&sleep_ts, NULL);
                continue;
            }
            break;
        }

        if (pid == 0) {
            /* No child exited yet; yield briefly. */
            nanosleep(&sleep_ts, NULL);
            continue;
        }

        /* Update the container record and notify waiters. */
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container_by_pid(ctx, pid);
        if (rec) {
            if (WIFEXITED(status)) {
                rec->state = CONTAINER_EXITED;
                rec->exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                rec->state = CONTAINER_KILLED;
                rec->exit_signal = WTERMSIG(status);
                rec->exit_code = 128 + WTERMSIG(status);
            }
            pthread_cond_broadcast(&rec->exit_cond);

            /* Free deferred allocations now that the child has exited. */
            free(rec->clone_stack);
            rec->clone_stack = NULL;
            free(rec->child_cfg);
            rec->child_cfg = NULL;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        /* Unregister from the kernel monitor (best-effort). */
        if (ctx->monitor_fd >= 0 && rec)
            unregister_from_monitor(ctx->monitor_fd, rec->id, pid);
    }

    return NULL;
}

/* -------------------------------------------------------------------------
 * Container start helper — creates the log capture pipe, clones the child
 * with namespace isolation, registers it with the kernel monitor, builds the
 * container_record_t, and spawns a log-reader thread.
 *
 * Returns the child PID on success, -1 on failure.
 * ------------------------------------------------------------------------- */
static pid_t start_container(supervisor_ctx_t *ctx, const control_request_t *req)
{
    size_t id_len;
    int pipefd[2];
    child_config_t *config = NULL;
    char *stack = NULL;
    container_record_t *rec = NULL;
    log_reader_arg_t *larg = NULL;
    pid_t child_pid;

    /* Validate container ID: must be non-empty, shorter than the field, and
     * must not contain '/' or '.' to prevent log-path traversal. */
    id_len = strnlen(req->container_id, CONTAINER_ID_LEN);
    if (id_len == 0 || id_len >= CONTAINER_ID_LEN ||
        strchr(req->container_id, '/') || strchr(req->container_id, '.')) {
        fprintf(stderr, "supervisor: invalid container id\n");
        return -1;
    }

    /* Pipe for capturing the container's stdout/stderr. */
    if (pipe(pipefd) != 0) {
        perror("supervisor: pipe");
        return -1;
    }
    /* Mark both ends close-on-exec so only the deliberately dup2'd
     * STDOUT/STDERR in child_fn remains open after exec. */
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    config = calloc(1, sizeof(*config));
    stack  = malloc(STACK_SIZE);
    if (!config || !stack)
        goto err_alloc;

    snprintf(config->id,      CONTAINER_ID_LEN,  "%s", req->container_id);
    snprintf(config->rootfs,  PATH_MAX,           "%s", req->rootfs);
    snprintf(config->command, CHILD_COMMAND_LEN,  "%s", req->command);
    config->nice_value   = req->nice_value;
    config->log_write_fd = pipefd[1]; /* child_fn dup2s this to stdout/stderr */

    child_pid = clone(child_fn,
                      stack + STACK_SIZE,
                      CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                      config);

    /* Close the write end in the parent regardless of clone outcome. */
    close(pipefd[1]);

    if (child_pid < 0) {
        perror("supervisor: clone");
        goto err_clone;
    }

    /* Register the new container with the kernel monitor (best-effort). */
    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, config->id, child_pid,
                              req->soft_limit_bytes, req->hard_limit_bytes);

    /* Build the in-memory container record. */
    rec = calloc(1, sizeof(*rec));
    if (!rec) {
        kill(child_pid, SIGKILL);
        close(pipefd[0]);
        goto err_clone;
    }

    snprintf(rec->id, CONTAINER_ID_LEN, "%s", config->id);
    rec->host_pid         = child_pid;
    rec->state            = CONTAINER_RUNNING;
    rec->started_at       = time(NULL);
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    snprintf(rec->log_path, sizeof(rec->log_path) - 1,
             "%s/%s.log", LOG_DIR, config->id);
    rec->log_read_fd = pipefd[0];
    rec->clone_stack = stack;
    rec->child_cfg   = config;
    pthread_cond_init(&rec->exit_cond, NULL);

    pthread_mutex_lock(&ctx->metadata_lock);
    add_container(ctx, rec);
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Spawn the log-reader thread that drains the pipe into the log buffer. */
    larg = malloc(sizeof(*larg));
    if (larg) {
        snprintf(larg->container_id, CONTAINER_ID_LEN, "%s", config->id);
        larg->read_fd = pipefd[0];
        larg->ctx     = ctx;
        pthread_create(&rec->log_reader_tid, NULL, log_reader_thread_fn, larg);
    } else {
        close(pipefd[0]);
    }

    printf("supervisor: container %s started (pid %d)\n", config->id, child_pid);
    return child_pid;

err_alloc:
    close(pipefd[0]);
    close(pipefd[1]);
    free(config);
    free(stack);
    return -1;

err_clone:
    free(config);
    free(stack);
    return -1;
}

/* -------------------------------------------------------------------------
 * Per-command handlers invoked from handle_client.
 * All populate *res before returning; the caller sends it to the client.
 * ------------------------------------------------------------------------- */

static void handle_start(supervisor_ctx_t *ctx,
                         const control_request_t *req,
                         control_response_t *res)
{
    pid_t pid = start_container(ctx, req);
    if (pid < 0) {
        res->status = -1;
        snprintf(res->message, sizeof(res->message),
                 "failed to start container %s", req->container_id);
    } else {
        res->status = (int)pid;
        snprintf(res->message, sizeof(res->message),
                 "started %s pid=%d", req->container_id, (int)pid);
    }
}

static void handle_run(supervisor_ctx_t *ctx,
                       const control_request_t *req,
                       control_response_t *res)
{
    pid_t pid = start_container(ctx, req);
    if (pid < 0) {
        res->status = -1;
        snprintf(res->message, sizeof(res->message),
                 "failed to start container %s", req->container_id);
        return;
    }

    /* Block until the reaper signals that this container has terminated. */
    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *rec = find_container_by_pid(ctx, pid);
    while (rec &&
           rec->state != CONTAINER_EXITED &&
           rec->state != CONTAINER_KILLED &&
           rec->state != CONTAINER_STOPPED) {
        pthread_cond_wait(&rec->exit_cond, &ctx->metadata_lock);
    }
    if (rec) {
        res->status = rec->exit_code;
        if (rec->state == CONTAINER_EXITED) {
            snprintf(res->message, sizeof(res->message),
                     "container %s exited with code %d",
                     req->container_id, rec->exit_code);
        } else {
            snprintf(res->message, sizeof(res->message),
                     "container %s killed by signal %d",
                     req->container_id, rec->exit_signal);
        }
    } else {
        res->status = -1;
        snprintf(res->message, sizeof(res->message),
                 "container %s record lost", req->container_id);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);
}

static void handle_ps(supervisor_ctx_t *ctx, control_response_t *res)
{
    char buf[CONTROL_MESSAGE_LEN];
    int len = 0;
    int remaining = (int)sizeof(buf) - 1;

    len += snprintf(buf + len, (size_t)(remaining - len > 0 ? remaining - len : 0),
                    "%-16s %-8s %-10s %-20s %s\n",
                    "ID", "PID", "STATE", "STARTED", "EXIT");

    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *c;
    for (c = ctx->containers; c != NULL && len < remaining; c = c->next) {
        char started[24] = "-";
        char exit_info[24] = "-";

        if (c->started_at) {
            struct tm *tm_info = localtime(&c->started_at);
            if (tm_info)
                strftime(started, sizeof(started), "%Y-%m-%d %H:%M:%S", tm_info);
        }

        if (c->state == CONTAINER_EXITED)
            snprintf(exit_info, sizeof(exit_info), "code=%d", c->exit_code);
        else if (c->state == CONTAINER_KILLED)
            snprintf(exit_info, sizeof(exit_info), "sig=%d",  c->exit_signal);
        else if (c->state == CONTAINER_STOPPED)
            snprintf(exit_info, sizeof(exit_info), "stopped");

        len += snprintf(buf + len, (size_t)(remaining - len > 0 ? remaining - len : 0),
                        "%-16s %-8d %-10s %-20s %s\n",
                        c->id, (int)c->host_pid,
                        state_to_string(c->state), started, exit_info);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (len == 0)
        snprintf(buf, sizeof(buf), "No containers.\n");

    snprintf(res->message, sizeof(res->message), "%s", buf);
    res->status = 0;
}

static void handle_logs(const control_request_t *req,
                        control_response_t *res)
{
    char path[PATH_MAX];
    int fd;
    off_t size, start;
    ssize_t n;

    /* Validate: container_id must not contain '/' or '.' */
    if (req->container_id[0] == '\0' ||
        strchr(req->container_id, '/') ||
        strchr(req->container_id, '.')) {
        res->status = -1;
        snprintf(res->message, sizeof(res->message), "invalid container id");
        return;
    }

    snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, req->container_id);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        res->status = -1;
        snprintf(res->message, sizeof(res->message),
                 "no log found for container %s", req->container_id);
        return;
    }

    size = lseek(fd, 0, SEEK_END);
    if (size < 0) size = 0;

    /* Return up to (sizeof(message)-1) bytes from the tail of the file. */
    start = (size > (off_t)(sizeof(res->message) - 1))
                ? size - (off_t)(sizeof(res->message) - 1)
                : 0;
    lseek(fd, start, SEEK_SET);

    n = read(fd, res->message, sizeof(res->message) - 1);
    close(fd);

    if (n < 0) n = 0;
    res->message[n] = '\0';
    res->status = 0;
}

static void handle_stop(supervisor_ctx_t *ctx,
                        const control_request_t *req,
                        control_response_t *res)
{
    pid_t pid;
    struct timespec deadline;

    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *rec = find_container(ctx, req->container_id);

    if (!rec ||
        (rec->state != CONTAINER_RUNNING && rec->state != CONTAINER_STARTING)) {
        res->status = -1;
        snprintf(res->message, sizeof(res->message),
                 "container %s not found or not running", req->container_id);
        pthread_mutex_unlock(&ctx->metadata_lock);
        return;
    }

    pid = rec->host_pid;
    rec->state = CONTAINER_STOPPED;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Ask nicely first. */
    kill(pid, SIGTERM);

    /* Wait up to STOP_TIMEOUT_SECS for the reaper to update the state. */
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += STOP_TIMEOUT_SECS;

    pthread_mutex_lock(&ctx->metadata_lock);
    rec = find_container(ctx, req->container_id);
    while (rec &&
           rec->state != CONTAINER_EXITED &&
           rec->state != CONTAINER_KILLED) {
        int rc = pthread_cond_timedwait(&rec->exit_cond,
                                        &ctx->metadata_lock, &deadline);
        if (rc == ETIMEDOUT) {
            /* SIGTERM was not enough; escalate to SIGKILL. */
            kill(pid, SIGKILL);
            break;
        }
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    res->status = 0;
    snprintf(res->message, sizeof(res->message),
             "container %s stopped", req->container_id);
}

/* -------------------------------------------------------------------------
 * Per-client handler thread — reads one request, dispatches it, sends the
 * response, and exits.  Detached so no join is required.
 * ------------------------------------------------------------------------- */
static void *handle_client(void *arg)
{
    client_handler_arg_t *carg = (client_handler_arg_t *)arg;
    supervisor_ctx_t *ctx = carg->ctx;
    int client_fd = carg->client_fd;
    control_request_t req;
    control_response_t res;

    free(carg);
    memset(&res, 0, sizeof(res));

    if (recv(client_fd, &req, sizeof(req), MSG_WAITALL) <= 0) {
        close(client_fd);
        return NULL;
    }

    switch (req.kind) {
    case CMD_START:
        handle_start(ctx, &req, &res);
        break;
    case CMD_RUN:
        handle_run(ctx, &req, &res);
        break;
    case CMD_PS:
        handle_ps(ctx, &res);
        break;
    case CMD_LOGS:
        handle_logs(&req, &res);
        break;
    case CMD_STOP:
        handle_stop(ctx, &req, &res);
        break;
    default:
        res.status = -1;
        snprintf(res.message, sizeof(res.message), "unknown command");
        break;
    }

    send(client_fd, &res, sizeof(res), MSG_NOSIGNAL);
    close(client_fd);
    return NULL;
}

/* -------------------------------------------------------------------------
 * Graceful shutdown helper — stop all containers, drain log pipeline, join
 * background threads, close descriptors, and remove the socket file.
 * ------------------------------------------------------------------------- */
static void shutdown_supervisor(supervisor_ctx_t *ctx)
{
    container_record_t *c;

    /* Ask all running containers to terminate. */
    pthread_mutex_lock(&ctx->metadata_lock);
    for (c = ctx->containers; c != NULL; c = c->next) {
        if (c->state == CONTAINER_RUNNING || c->state == CONTAINER_STARTING)
            kill(c->host_pid, SIGTERM);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Give them a moment, then force-kill any survivors. */
    sleep(1);

    pthread_mutex_lock(&ctx->metadata_lock);
    for (c = ctx->containers; c != NULL; c = c->next) {
        if (c->state == CONTAINER_RUNNING ||
            c->state == CONTAINER_STARTING ||
            c->state == CONTAINER_STOPPED)
            kill(c->host_pid, SIGKILL);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Wait for the reaper to finish draining child exits. */
    pthread_join(ctx->reaper_thread_id, NULL);

    /* Drain the logging pipeline then join the logger thread. */
    bounded_buffer_begin_shutdown(&ctx->log_buffer);
    pthread_join(ctx->logger_thread, NULL);

    /* Close the listening socket and remove the socket file. */
    close(ctx->server_fd);
    unlink(CONTROL_PATH);

    if (ctx->monitor_fd >= 0)
        close(ctx->monitor_fd);

    /* Free all remaining container records. */
    pthread_mutex_lock(&ctx->metadata_lock);
    c = ctx->containers;
    while (c) {
        container_record_t *next = c->next;
        pthread_cond_destroy(&c->exit_cond);
        free(c->clone_stack);
        free(c->child_cfg);
        free(c);
        c = next;
    }
    ctx->containers = NULL;
    pthread_mutex_unlock(&ctx->metadata_lock);

    pthread_mutex_destroy(&ctx->metadata_lock);
    bounded_buffer_destroy(&ctx->log_buffer);
}

/* -------------------------------------------------------------------------
 * Supervisor entry point.
 * ------------------------------------------------------------------------- */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    struct sigaction sa;

    memset(&ctx, 0, sizeof(ctx));

    /* Open the kernel monitor (best-effort; -1 disables monitor ops). */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "supervisor: /dev/container_monitor unavailable (%s); "
                "monitor integration disabled\n", strerror(errno));
    else
        fcntl(ctx.monitor_fd, F_SETFD, FD_CLOEXEC);

    pthread_mutex_init(&ctx.metadata_lock, NULL);
    bounded_buffer_init(&ctx.log_buffer);

    /* UNIX domain socket control plane. */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("supervisor: socket");
        return 1;
    }
    fcntl(ctx.server_fd, F_SETFD, FD_CLOEXEC);

    unlink(CONTROL_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("supervisor: bind");
        close(ctx.server_fd);
        return 1;
    }
    if (listen(ctx.server_fd, 16) < 0) {
        perror("supervisor: listen");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        return 1;
    }

    /* Install signal handlers for graceful shutdown.
     * Not setting SA_RESTART means accept() will return EINTR on signal. */
    g_ctx = &ctx;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Ignore SIGPIPE so writes to disconnected clients don't kill us. */
    signal(SIGPIPE, SIG_IGN);

    /* Start background threads. */
    pthread_create(&ctx.logger_thread,    NULL, logging_thread, &ctx);
    pthread_create(&ctx.reaper_thread_id, NULL, reaper_thread_fn, &ctx);

    printf("supervisor: initialized (rootfs base: %s)\n", rootfs);
    printf("supervisor: listening on %s\n", CONTROL_PATH);

    /* Accept loop — each connection is handled in a detached thread so that
     * CMD_RUN (which blocks until the container exits) does not stall other
     * clients. */
    while (!ctx.should_stop) {
        int client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                break; /* signal received — start shutdown */
            if (!ctx.should_stop)
                perror("supervisor: accept");
            continue;
        }

        client_handler_arg_t *carg = malloc(sizeof(*carg));
        if (!carg) {
            close(client_fd);
            continue;
        }
        carg->client_fd = client_fd;
        carg->ctx       = &ctx;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, handle_client, carg) != 0) {
            free(carg);
            close(client_fd);
        }
        pthread_attr_destroy(&attr);
    }

    shutdown_supervisor(&ctx);
    return 0;
}

/* -------------------------------------------------------------------------
 * Client-side: send a control request and print the supervisor's response.
 * Returns res.status so the process exit code reflects the container's.
 * ------------------------------------------------------------------------- */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t res;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("client: socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("client: connect to supervisor failed");
        close(fd);
        return 1;
    }

    if (send(fd, req, sizeof(*req), 0) < 0) {
        perror("client: send");
        close(fd);
        return 1;
    }

    memset(&res, 0, sizeof(res));
    if (recv(fd, &res, sizeof(res), MSG_WAITALL) <= 0) {
        perror("client: recv");
        close(fd);
        return 1;
    }

    close(fd);

    if (res.message[0] != '\0')
        printf("%s\n", res.message);

    return res.status;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,        argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,       argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command>"
                " [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,        argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,       argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    /* Return value propagates the container exit code to the caller. */
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
