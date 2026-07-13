/*
 * crucible_monitor.c — eBPF program for crucible's agent runtime sidecar
 *
 * Probes:
 *   - sys_execve  (type=1) : captures process execution
 *   - sys_openat  (type=2) : captures file open events
 *   - tcp_connect (type=3) : captures outbound TCP connections (future)
 *
 * Build requirement: Linux kernel ≥ 4.8 with BCC toolkit.
 * On non-Linux systems the Python controller falls back to simulator mode.
 *
 * v0.15.0 — Phase 17 Crucible eBPF Sidecar
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* Maximum length for captured strings */
#define MAX_STR_LEN 256

struct event_t {
    u32 pid;
    u32 tgid;
    u32 type;         /* 1=EXECVE, 2=OPENAT, 3=CONNECT */
    char comm[16];
    char details[MAX_STR_LEN];
};

BPF_PERF_OUTPUT(events);

/* Shared helper to submit an event */
static inline int __submit_event(struct pt_regs *ctx, u32 etype, const char *path) {
    struct event_t evt = {};

    evt.pid  = bpf_get_current_pid_tgid() & 0xffffffff;
    evt.tgid = bpf_get_current_pid_tgid() >> 32;
    evt.type = etype;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    if (path) {
        bpf_probe_read_user_str(evt.details, sizeof(evt.details), path);
    }

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* Probe: sys_execve */
int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    return __submit_event(ctx, 1, filename);
}

/* Probe: sys_openat */
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    return __submit_event(ctx, 2, filename);
}
