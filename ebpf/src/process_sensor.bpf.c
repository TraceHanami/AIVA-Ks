// SPDX-License-Identifier: GPL-2.0
// AIVA-KS process sensor: execve / fork / clone
// Build with libbpf + CO-RE (bpftool-generated vmlinux.h expected in include/)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} events SEC(".maps");

/* Optional: allow userspace to filter by pid namespace / cgroup later */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);   /* pid */
    __type(value, __u8);  /* 1 = ignore (e.g. our own agent) */
} ignore_pids SEC(".maps");

static __always_inline struct aiva_event *reserve_event(__u8 type)
{
    struct aiva_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    u8 *ignored = bpf_map_lookup_elem(&ignore_pids, &pid);
    if (ignored) {
        bpf_ringbuf_discard(e, 0);
        return NULL;
    }

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->type = type;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;
    e->gid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

/* ---------------- execve ---------------- */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct aiva_event *e = reserve_event(EVT_EXECVE);
    if (!e)
        return 0;

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------- fork / clone ---------------- */
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct aiva_event *e = reserve_event(EVT_FORK);
    if (!e)
        return 0;

    /* child pid captured directly from tracepoint args for accuracy */
    e->target_pid = ctx->child_pid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------- ptrace (injection detection) ---------------- */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct aiva_event *e = reserve_event(EVT_PTRACE);
    if (!e)
        return 0;

    e->ptrace_request = (__u32)ctx->args[0];
    e->target_pid = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------- mprotect (memory permission changes: RWX flips) ---------------- */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    struct aiva_event *e = reserve_event(EVT_MPROTECT);
    if (!e)
        return 0;

    e->addr = (__u64)ctx->args[0];
    e->length = (__u64)ctx->args[1];
    e->prot_flags = (__u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
