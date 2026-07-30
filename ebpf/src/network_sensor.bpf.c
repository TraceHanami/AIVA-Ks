// SPDX-License-Identifier: GPL-2.0
// AIVA-KS network sensor: connect / accept / socket / bind / listen
// Uses kprobes on tcp_v4_connect + tracepoints for socket syscalls.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

static __always_inline struct aiva_event *reserve_net_event(__u8 type)
{
    struct aiva_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return NULL;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

/* kprobe on tcp_v4_connect gives us the sock struct with real 4-tuple,
 * which is far more reliable than parsing sockaddr from the syscall args. */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk)
{
    struct aiva_event *e = reserve_net_event(EVT_CONNECT);
    if (!e)
        return 0;

    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->protocol = IPPROTO_TCP;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept(struct trace_event_raw_sys_enter *ctx)
{
    struct aiva_event *e = reserve_net_event(EVT_ACCEPT);
    if (!e)
        return 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct aiva_event *e = reserve_net_event(EVT_SOCKET);
    if (!e)
        return 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx)
{
    struct aiva_event *e = reserve_net_event(EVT_LISTEN);
    if (!e)
        return 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
