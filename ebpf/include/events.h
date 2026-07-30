#ifndef AIVA_EVENTS_H
#define AIVA_EVENTS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 384

enum event_type {
    EVT_EXECVE = 1,
    EVT_FORK   = 2,
    EVT_CLONE  = 3,
    EVT_OPEN   = 4,
    EVT_UNLINK = 5,
    EVT_CONNECT = 6,
    EVT_ACCEPT  = 7,
    EVT_PTRACE  = 8,
    EVT_MPROTECT = 9,
    EVT_MMAP    = 10,
    EVT_SOCKET  = 11,
    EVT_BIND    = 12,
    EVT_LISTEN  = 13,
};

/*
 * Fixed-size event struct shipped through the BPF ring buffer.
 * Kept flat/fixed-size deliberately: the verifier is much happier with
 * fixed-size ring buffer reservations, and it keeps userspace parsing
 * branch-free.
 */
struct aiva_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u8  type;              /* enum event_type */
    char  comm[TASK_COMM_LEN];

    /* process/exec fields */
    char  filename[MAX_FILENAME_LEN];

    /* network fields */
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;          /* IPPROTO_TCP / IPPROTO_UDP */

    /* mmap/mprotect fields */
    __u64 addr;
    __u64 length;
    __u32 prot_flags;

    /* ptrace fields */
    __u32 ptrace_request;
    __u32 target_pid;

    __s32 ret;
};

#endif /* AIVA_EVENTS_H */
