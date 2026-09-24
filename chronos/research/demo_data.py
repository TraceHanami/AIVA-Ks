"""
CHRONOS Research & Technical Demonstration Synthetic Telemetry Datasets.
"""

HOST = "test-host"

ATTACK_EVENTS = [
    {
        "host_id": HOST,
        "pid": 4210,
        "ppid": 1500,
        "comm": "invoice.exe",
        "time": "2026-07-02T10:00:00Z",
        "syscall": "execve",
        "args": {"filename": "/tmp/invoice.exe"},
        "event_id": 1,
    },
    {
        "host_id": HOST,
        "pid": 4210,
        "ppid": 1500,
        "comm": "invoice.exe",
        "time": "2026-07-02T10:00:02Z",
        "syscall": "fork",
        "args": {"target_pid": 4260},
        "event_id": 2,
    },
    {
        "host_id": HOST,
        "pid": 4260,
        "ppid": 4210,
        "comm": "powershell",
        "time": "2026-07-02T10:00:03Z",
        "syscall": "mprotect",
        "args": {"addr": 140234, "length": 4096, "prot_flags": 7},
        "features": {"rwx_mprotect_flag": True},
        "event_id": 3,
    },
    {
        "host_id": HOST,
        "pid": 4260,
        "ppid": 4210,
        "comm": "powershell",
        "time": "2026-07-02T10:00:05Z",
        "syscall": "ptrace",
        "args": {"ptrace_request": 6, "target_pid": 890},
        "event_id": 4,
    },
    {
        "host_id": HOST,
        "pid": 890,
        "ppid": 1,
        "comm": "target_proc",
        "time": "2026-07-02T10:00:07Z",
        "syscall": "open",
        "args": {"filename": "/etc/shadow"},
        "event_id": 5,
    },
    {
        "host_id": HOST,
        "pid": 890,
        "ppid": 1,
        "comm": "target_proc",
        "time": "2026-07-02T10:00:08Z",
        "syscall": "write",
        "args": {"filename": "/tmp/.cache_dump", "bytes": 20480},
        "event_id": 6,
    },
    {
        "host_id": HOST,
        "pid": 4260,
        "ppid": 4210,
        "comm": "powershell",
        "time": "2026-07-02T10:00:10Z",
        "syscall": "connect",
        "args": {"daddr": "203.0.113.55", "dport": 443},
        "event_id": 7,
    },
]

BENIGN_EVENTS = [
    {
        "host_id": HOST,
        "pid": 5000,
        "ppid": 1,
        "comm": "cron",
        "time": "2026-07-02T10:00:11Z",
        "syscall": "execve",
        "args": {"filename": "/usr/sbin/cron"},
        "event_id": 8,
    },
]
