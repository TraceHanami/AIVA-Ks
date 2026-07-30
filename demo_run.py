"""
Demo: feeds a synthetic attack sequence (process spawn -> RWX memory
staging -> ptrace injection -> credential file access -> outbound
exfil connection) through the real BehavioralGraph engine and prints
the resulting risk-scored graph + highest-risk path.

This is NOT using live eBPF data — it's synthetic `enriched.events`
shaped exactly like what the real pipeline (collector -> Kafka ->
feature_extraction) would produce, so the graph engine code path is
identical to production.
"""
import json

from ai.graph_engine.graph_builder import BehavioralGraph

HOST = "demo-host-01"

events = [
    # 1. Attacker payload spawns (already-landed foothold, e.g. via phishing)
    {"host_id": HOST, "pid": 4210, "ppid": 1500, "comm": "invoice.exe",
     "time": "2026-07-02T10:00:00Z", "syscall": "execve",
     "args": {"filename": "/tmp/invoice.exe"}, "event_id": 1},

    # 2. It spawns a child process (living-off-the-land binary)
    {"host_id": HOST, "pid": 4210, "ppid": 1500, "comm": "invoice.exe",
     "time": "2026-07-02T10:00:02Z", "syscall": "fork",
     "args": {"target_pid": 4260}, "event_id": 2},

    # 3. Memory region flipped to RWX (classic shellcode staging)
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "powershell",
     "time": "2026-07-02T10:00:03Z", "syscall": "mprotect",
     "args": {"addr": 140234, "length": 4096, "prot_flags": 7},
     "features": {"rwx_mprotect_flag": True}, "event_id": 3},

    # 4. ptrace injection into a legitimate process (e.g. lsass-equivalent)
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "powershell",
     "time": "2026-07-02T10:00:05Z", "syscall": "ptrace",
     "args": {"ptrace_request": 6, "target_pid": 890}, "event_id": 4},

    # 5. Credential store file access (from the injected/target process)
    {"host_id": HOST, "pid": 890, "ppid": 1, "comm": "target_proc",
     "time": "2026-07-02T10:00:07Z", "syscall": "open",
     "args": {"filename": "/etc/shadow"}, "event_id": 5},

    {"host_id": HOST, "pid": 890, "ppid": 1, "comm": "target_proc",
     "time": "2026-07-02T10:00:08Z", "syscall": "write",
     "args": {"filename": "/tmp/.cache_dump", "bytes": 20480}, "event_id": 6},

    # 6. Outbound connection to an external IP (exfil)
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "powershell",
     "time": "2026-07-02T10:00:10Z", "syscall": "connect",
     "args": {"daddr": "203.0.113.55", "dport": 443}, "event_id": 7},

    # noise: an unrelated benign process, should stay low-risk
    {"host_id": HOST, "pid": 5000, "ppid": 1, "comm": "cron",
     "time": "2026-07-02T10:00:11Z", "syscall": "execve",
     "args": {"filename": "/usr/sbin/cron"}, "event_id": 8},
]

graph = BehavioralGraph(HOST)
for e in events:
    graph.ingest_event(e)

graph.propagate_risk(decay=0.7, iterations=3)

result = graph.to_json()

print("=" * 70)
print("GRAPH SUMMARY")
print("=" * 70)
print(f"Nodes: {len(result['nodes'])}   Edges: {len(result['edges'])}")
print()

print("NODE RISK SCORES (sorted highest first)")
print("-" * 70)
for n in sorted(result["nodes"], key=lambda x: -x["risk"]):
    print(f"  [{n['risk']:.2f}] {n['type']:12s} {n['id']:35s} label={n.get('label')}")

print()
print("EDGES")
print("-" * 70)
for e in result["edges"]:
    print(f"  {e['source']:35s} --{e['relation']}--> {e['target']:35s} (w={e['weight']})")

print()
print("HIGHEST-RISK ATTACK PATH")
print("-" * 70)
path = graph.highest_risk_path(min_risk=0.3)
for i, n in enumerate(path):
    risk = graph.g.nodes[n]["risk"]
    arrow = "  ->  " if i > 0 else "      "
    print(f"{arrow}{n}  (risk={risk:.2f})")

with open("demo_graph_output.json", "w") as f:
    json.dump(result, f, indent=2)
print()
print("Full graph JSON written to demo_graph_output.json")
