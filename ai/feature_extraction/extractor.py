"""
AIVA-KS Feature Extraction Engine.

Consumes `raw.events`, maintains a short sliding window of per-process
state, computes behavioral features, and republishes to `enriched.events`.

Run: python -m ai.feature_extraction.extractor
"""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from kafka import KafkaConsumer, KafkaProducer

WINDOW_SECONDS = 60


@dataclass
class ProcessWindow:
    """Rolling state for a single (host_id, pid) used to derive features."""
    syscall_times: deque = field(default_factory=deque)   # (ts, syscall)
    file_write_bytes: deque = field(default_factory=deque)  # (ts, bytes)
    connect_targets: deque = field(default_factory=deque)   # (ts, daddr, dport)
    started_at: float = field(default_factory=time.time)

    def prune(self, now: float):
        cutoff = now - WINDOW_SECONDS
        while self.syscall_times and self.syscall_times[0][0] < cutoff:
            self.syscall_times.popleft()
        while self.file_write_bytes and self.file_write_bytes[0][0] < cutoff:
            self.file_write_bytes.popleft()
        while self.connect_targets and self.connect_targets[0][0] < cutoff:
            self.connect_targets.popleft()


class FeatureExtractor:
    def __init__(self):
        self.windows: dict[tuple[str, int], ProcessWindow] = defaultdict(ProcessWindow)

    # ---------- individual feature computations ----------

    def syscall_frequency(self, w: ProcessWindow) -> dict[str, float]:
        """Syscalls/sec over the window, overall and per-syscall-type."""
        if not w.syscall_times:
            return {"overall": 0.0}
        span = max(w.syscall_times[-1][0] - w.syscall_times[0][0], 1.0)
        per_type: dict[str, int] = defaultdict(int)
        for _, sc in w.syscall_times:
            per_type[sc] += 1
        result = {sc: count / span for sc, count in per_type.items()}
        result["overall"] = len(w.syscall_times) / span
        return result

    def file_modification_rate(self, w: ProcessWindow) -> float:
        """Bytes written per second — a spike often precedes ransomware encryption."""
        if not w.file_write_bytes:
            return 0.0
        span = max(w.file_write_bytes[-1][0] - w.file_write_bytes[0][0], 1.0)
        total = sum(b for _, b in w.file_write_bytes)
        return total / span

    def network_burst_score(self, w: ProcessWindow) -> float:
        """
        Detects a burst of distinct outbound connections in a short span —
        a signal for both C2 beaconing and exfiltration/scanning behavior.
        Uses count of distinct (daddr, dport) pairs in the last 10s.
        """
        now = w.connect_targets[-1][0] if w.connect_targets else time.time()
        recent = [t for t in w.connect_targets if t[0] > now - 10]
        distinct = {(d[1], d[2]) for d in recent}
        return float(len(distinct))

    def process_lifespan(self, w: ProcessWindow) -> float:
        return time.time() - w.started_at

    def memory_entropy_flag(self, event: dict) -> bool:
        """
        mprotect flipping a region to RWX (PROT_READ|PROT_WRITE|PROT_EXEC = 7)
        is one of the strongest single-syscall indicators of shellcode
        staging / reflective injection.
        """
        if event["syscall"] != "mprotect":
            return False
        return event.get("args", {}).get("prot_flags") == 7

    # ---------- main event handling ----------

    def process_event(self, event: dict) -> dict:
        key = (event["host_id"], event["pid"])
        w = self.windows[key]
        now = time.time()
        w.prune(now)

        w.syscall_times.append((now, event["syscall"]))

        if event["syscall"] == "write":
            w.file_write_bytes.append((now, event.get("args", {}).get("bytes", 0)))

        if event["syscall"] == "connect":
            args = event.get("args", {})
            w.connect_targets.append((now, args.get("daddr"), args.get("dport")))

        features = {
            "syscall_frequency": self.syscall_frequency(w),
            "file_modification_rate_bps": self.file_modification_rate(w),
            "network_burst_score": self.network_burst_score(w),
            "process_lifespan_s": self.process_lifespan(w),
            "rwx_mprotect_flag": self.memory_entropy_flag(event),
        }

        enriched = dict(event)
        enriched["features"] = features
        return enriched

    def parent_child_lineage(self, event: dict, process_index: dict) -> list[str]:
        """
        Walk ppid chain using an in-memory process index (host_id,pid)->ppid
        populated from execve/fork events, up to depth 10, to give the graph
        engine a ready-made ancestry chain without a DB round-trip.
        """
        chain = [event.get("comm", "?")]
        cur = (event["host_id"], event.get("ppid"))
        depth = 0
        while cur in process_index and depth < 10:
            comm, ppid = process_index[cur]
            chain.append(comm)
            cur = (event["host_id"], ppid)
            depth += 1
        return chain


def main():
    consumer = KafkaConsumer(
        "raw.events",
        bootstrap_servers="localhost:9092",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        group_id="feature-extraction",
        auto_offset_reset="latest",
    )
    producer = KafkaProducer(
        bootstrap_servers="localhost:9092",
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8"),
    )

    extractor = FeatureExtractor()

    for msg in consumer:
        event = msg.value
        enriched = extractor.process_event(event)
        producer.send("enriched.events", key=event["host_id"], value=enriched)


if __name__ == "__main__":
    main()
