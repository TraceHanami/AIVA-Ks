"""
CHRONOS Investigation Package — Digital Twin Replay Engine (Module 19).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any
from chronos.research.causality_engine import BehavioralGraph


@dataclass
class ReplaySnapshot:
    step: int
    timestamp: str
    event: dict[str, Any]
    graph_snapshot: dict[str, Any]
    predicted_next_actions: list[str]


class ReplayService:
    def __init__(self):
        self.sessions: dict[str, list[ReplaySnapshot]] = {}

    def build_digital_twin_replay(self, host_id: str, events: list[dict[str, Any]]) -> str:
        session_id = f"replay-{uuid.uuid4().hex[:8]}"
        graph = BehavioralGraph(host_id)
        snapshots: list[ReplaySnapshot] = []

        sorted_events = sorted(events, key=lambda e: str(e.get("time") or e.get("timestamp", "")))

        for idx, evt in enumerate(sorted_events, 1):
            graph.ingest_event(evt)
            graph.propagate_risk()

            next_actions = []
            etype = evt.get("syscall") or evt.get("event_type", "")
            if etype == "execve":
                next_actions.append("Process Execution -> Staging Memory RWX region (T1055)")
            elif etype == "connect":
                next_actions.append("Network Socket Established -> Data Exfiltration C2 (T1041)")
            elif etype in ("open", "read") and "shadow" in str(evt.get("args", {}).get("filename", "")):
                next_actions.append("Credential File Access -> Lateral Movement / Privilege Escalation")
            else:
                next_actions.append("Attacker Reconnaissance / Process Lineage Expansion")

            snapshots.append(ReplaySnapshot(
                step=idx,
                timestamp=str(evt.get("time") or evt.get("timestamp", "")),
                event=evt,
                graph_snapshot=graph.to_json(),
                predicted_next_actions=next_actions,
            ))

        self.sessions[session_id] = snapshots
        return session_id

    def get_snapshot(self, session_id: str, step: int) -> dict[str, Any] | None:
        snapshots = self.sessions.get(session_id)
        if not snapshots:
            return None
        idx = max(0, min(step - 1, len(snapshots) - 1))
        sn = snapshots[idx]
        return {
            "session_id": session_id,
            "step": sn.step,
            "total_steps": len(snapshots),
            "timestamp": sn.timestamp,
            "event": sn.event,
            "graph_snapshot": sn.graph_snapshot,
            "predicted_next_actions": sn.predicted_next_actions,
        }
