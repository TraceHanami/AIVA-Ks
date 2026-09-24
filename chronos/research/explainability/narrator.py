"""
CHRONOS Research Module — Grounded Narrative Generator (Module 7 & 14).

Converts EvidenceBundle into deterministic analyst summaries and chronological timelines.
"""
from __future__ import annotations

from chronos.research.explainability.evidence import EvidenceBundle


class TemplateNarrator:
    """Deterministic, zero-dependency, grounded incident narrator."""

    def narrate(self, bundle: EvidenceBundle) -> str:
        if not bundle.technique_matches:
            return (f"No significant attack techniques were identified on host "
                     f"'{bundle.host_id}'. Overall risk score: {bundle.overall_risk_score:.2f}.")

        technique_phrases = []
        for m in bundle.technique_matches:
            technique_phrases.append(
                f"{m.technique.name} ({m.technique.technique_id}, "
                f"confidence {m.confidence:.0%}) — {m.rationale}"
            )

        chain_str = " -> ".join(bundle.highest_risk_path) if bundle.highest_risk_path else "unclear"

        return (
            f"On host '{bundle.host_id}', the process chain '{chain_str}' "
            f"reached an overall blast risk score of {bundle.overall_risk_score:.2f}. "
            f"The following MITRE ATT&CK techniques were identified, ordered by kill-chain phase:\n"
            + "\n".join(f"  - {p}" for p in technique_phrases)
            + f"\nEvidence spans {len(bundle.evidence_event_ids)} correlated events."
        )


class AttackNarrativeGenerator:
    """Builds chronological attack timelines and timeline text summaries."""

    def generate_timeline(self, events: list[dict]) -> list[dict]:
        timeline = []
        for e in sorted(events, key=lambda evt: str(evt.get("time") or evt.get("timestamp", ""))):
            timeline.append({
                "time": str(e.get("time") or e.get("timestamp", "")),
                "event_id": e.get("event_id"),
                "summary": self._summarize_event(e),
            })
        return timeline

    def _summarize_event(self, e: dict) -> str:
        comm = e.get("comm", "process")
        pid = e.get("pid")
        etype = e.get("syscall") or e.get("event_type", "event")
        if etype == "execve":
            return f"{comm} (pid {pid}) executed {e.get('args', {}).get('filename', '?')}"
        if etype in ("fork", "clone"):
            return f"{comm} (pid {pid}) spawned child pid {e.get('args', {}).get('target_pid')}"
        if etype == "mprotect" and e.get("features", {}).get("rwx_mprotect_flag"):
            return f"{comm} (pid {pid}) flipped a memory region to RWX (possible shellcode staging)"
        if etype == "ptrace":
            return f"{comm} (pid {pid}) used ptrace on pid {e.get('args', {}).get('target_pid')} (possible injection)"
        if etype in ("open", "read") and "shadow" in str(e.get("args", {}).get("filename", "")):
            return f"{comm} (pid {pid}) accessed credential store {e.get('args', {}).get('filename')}"
        if etype == "write":
            return f"{comm} (pid {pid}) wrote {e.get('args', {}).get('bytes', '?')} bytes to {e.get('args', {}).get('filename', '?')}"
        if etype == "connect":
            args = e.get("args", {})
            return f"{comm} (pid {pid}) connected to {args.get('daddr')}:{args.get('dport')}"
        return f"{comm} (pid {pid}) called {etype}"

    def generate_summary(self, timeline: list[dict]) -> str:
        if not timeline:
            return "No events recorded."
        lines = [f"  {t['time']}  {t['summary']}" for t in timeline]
        return "Attack timeline:\n" + "\n".join(lines)
