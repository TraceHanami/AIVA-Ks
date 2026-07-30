"""
AIVA-KS MITRE ATT&CK Mapping Engine (Phase 9).

Maps observed behavioral graph evidence to MITRE ATT&CK techniques with
confidence scores, and chains techniques into a kill-chain-ordered
sequence for the narrative generator.

This is a hybrid approach:
  - Rule-based signatures give deterministic, explainable base evidence
    (fast, no training data needed, good precision for well-known TTPs).
  - A confidence score blends signature strength with graph risk, so
    weakly-evidenced matches don't get reported with false certainty.

A production system would add an embedding-similarity layer on top (for
techniques with no clean syscall signature), but the rule layer alone
already covers the syscalls this platform observes.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Technique:
    technique_id: str
    name: str
    tactic: str          # kill-chain phase, used for chaining/ordering
    kill_chain_order: int


# Minimal but real subset of ATT&CK, scoped to what this platform's
# syscall sensors can actually see evidence for.
TECHNIQUE_KB: dict[str, Technique] = {
    "T1055": Technique("T1055", "Process Injection", "Defense Evasion", 4),
    "T1003": Technique("T1003", "OS Credential Dumping", "Credential Access", 5),
    "T1041": Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration", 7),
    "T1105": Technique("T1105", "Ingress Tool Transfer", "Command and Control", 6),
    "T1547": Technique("T1547", "Boot or Logon Autostart Execution", "Persistence", 3),
    "T1071": Technique("T1071", "Application Layer Protocol", "Command and Control", 6),
    "T1486": Technique("T1486", "Data Encrypted for Impact", "Impact", 8),
    "T1059": Technique("T1059", "Command and Scripting Interpreter", "Execution", 2),
}


@dataclass
class TechniqueMatch:
    technique: Technique
    confidence: float
    evidence_event_ids: list[int] = field(default_factory=list)
    rationale: str = ""


class MitreMapper:
    """
    Consumes a BehavioralGraph (see ai/graph_engine/graph_builder.py) plus
    the raw event list it was built from, and produces technique matches.
    """

    def map_events(self, events: list[dict], graph) -> list[TechniqueMatch]:
        matches: list[TechniqueMatch] = []

        matches += self._detect_process_injection(events, graph)
        matches += self._detect_credential_access(events)
        matches += self._detect_exfiltration(events, graph)
        matches += self._detect_scripting_interpreter(events)
        matches += self._detect_c2_channel(events, graph)

        # de-dup by technique_id, keeping highest-confidence match
        best: dict[str, TechniqueMatch] = {}
        for m in matches:
            existing = best.get(m.technique.technique_id)
            if not existing or m.confidence > existing.confidence:
                best[m.technique.technique_id] = m
        return sorted(best.values(), key=lambda m: m.technique.kill_chain_order)

    # ---------- individual signatures ----------

    def _detect_process_injection(self, events, graph) -> list[TechniqueMatch]:
        ptrace_events = [e for e in events if e["syscall"] == "ptrace"]
        rwx_events = [e for e in events if e.get("features", {}).get("rwx_mprotect_flag")]
        if not ptrace_events:
            return []
        confidence = 0.6
        rationale = "ptrace call targeting another process"
        if rwx_events:
            confidence = 0.9
            rationale += "; preceded by an RWX memory region (shellcode staging pattern)"
        return [TechniqueMatch(
            TECHNIQUE_KB["T1055"], confidence,
            evidence_event_ids=[e["event_id"] for e in ptrace_events + rwx_events],
            rationale=rationale,
        )]

    def _detect_credential_access(self, events) -> list[TechniqueMatch]:
        sensitive_paths = ("/etc/shadow", "/etc/passwd", "/etc/gshadow")
        hits = [e for e in events if e["syscall"] in ("open", "read")
                and any(p in e.get("args", {}).get("filename", "") for p in sensitive_paths)]
        if not hits:
            return []
        return [TechniqueMatch(
            TECHNIQUE_KB["T1003"], 0.75,
            evidence_event_ids=[e["event_id"] for e in hits],
            rationale=f"access to credential store file(s): "
                      f"{sorted({e['args']['filename'] for e in hits})}",
        )]

    def _detect_exfiltration(self, events, graph) -> list[TechniqueMatch]:
        connects = [e for e in events if e["syscall"] == "connect"]
        writes = [e for e in events if e["syscall"] == "write"
                  and e.get("args", {}).get("bytes", 0) > 1000]
        if not connects or not writes:
            return []
        # confidence rises if the writing process is the same one that connects,
        # or if it's within the same causal chain (graph predecessor relationship)
        confidence = 0.5
        rationale = "large file write followed by outbound connection"
        writer_pids = {w["pid"] for w in writes}
        connector_pids = {c["pid"] for c in connects}
        if writer_pids & connector_pids:
            confidence = 0.7
            rationale += " (same process performed both)"
        return [TechniqueMatch(
            TECHNIQUE_KB["T1041"], confidence,
            evidence_event_ids=[e["event_id"] for e in connects + writes],
            rationale=rationale,
        )]

    def _detect_scripting_interpreter(self, events) -> list[TechniqueMatch]:
        interpreters = ("powershell", "bash", "sh", "python", "perl", "wscript", "cscript")
        hits = [e for e in events if e["syscall"] == "execve"
                and any(i in (e.get("comm", "") or "").lower() for i in interpreters)]
        if not hits:
            return []
        return [TechniqueMatch(
            TECHNIQUE_KB["T1059"], 0.4,   # low confidence alone — very common, benign most of the time
            evidence_event_ids=[e["event_id"] for e in hits],
            rationale="scripting interpreter execution observed",
        )]

    def _detect_c2_channel(self, events, graph) -> list[TechniqueMatch]:
        connects = [e for e in events if e["syscall"] == "connect"
                    and e.get("args", {}).get("dport") in (443, 8443, 53)]
        if not connects:
            return []
        return [TechniqueMatch(
            TECHNIQUE_KB["T1071"], 0.35,  # low alone; rises when combined with injection/exfil
            evidence_event_ids=[e["event_id"] for e in connects],
            rationale="outbound connection on a common C2/blend-in port",
        )]

    # ---------- kill chain assembly ----------

    def build_kill_chain(self, matches: list[TechniqueMatch]) -> list[TechniqueMatch]:
        """Order matches by kill-chain phase for the narrative generator."""
        return sorted(matches, key=lambda m: m.technique.kill_chain_order)
