"""
AIVA-KS Explainability Engine (Phase 10) + Attack Narrative Generator (Phase 11).

Two-stage design:
  1. Evidence extraction — pull the concrete, cited facts (which events,
     which files, which techniques) out of the graph + MITRE matches.
     This stage is deterministic and produces the same evidence_bundle
     every time for the same input, which is what makes the narrative
     auditable (every claim traces back to an event_id).
  2. Narrative generation — turn the evidence bundle into analyst prose.
     Two backends are provided:
       - TemplateNarrator: rule-based, zero-dependency, deterministic.
         Used here (and in tests) because it needs no API key/network.
       - LLMNarrator: the production path — builds a grounded prompt from
         the SAME evidence_bundle and calls an LLM. Shown with the exact
         prompt structure; the actual API call is stubbed since this
         environment has no LLM credentials configured.

Keeping evidence extraction separate from narration means both backends
are provably grounded in the same facts — the LLM can't "hallucinate" an
event that didn't happen because it never sees raw telemetry, only the
pre-extracted evidence_bundle.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ai.mitre_mapping.mapping_engine import TechniqueMatch


@dataclass
class EvidenceBundle:
    host_id: str
    root_process: str
    highest_risk_path: list[str]
    technique_matches: list[TechniqueMatch]
    overall_risk_score: float
    evidence_event_ids: list[int] = field(default_factory=list)


class EvidenceExtractor:
    def extract(self, graph, technique_matches: list[TechniqueMatch]) -> EvidenceBundle:
        path = graph.highest_risk_path(min_risk=0.3)
        root_label = graph.g.nodes[path[0]].get("label", path[0]) if path else "unknown"
        overall_risk = max((graph.g.nodes[n]["risk"] for n in graph.g.nodes), default=0.0)

        all_event_ids = sorted({
            eid for m in technique_matches for eid in m.evidence_event_ids
        })

        return EvidenceBundle(
            host_id=graph.host_id,
            root_process=root_label,
            highest_risk_path=[graph.g.nodes[n].get("label", n) for n in path],
            technique_matches=technique_matches,
            overall_risk_score=overall_risk,
            evidence_event_ids=all_event_ids,
        )


class TemplateNarrator:
    """
    Deterministic, dependency-free narrative generation. Good enough for
    a first-pass analyst summary and useful as a fallback if the LLM
    backend is unavailable — explainability shouldn't have a hard
    dependency on an external API.
    """

    def narrate(self, bundle: EvidenceBundle) -> str:
        if not bundle.technique_matches:
            return (f"No significant attack techniques were identified on "
                     f"{bundle.host_id}. Overall risk score: {bundle.overall_risk_score:.2f}.")

        technique_phrases = []
        for m in bundle.technique_matches:
            technique_phrases.append(
                f"{m.technique.name} ({m.technique.technique_id}, "
                f"confidence {m.confidence:.0%}) — {m.rationale}"
            )

        chain_str = " -> ".join(bundle.highest_risk_path) if bundle.highest_risk_path else "unclear"

        return (
            f"On host {bundle.host_id}, the process chain {chain_str} "
            f"reached an overall risk score of {bundle.overall_risk_score:.2f}. "
            f"The following MITRE ATT&CK techniques were identified, ordered "
            f"by kill-chain phase:\n"
            + "\n".join(f"  - {p}" for p in technique_phrases)
            + f"\nEvidence spans {len(bundle.evidence_event_ids)} correlated events."
        )


class LLMNarrator:
    """
    Production backend. Builds a grounded prompt from EvidenceBundle only
    (never raw events) and calls the configured LLM provider.
    """

    PROMPT_TEMPLATE = """You are a security analyst assistant. Write a concise, \
factual incident summary using ONLY the evidence below. Do not invent \
details not present here.

Host: {host_id}
Overall risk score: {overall_risk_score:.2f}
Process chain: {chain}

Identified techniques:
{techniques}

Write 2-4 sentences suitable for a SOC analyst triaging this alert."""

    def build_prompt(self, bundle: EvidenceBundle) -> str:
        techniques = "\n".join(
            f"- {m.technique.name} ({m.technique.technique_id}), "
            f"confidence {m.confidence:.0%}: {m.rationale}"
            for m in bundle.technique_matches
        )
        return self.PROMPT_TEMPLATE.format(
            host_id=bundle.host_id,
            overall_risk_score=bundle.overall_risk_score,
            chain=" -> ".join(bundle.highest_risk_path),
            techniques=techniques or "none",
        )

    def narrate(self, bundle: EvidenceBundle) -> str:
        prompt = self.build_prompt(bundle)
        # Production call point:
        #   response = anthropic_client.messages.create(
        #       model="claude-sonnet-4-6", max_tokens=300,
        #       messages=[{"role": "user", "content": prompt}])
        #   return response.content[0].text
        raise NotImplementedError(
            "Wire to an LLM provider. Prompt is fully built and grounded — "
            "see build_prompt() output."
        )


class AttackNarrativeGenerator:
    """
    Phase 11 — builds a chronological timeline narrative (distinct from the
    XAI summary above, which is a risk-focused explanation). This produces
    the "story" for the investigation report / dashboard timeline view.
    """

    def generate_timeline(self, events: list[dict]) -> list[dict]:
        timeline = []
        for e in sorted(events, key=lambda e: e["time"]):
            timeline.append({
                "time": e["time"],
                "event_id": e.get("event_id"),
                "summary": self._summarize_event(e),
            })
        return timeline

    def _summarize_event(self, e: dict) -> str:
        comm = e.get("comm", "process")
        pid = e.get("pid")
        if e["syscall"] == "execve":
            return f"{comm} (pid {pid}) executed {e.get('args', {}).get('filename', '?')}"
        if e["syscall"] == "fork":
            return f"{comm} (pid {pid}) spawned child pid {e.get('args', {}).get('target_pid')}"
        if e["syscall"] == "mprotect" and e.get("features", {}).get("rwx_mprotect_flag"):
            return f"{comm} (pid {pid}) flipped a memory region to RWX (possible shellcode staging)"
        if e["syscall"] == "ptrace":
            return f"{comm} (pid {pid}) used ptrace on pid {e.get('args', {}).get('target_pid')} (possible injection)"
        if e["syscall"] in ("open", "read") and "shadow" in str(e.get("args", {}).get("filename", "")):
            return f"{comm} (pid {pid}) accessed credential store {e['args']['filename']}"
        if e["syscall"] == "write":
            return f"{comm} (pid {pid}) wrote {e.get('args', {}).get('bytes', '?')} bytes to {e.get('args', {}).get('filename', '?')}"
        if e["syscall"] == "connect":
            args = e.get("args", {})
            return f"{comm} (pid {pid}) connected to {args.get('daddr')}:{args.get('dport')}"
        return f"{comm} (pid {pid}) called {e['syscall']}"

    def generate_summary(self, timeline: list[dict]) -> str:
        if not timeline:
            return "No events recorded."
        lines = [f"  {t['time']}  {t['summary']}" for t in timeline]
        return "Attack timeline:\n" + "\n".join(lines)
