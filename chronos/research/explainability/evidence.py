"""
CHRONOS Research Module — Grounded Evidence Extractor (Module 7 & 14).

Extracts concrete, cited facts (events, paths, files, techniques) out of the graph
and MITRE matches to construct audit-grounded EvidenceBundles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from chronos.research.mitre_intelligence import TechniqueMatch


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
        overall_risk = max((graph.g.nodes[n].get("risk", 0.0) for n in graph.g.nodes), default=0.0)

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
