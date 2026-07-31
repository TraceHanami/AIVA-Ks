"""
AIVA-KS — End-to-End Security Intelligence Pipeline Demo.

Ingests synthetic Linux kernel syscall events, constructs a behavioral attack graph,
performs graph risk propagation, maps evidence to MITRE ATT&CK techniques,
generates an evidence-grounded XAI narrative and chronological timeline,
computes system threat heatmaps, and evaluates safety-governed containment policies.

Usage:
    python3 demo_full_pipeline.py
"""

from __future__ import annotations

import json
import sys

# Ensure response-engine is in import path
sys.path.insert(0, "response-engine")

from ai.explainability.explainer import AttackNarrativeGenerator, EvidenceExtractor, TemplateNarrator
from ai.graph_engine.graph_builder import BehavioralGraph
from ai.mitre_mapping.mapping_engine import MitreMapper
from ai.threat_heatmap.heatmap_engine import ThreatHeatmapEngine
from policy_engine import PolicyEngine
from tests.test_pipeline import ATTACK_EVENTS, BENIGN_EVENTS, HOST


def run_pipeline_demo() -> None:
    print("=" * 80)
    print("           AIVA-KS — INTELLIGENT KERNEL SECURITY PIPELINE DEMO")
    print("=" * 80)

    # 1. Ingest Telemetry into Behavioral Graph
    print("\n[1/5] Ingesting Syscall Telemetry & Propagating Risk...")
    graph = BehavioralGraph(HOST)
    for event in ATTACK_EVENTS + BENIGN_EVENTS:
        graph.ingest_event(event)
    graph.propagate_risk()
    print(f"      ✔ Ingested {len(ATTACK_EVENTS + BENIGN_EVENTS)} events across host '{HOST}'")
    print(f"      ✔ Graph topology: {len(graph.g.nodes)} nodes, {len(graph.g.edges)} edges")

    # 2. MITRE ATT&CK Mapping
    print("\n[2/5] Mapping Behavioral Evidence to MITRE ATT&CK Techniques...")
    mapper = MitreMapper()
    matches = mapper.map_events(ATTACK_EVENTS, graph)
    print(f"      ✔ Detected {len(matches)} technique matches across kill-chain phases:")
    for match in matches:
        print(f"        • [{match.technique.technique_id}] {match.technique.name:<32} (Phase: {match.technique.tactic}, Confidence: {match.confidence * 100:.0f}%)")

    # 3. Explainability Engine & Narrative
    print("\n" + "-" * 80)
    print("                       EXPLAINABILITY NARRATIVE (XAI)")
    print("-" * 80)
    bundle = EvidenceExtractor().extract(graph, matches)
    narrative = TemplateNarrator().narrate(bundle)
    print(narrative)

    # 4. Attack Timeline
    print("\n" + "-" * 80)
    print("                          CHRONOLOGICAL TIMELINE")
    print("-" * 80)
    timeline = AttackNarrativeGenerator().generate_timeline(ATTACK_EVENTS)
    print(AttackNarrativeGenerator().generate_summary(timeline))

    # 5. Threat Heatmap
    print("\n" + "-" * 80)
    print("                           THREAT HEATMAP MATRIX")
    print("-" * 80)
    scores = ThreatHeatmapEngine().compute(graph)
    print(json.dumps(ThreatHeatmapEngine().to_dashboard_json(scores), indent=2))

    # 6. Policy-Driven Response Engine
    print("\n" + "-" * 80)
    print("                     RESPONSE ENGINE RECOMMENDATIONS")
    print("-" * 80)
    overall_risk = max((d.get("risk", 0.0) for _, d in graph.g.nodes(data=True)), default=0.0)
    target = {"pid": 4260, "host_id": HOST}
    actions = PolicyEngine().evaluate(matches, overall_risk, target=target)

    for action in actions:
        mode_str = f"[{action.mode.value}]".ljust(12)
        print(f"  {mode_str} Action: {action.action_type.value:<18} Status: {action.status:<20} Policy: {action.policy_name}")

    print("\n" + "=" * 80)
    print("           ✔ PIPELINE EXECUTION COMPLETED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    run_pipeline_demo()
