"""
End-to-end pipeline demo: events -> graph -> MITRE mapping -> narrative
-> timeline -> heatmap -> response policy. Run from the repo root:

    python3 demo_full_pipeline.py
"""
import json
import sys

sys.path.insert(0, "response-engine")

from ai.graph_engine.graph_builder import BehavioralGraph
from ai.mitre_mapping.mapping_engine import MitreMapper
from ai.explainability.explainer import EvidenceExtractor, TemplateNarrator, AttackNarrativeGenerator
from ai.threat_heatmap.heatmap_engine import ThreatHeatmapEngine
from policy_engine import PolicyEngine
from tests.test_pipeline import ATTACK_EVENTS, BENIGN_EVENTS, HOST

graph = BehavioralGraph(HOST)
for e in ATTACK_EVENTS + BENIGN_EVENTS:
    graph.ingest_event(e)
graph.propagate_risk()

matches = MitreMapper().map_events(ATTACK_EVENTS, graph)
bundle = EvidenceExtractor().extract(graph, matches)
narrative = TemplateNarrator().narrate(bundle)

print("=== EXPLAINABILITY NARRATIVE ===")
print(narrative)

print("\n=== ATTACK TIMELINE ===")
timeline = AttackNarrativeGenerator().generate_timeline(ATTACK_EVENTS)
print(AttackNarrativeGenerator().generate_summary(timeline))

print("\n=== THREAT HEATMAP ===")
scores = ThreatHeatmapEngine().compute(graph)
print(json.dumps(ThreatHeatmapEngine().to_dashboard_json(scores), indent=2))

print("\n=== RESPONSE ENGINE RECOMMENDATIONS ===")
overall_risk = max(d["risk"] for _, d in graph.g.nodes(data=True))
actions = PolicyEngine().evaluate(matches, overall_risk, target={"pid": 4260, "host_id": HOST})
for a in actions:
    print(f"  [{a.mode.value:10s}] {a.action_type.value:20s} status={a.status:18s} policy={a.policy_name}")
