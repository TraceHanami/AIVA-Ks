"""
Integration test for full CHRONOS telemetry processing pipeline.
Exercises:
Telemetry Ingestion -> Behavioral Graph -> MITRE Mapper -> Heatmap -> Explainability -> Policy Engine
"""
import pytest

from chronos.research.causality_engine import BehavioralGraph
from chronos.research.mitre_intelligence import MitreMapper
from chronos.research.threat_heatmap import ThreatHeatmapEngine
from chronos.research.explainability.evidence import EvidenceExtractor
from chronos.research.explainability.narrator import TemplateNarrator, AttackNarrativeGenerator
from chronos.response.policy_engine import PolicyEngine, ActionType, ResponseMode

HOST = "integration-host"

ATTACK_EVENTS = [
    {"host_id": HOST, "pid": 4210, "ppid": 1500, "comm": "dropper.sh",
     "time": "2026-07-02T10:00:00Z", "syscall": "execve",
     "args": {"filename": "/tmp/dropper.sh"}, "event_id": 1},
    {"host_id": HOST, "pid": 4210, "ppid": 1500, "comm": "dropper.sh",
     "time": "2026-07-02T10:00:02Z", "syscall": "fork",
     "args": {"target_pid": 4260}, "event_id": 2},
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "bash",
     "time": "2026-07-02T10:00:03Z", "syscall": "mprotect",
     "args": {"addr": 140234, "length": 4096, "prot_flags": 7},
     "features": {"rwx_mprotect_flag": True}, "event_id": 3},
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "bash",
     "time": "2026-07-02T10:00:05Z", "syscall": "ptrace",
     "args": {"ptrace_request": 6, "target_pid": 890}, "event_id": 4},
    {"host_id": HOST, "pid": 890, "ppid": 1, "comm": "target_proc",
     "time": "2026-07-02T10:00:07Z", "syscall": "open",
     "args": {"filename": "/etc/shadow"}, "event_id": 5},
]


@pytest.fixture
def integrated_graph():
    graph = BehavioralGraph(HOST)
    for event in ATTACK_EVENTS:
        graph.ingest_event(event)
    graph.propagate_risk()
    return graph


def test_end_to_end_investigation_pipeline(integrated_graph):
    # 1. MITRE ATT&CK Mapping
    mapper = MitreMapper()
    matches = mapper.map_events(ATTACK_EVENTS, integrated_graph)
    assert len(matches) > 0
    technique_ids = {m.technique.technique_id for m in matches}
    assert "T1055" in technique_ids

    # 2. Threat Heatmap
    heatmap = ThreatHeatmapEngine().compute(integrated_graph)
    assert heatmap["memory"].score > 0.0
    assert heatmap["process"].score > 0.0

    # 3. Explainability
    bundle = EvidenceExtractor().extract(integrated_graph, matches)
    narrative = TemplateNarrator().narrate(bundle)
    assert "T1055" in narrative

    timeline = AttackNarrativeGenerator().generate_timeline(ATTACK_EVENTS)
    assert len(timeline) == len(ATTACK_EVENTS)

    # 4. Policy Evaluation
    risk = max(d.get("risk", 0.0) for _, d in integrated_graph.g.nodes(data=True))
    actions = PolicyEngine().evaluate(matches, risk, target={"pid": 4260})
    assert len(actions) > 0
    assert any(a.action_type == ActionType.ISOLATE_PROCESS for a in actions)
