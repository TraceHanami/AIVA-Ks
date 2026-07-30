"""
AIVA-KS integration tests (Phase 19, first slice).

These tests exercise the real, non-stubbed pipeline:
    synthetic events -> BehavioralGraph -> risk propagation
        -> MitreMapper -> EvidenceExtractor -> TemplateNarrator
        -> ThreatHeatmapEngine
        -> PolicyEngine

No mocks for the logic under test — only external I/O (Kafka, Postgres,
LLM API) is out of scope here since this environment has none of that
wired up live. That boundary is deliberate: everything on this side of
it is pure Python and fully testable without infrastructure.

Run: pytest tests/test_pipeline.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "response-engine"))

import pytest

from ai.graph_engine.graph_builder import BehavioralGraph
from ai.mitre_mapping.mapping_engine import MitreMapper
from ai.explainability.explainer import EvidenceExtractor, TemplateNarrator, AttackNarrativeGenerator
from ai.threat_heatmap.heatmap_engine import ThreatHeatmapEngine
from policy_engine import PolicyEngine, ActionType, ResponseMode

HOST = "test-host"

ATTACK_EVENTS = [
    {"host_id": HOST, "pid": 4210, "ppid": 1500, "comm": "invoice.exe",
     "time": "2026-07-02T10:00:00Z", "syscall": "execve",
     "args": {"filename": "/tmp/invoice.exe"}, "event_id": 1},
    {"host_id": HOST, "pid": 4210, "ppid": 1500, "comm": "invoice.exe",
     "time": "2026-07-02T10:00:02Z", "syscall": "fork",
     "args": {"target_pid": 4260}, "event_id": 2},
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "powershell",
     "time": "2026-07-02T10:00:03Z", "syscall": "mprotect",
     "args": {"addr": 140234, "length": 4096, "prot_flags": 7},
     "features": {"rwx_mprotect_flag": True}, "event_id": 3},
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "powershell",
     "time": "2026-07-02T10:00:05Z", "syscall": "ptrace",
     "args": {"ptrace_request": 6, "target_pid": 890}, "event_id": 4},
    {"host_id": HOST, "pid": 890, "ppid": 1, "comm": "target_proc",
     "time": "2026-07-02T10:00:07Z", "syscall": "open",
     "args": {"filename": "/etc/shadow"}, "event_id": 5},
    {"host_id": HOST, "pid": 890, "ppid": 1, "comm": "target_proc",
     "time": "2026-07-02T10:00:08Z", "syscall": "write",
     "args": {"filename": "/tmp/.cache_dump", "bytes": 20480}, "event_id": 6},
    {"host_id": HOST, "pid": 4260, "ppid": 4210, "comm": "powershell",
     "time": "2026-07-02T10:00:10Z", "syscall": "connect",
     "args": {"daddr": "203.0.113.55", "dport": 443}, "event_id": 7},
]

BENIGN_EVENTS = [
    {"host_id": HOST, "pid": 5000, "ppid": 1, "comm": "cron",
     "time": "2026-07-02T10:00:11Z", "syscall": "execve",
     "args": {"filename": "/usr/sbin/cron"}, "event_id": 8},
]


@pytest.fixture
def attack_graph():
    graph = BehavioralGraph(HOST)
    for e in ATTACK_EVENTS + BENIGN_EVENTS:
        graph.ingest_event(e)
    graph.propagate_risk()
    return graph


def test_graph_engine_scores_injection_chain_highest(attack_graph):
    """The injected process/its descendants should outrank the benign cron process."""
    risks = {n: d["risk"] for n, d in attack_graph.g.nodes(data=True)}
    powershell_node = "Process:test-host:4260"
    cron_node = "Process:test-host:5000"
    assert risks[powershell_node] > risks[cron_node]
    assert risks[powershell_node] >= 0.7   # injection edge weight dominates


def test_mitre_mapper_identifies_injection_and_credential_access(attack_graph):
    mapper = MitreMapper()
    matches = mapper.map_events(ATTACK_EVENTS, attack_graph)
    technique_ids = {m.technique.technique_id for m in matches}
    assert "T1055" in technique_ids   # process injection
    assert "T1003" in technique_ids   # credential dumping

    injection_match = next(m for m in matches if m.technique.technique_id == "T1055")
    assert injection_match.confidence >= 0.8   # RWX + ptrace combo should score high
    assert 3 in injection_match.evidence_event_ids  # the mprotect event
    assert 4 in injection_match.evidence_event_ids  # the ptrace event


def test_mitre_mapper_ignores_benign_events():
    graph = BehavioralGraph(HOST)
    for e in BENIGN_EVENTS:
        graph.ingest_event(e)
    graph.propagate_risk()
    matches = MitreMapper().map_events(BENIGN_EVENTS, graph)
    assert matches == []


def test_explainability_narrative_cites_real_evidence(attack_graph):
    matches = MitreMapper().map_events(ATTACK_EVENTS, attack_graph)
    bundle = EvidenceExtractor().extract(attack_graph, matches)
    narrative = TemplateNarrator().narrate(bundle)

    assert "T1055" in narrative
    assert "T1003" in narrative
    assert bundle.evidence_event_ids  # not empty — every claim traces to an event


def test_narrative_generator_produces_chronological_timeline():
    gen = AttackNarrativeGenerator()
    timeline = gen.generate_timeline(ATTACK_EVENTS)
    assert len(timeline) == len(ATTACK_EVENTS)
    times = [t["time"] for t in timeline]
    assert times == sorted(times)  # chronological order preserved
    assert "shellcode" in timeline[2]["summary"].lower()  # the mprotect event


def test_heatmap_flags_memory_and_process_areas(attack_graph):
    scores = ThreatHeatmapEngine().compute(attack_graph)
    assert scores["memory"].score > 0.3     # RWX region present
    assert scores["process"].score >= 0.6   # peak-weighted aggregation: 0.7*0.8 + 0.3*avg ≈ 0.67
    assert scores["process"].peak_node == "Process:test-host:4260"


def test_heatmap_area_with_no_nodes_scores_zero():
    empty_graph = BehavioralGraph("empty-host")
    scores = ThreatHeatmapEngine().compute(empty_graph)
    for area_score in scores.values():
        assert area_score.score == 0.0
        assert area_score.node_count == 0


def test_response_policy_recommends_isolation_for_high_confidence_injection(attack_graph):
    matches = MitreMapper().map_events(ATTACK_EVENTS, attack_graph)
    overall_risk = max(d["risk"] for _, d in attack_graph.g.nodes(data=True))
    actions = PolicyEngine().evaluate(matches, overall_risk, target={"pid": 4260})

    isolate_actions = [a for a in actions if a.action_type == ActionType.ISOLATE_PROCESS]
    assert len(isolate_actions) == 1
    assert isolate_actions[0].mode == ResponseMode.RECOMMEND
    assert isolate_actions[0].status == "awaiting_approval"


def test_response_policy_never_auto_executes_destructive_actions(attack_graph):
    matches = MitreMapper().map_events(ATTACK_EVENTS, attack_graph)
    overall_risk = max(d["risk"] for _, d in attack_graph.g.nodes(data=True))
    actions = PolicyEngine().evaluate(matches, overall_risk, target={"pid": 4260})

    destructive = {ActionType.ISOLATE_PROCESS, ActionType.ISOLATE_NETWORK, ActionType.QUARANTINE_FILE}
    for a in actions:
        if a.action_type in destructive:
            assert a.mode == ResponseMode.RECOMMEND, (
                f"{a.action_type} must never be AUTO — safety invariant violated"
            )


def test_response_executor_rejects_unapproved_destructive_action():
    from policy_engine import ResponseExecutor, ResponseAction
    action = ResponseAction(
        response_id="test-1", action_type=ActionType.ISOLATE_PROCESS,
        target={"pid": 1}, triggered_by="policy:test", mode=ResponseMode.RECOMMEND,
        status="awaiting_approval",
    )
    with pytest.raises(RuntimeError):
        ResponseExecutor().execute(action)  # must go through approve_and_execute instead


def test_response_executor_allows_approved_action():
    from policy_engine import ResponseExecutor, ResponseAction
    action = ResponseAction(
        response_id="test-2", action_type=ActionType.ISOLATE_PROCESS,
        target={"pid": 1}, triggered_by="policy:test", mode=ResponseMode.RECOMMEND,
        status="awaiting_approval",
    )
    executed = ResponseExecutor().approve_and_execute(action, approved_by="analyst_jdoe")
    assert executed.status == "executed"
    assert "approved_by:analyst_jdoe" in executed.triggered_by
