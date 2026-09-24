"""
Integration tests for Case Workspace & Digital Twin Replay engines.
"""
import pytest

from chronos.investigation.case_workspace import CaseService
from chronos.investigation.replay_engine import ReplayService
from chronos.research.demo_data import ATTACK_EVENTS, HOST


def test_case_service_lifecycle():
    service = CaseService()
    
    # List default cases
    cases = service.list_cases()
    assert len(cases) >= 1

    # Create case
    case = service.create_case(
        title="Integration Case Test",
        host_id=HOST,
        severity="HIGH",
        assigned_to="analyst_alice",
        evidence_event_ids=[1, 2, 3],
        mitre_technique_ids=["T1055"],
    )
    assert case.case_id.startswith("CASE-")
    assert case.status == "OPEN"

    # Add note
    note = service.add_note(case.case_id, author="analyst_alice", content="Containment initiated.")
    assert note.content == "Containment initiated."

    # Export binder
    binder = service.export_case_binder(case.case_id)
    assert binder["chronos_version"] == "2.0.0"
    assert binder["case"]["title"] == "Integration Case Test"


def test_digital_twin_replay_service():
    service = ReplayService()
    session_id = service.build_digital_twin_replay(HOST, ATTACK_EVENTS)
    assert session_id.startswith("replay-")

    snapshot = service.get_snapshot(session_id, step=1)
    assert snapshot["step"] == 1
    assert "predicted_next_actions" in snapshot
