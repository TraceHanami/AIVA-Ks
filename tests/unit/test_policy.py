"""
Unit tests for Policy Engine and OS Containment Executor (Module 9 & Module 15).
"""
import os
import tempfile
import pytest

from chronos.response.policy_engine import (
    ActionType,
    PolicyEngine,
    ResponseAction,
    ResponseMode,
)
from chronos.response.executor import ResponseExecutor


@pytest.fixture
def executor():
    return ResponseExecutor()


def test_response_policy_evaluates_remedial_actions():
    engine = PolicyEngine()
    target = {"pid": 4260, "path": "/tmp/malware"}
    actions = engine.evaluate(technique_matches=[], overall_risk=0.85, target=target)
    
    assert len(actions) > 0
    action_types = {a.action_type for a in actions}
    assert ActionType.ALERT_ONLY in action_types or ActionType.ISOLATE_PROCESS in action_types


def test_response_policy_safety_invariant():
    """Destructive actions must default to RECOMMEND / awaiting approval."""
    engine = PolicyEngine()
    target = {"pid": 4260}
    actions = engine.evaluate(technique_matches=[], overall_risk=0.95, target=target)

    destructive = {
        ActionType.ISOLATE_PROCESS,
        ActionType.ISOLATE_NETWORK,
        ActionType.QUARANTINE_FILE,
    }
    for action in actions:
        if action.action_type in destructive:
            assert action.mode == ResponseMode.RECOMMEND
            assert action.status == "awaiting_approval"


def test_executor_quarantines_file(executor):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"malicious_payload_binary")
        target_path = f.name

    try:
        action = ResponseAction(
            response_id="act-unit-01",
            action_type=ActionType.QUARANTINE_FILE,
            target={"path": target_path},
            triggered_by="unit_test",
            mode=ResponseMode.RECOMMEND,
            status="awaiting_approval",
        )
        executed = executor.approve_and_execute(action, approved_by="unit_tester")
        assert executed.status == "executed"
        assert not os.path.exists(target_path)
    finally:
        if os.path.exists(target_path):
            os.remove(target_path)


def test_executor_rejects_unapproved_destructive_action(executor):
    action = ResponseAction(
        response_id="act-unit-02",
        action_type=ActionType.ISOLATE_PROCESS,
        target={"pid": 9999},
        triggered_by="unit_test",
        mode=ResponseMode.RECOMMEND,
        status="awaiting_approval",
    )
    with pytest.raises(RuntimeError, match="requires analyst approval"):
        executor.execute(action)
