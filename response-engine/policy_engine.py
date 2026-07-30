"""
AIVA-KS Response Engine (Phase 15).

Policy-driven, human-in-the-loop-by-default containment. This module is
pure decision logic — it decides WHAT should happen and produces an
auditable ResponseAction record; the actual execution (killing a process,
applying an iptables rule, etc.) is a separate, deliberately-isolated
executor so the decision logic can be fully unit-tested without ever
touching a real system.

Design principle from the architecture doc: default to detect-and-
recommend. Auto-execution is opt-in per policy and every action, whether
auto or analyst-approved, is logged before execution is attempted.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ActionType(str, Enum):
    ISOLATE_PROCESS = "isolate_process"
    ISOLATE_NETWORK = "isolate_network"
    QUARANTINE_FILE = "quarantine_file"
    MEMORY_SNAPSHOT = "memory_snapshot"
    ALERT_ONLY = "alert_only"


class ResponseMode(str, Enum):
    RECOMMEND = "recommend"     # never auto-executes, always needs analyst approval
    AUTO = "auto"                # executes automatically if policy conditions are met


@dataclass
class Policy:
    """
    A policy maps a MITRE technique + minimum confidence + minimum risk
    to a recommended action and execution mode. Irreversible actions
    (isolate_network, quarantine_file) default to RECOMMEND-only;
    reversible/low-impact ones (memory_snapshot, alert_only) can be AUTO.
    """
    name: str
    technique_ids: set[str]
    min_confidence: float
    min_risk: float
    action: ActionType
    mode: ResponseMode


# Sensible defaults — never auto-contain destructively. Snapshots and
# alerts can fire automatically since they carry no risk of disrupting
# legitimate work; isolation/quarantine always route to an analyst.
DEFAULT_POLICIES: list[Policy] = [
    Policy("credential-theft-snapshot", {"T1003"}, 0.6, 0.3,
           ActionType.MEMORY_SNAPSHOT, ResponseMode.AUTO),
    Policy("injection-isolate-recommend", {"T1055"}, 0.7, 0.5,
           ActionType.ISOLATE_PROCESS, ResponseMode.RECOMMEND),
    Policy("exfil-network-isolate-recommend", {"T1041"}, 0.6, 0.5,
           ActionType.ISOLATE_NETWORK, ResponseMode.RECOMMEND),
    Policy("ransomware-quarantine-recommend", {"T1486"}, 0.5, 0.4,
           ActionType.QUARANTINE_FILE, ResponseMode.RECOMMEND),
    Policy("catch-all-alert", set(), 0.0, 0.2,
           ActionType.ALERT_ONLY, ResponseMode.AUTO),
]


@dataclass
class ResponseAction:
    response_id: str
    action_type: ActionType
    target: dict
    triggered_by: str
    mode: ResponseMode
    status: str = "pending"     # pending|awaiting_approval|executed|rejected
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_name: str = ""


class PolicyEngine:
    def __init__(self, policies: list[Policy] | None = None):
        self.policies = policies or DEFAULT_POLICIES

    def evaluate(self, technique_matches, overall_risk: float, target: dict) -> list[ResponseAction]:
        """
        technique_matches: list[TechniqueMatch] from ai.mitre_mapping
        Returns one ResponseAction per matching policy — a single incident
        can trigger multiple simultaneous recommendations (e.g. isolate
        + snapshot), which is intentional; the analyst/executor decides
        ordering.
        """
        actions = []
        matched_technique_ids = {m.technique.technique_id: m.confidence for m in technique_matches}

        for policy in self.policies:
            if policy.technique_ids and not (policy.technique_ids & matched_technique_ids.keys()):
                continue
            if policy.technique_ids:
                confidence = max(matched_technique_ids[t] for t in policy.technique_ids
                                  if t in matched_technique_ids)
            else:
                confidence = 1.0  # catch-all doesn't gate on technique confidence

            if confidence < policy.min_confidence or overall_risk < policy.min_risk:
                continue

            status = "pending" if policy.mode == ResponseMode.AUTO else "awaiting_approval"
            actions.append(ResponseAction(
                response_id=str(uuid.uuid4()),
                action_type=policy.action,
                target=target,
                triggered_by=f"policy:{policy.name}",
                mode=policy.mode,
                status=status,
                policy_name=policy.name,
            ))
        return actions


class ResponseExecutor:
    """
    Deliberately separate from PolicyEngine so decision logic (tested
    exhaustively, no side effects) never shares a code path with
    system-mutating logic (isolated, harder to unit test, needs real
    infra). In production this would shell out to cgroup/netns/iptables
    tooling or an EDR agent's containment API — never implemented here.
    """

    def execute(self, action: ResponseAction) -> ResponseAction:
        if action.mode == ResponseMode.RECOMMEND:
            raise RuntimeError(
                f"{action.action_type} requires analyst approval before execution "
                f"(policy={action.policy_name})"
            )
        # AUTO-mode, low-impact actions only reach here by policy design
        # (memory_snapshot, alert_only). Real execution wired per-action:
        #   if action.action_type == ActionType.MEMORY_SNAPSHOT: ...
        #   if action.action_type == ActionType.ALERT_ONLY: notify_soc(...)
        action.status = "executed"
        return action

    def approve_and_execute(self, action: ResponseAction, approved_by: str) -> ResponseAction:
        if action.status != "awaiting_approval":
            raise RuntimeError(f"action {action.response_id} is not awaiting approval")
        action.status = "executed"
        action.triggered_by += f" | approved_by:{approved_by}"
        return action
