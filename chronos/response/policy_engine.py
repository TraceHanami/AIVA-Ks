"""
CHRONOS Response Package — Safety Invariant Policy Engine (Module 9).
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
    RECOMMEND = "recommend"
    AUTO = "auto"


@dataclass
class Policy:
    name: str
    technique_ids: set[str]
    min_confidence: float
    min_risk: float
    action: ActionType
    mode: ResponseMode


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
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_name: str = ""


class PolicyEngine:
    def __init__(self, policies: list[Policy] | None = None):
        self.policies = policies or DEFAULT_POLICIES

    def evaluate(self, technique_matches, overall_risk: float, target: dict) -> list[ResponseAction]:
        actions = []
        matched_technique_ids = {m.technique.technique_id: m.confidence for m in technique_matches}

        for policy in self.policies:
            if policy.technique_ids and not (policy.technique_ids & matched_technique_ids.keys()):
                continue
            if policy.technique_ids:
                confidence = max(matched_technique_ids[t] for t in policy.technique_ids
                                  if t in matched_technique_ids)
            else:
                confidence = 1.0

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
