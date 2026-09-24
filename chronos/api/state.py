"""
CHRONOS API — System State & Engine Manager.

Manages in-memory security graph states for live host and test attack hosts.
"""
from __future__ import annotations

import socket
import uuid
from datetime import datetime, timezone
from typing import Any

from chronos.intelligence.threat_intel import ThreatIntelEngine
from chronos.investigation.case_workspace import CaseService
from chronos.investigation.replay_engine import ReplayService
from chronos.research.causality_engine import BehavioralGraph
from chronos.research.explainability.evidence import EvidenceExtractor
from chronos.research.explainability.narrator import AttackNarrativeGenerator, TemplateNarrator
from chronos.research.mitre_intelligence import MitreMapper
from chronos.research.threat_heatmap import ThreatHeatmapEngine
from chronos.research.ueba_engine import UebaEngine
from chronos.response.policy_engine import PolicyEngine

from chronos.research.demo_data import ATTACK_EVENTS, BENIGN_EVENTS, HOST

threat_intel = ThreatIntelEngine()
ueba = UebaEngine()
case_service = CaseService()
replay_service = ReplayService()


class SecurityState:
    def __init__(self, host_id: str = HOST, asset_type: str = "WORKSTATION"):
        self.host_id = host_id
        self.asset_type = asset_type
        self.graph = BehavioralGraph(host_id, asset_type=asset_type)
        self.events: list[dict[str, Any]] = []
        self.mitre_matches: list[Any] = []
        self.threat_scores: dict[str, float] = {}
        self.pending_actions: list[dict[str, Any]] = []
        self.audit_log: list[dict[str, Any]] = []
        self.chat_history: list[dict[str, Any]] = [
            {
                "id": str(uuid.uuid4()),
                "role": "assistant",
                "content": "CHRONOS Copilot initialized. I can explain kernel syscall anomalies, MITRE ATT&CK kill-chain mapping, graph blast radiuses, and policy containment actions.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
        self.reset_to_demo()

    def reset_to_demo(self):
        self.graph = BehavioralGraph(self.host_id, asset_type=self.asset_type)
        self.events = [dict(e) for e in (ATTACK_EVENTS + BENIGN_EVENTS)]
        for event in self.events:
            self.graph.ingest_event(event)
        self.graph.propagate_risk()
        self.recompute()

    def recompute(self):
        mapper = MitreMapper()
        self.mitre_matches = mapper.map_events(self.events, self.graph)
        self.threat_scores = ThreatHeatmapEngine().compute(self.graph)

        overall_risk = max((d.get("risk", 0.0) for _, d in self.graph.g.nodes(data=True)), default=0.0)
        target = {"pid": 4260, "host_id": self.host_id}
        evaluated_actions = PolicyEngine().evaluate(self.mitre_matches, overall_risk, target=target)

        self.pending_actions = [
            {
                "action_id": f"act-{i+1:03d}",
                "policy_name": act.policy_name,
                "action_type": act.action_type.value,
                "target": act.target,
                "mode": act.mode.value,
                "requires_approval": (act.mode.value == "recommend"),
                "status": "pending_approval" if act.status == "awaiting_approval" else act.status,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            for i, act in enumerate(evaluated_actions)
        ]

    def add_event(self, event: dict[str, Any]):
        normalized = dict(event)
        if "syscall" not in normalized:
            normalized["syscall"] = normalized.get("event_type", "execve").replace("sys_enter_", "")
        if "time" not in normalized:
            normalized["time"] = normalized.get("timestamp", datetime.now(timezone.utc).isoformat())
        if "host_id" not in normalized:
            normalized["host_id"] = self.host_id
        if "event_id" not in normalized:
            normalized["event_id"] = len(self.events) + 1

        args = normalized.setdefault("args", {})
        if "target_pid" in normalized and normalized["target_pid"]:
            args["target_pid"] = normalized["target_pid"]
        if "target_ip" in normalized and normalized["target_ip"]:
            args["daddr"] = normalized["target_ip"]
        if "target_port" in normalized and normalized["target_port"]:
            args["dport"] = normalized["target_port"]
        if "target_path" in normalized and normalized["target_path"]:
            args["filename"] = normalized["target_path"]
        if "prot_flags" in normalized and normalized["prot_flags"]:
            args["prot_flags"] = normalized["prot_flags"]
            if "rwx" in str(normalized["prot_flags"]).lower() or str(normalized["prot_flags"]) == "7":
                normalized.setdefault("features", {})["rwx_mprotect_flag"] = True

        normalized = threat_intel.enrich_event(normalized)
        self.events.append(normalized)
        self.graph.ingest_event(normalized)
        self.graph.propagate_risk()
        self.recompute()


class SecurityEngineManager:
    def __init__(self):
        self.live_host_id = socket.gethostname()
        self.test_host_id = "test-host"

        self.test_state = SecurityState(host_id=self.test_host_id, asset_type="DOMAIN_CONTROLLER")
        self.test_state.reset_to_demo()

        self.live_state = SecurityState(host_id=self.live_host_id, asset_type="WORKSTATION")
        self.live_state.events = []
        self.live_state.graph = BehavioralGraph(self.live_host_id)

    def get_state(self, host_mode: str = "live") -> SecurityState:
        if host_mode == "test":
            return self.test_state
        return self.live_state


manager = SecurityEngineManager()
