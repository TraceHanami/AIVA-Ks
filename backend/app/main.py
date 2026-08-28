import asyncio
from datetime import datetime, timezone
import json
import os
import socket
import sys
import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add paths for AI engine and response engine
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../response-engine")))

from ai.explainability.explainer import AttackNarrativeGenerator, EvidenceExtractor, TemplateNarrator
from ai.graph_engine.graph_builder import BehavioralGraph
from ai.mitre_mapping.mapping_engine import MitreMapper
from ai.threat_heatmap.heatmap_engine import ThreatHeatmapEngine
from policy_engine import PolicyEngine
from tests.test_pipeline import ATTACK_EVENTS, BENIGN_EVENTS, HOST

app = FastAPI(
    title="AIVA-KS API",
    description="AI-Powered Intelligent Kernel Security Visualizer & Response Engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EventIngest(BaseModel):
    event_type: str
    pid: int
    ppid: Optional[int] = 1
    comm: str
    target_pid: Optional[int] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    target_path: Optional[str] = None
    prot_flags: Optional[str] = None
    anomaly_score: Optional[float] = 0.0
    timestamp: Optional[str] = None


class ActionApproveRequest(BaseModel):
    action_id: str
    approver: str = "security_lead"
    approved: bool = True


# In-Memory Security Engine State
class SecurityState:
    def __init__(self, host_id: str = HOST):
        self.host_id = host_id
        self.graph = BehavioralGraph(host_id)
        self.events: list[dict[str, Any]] = []
        self.mitre_matches: list[Any] = []
        self.threat_scores: dict[str, float] = {}
        self.pending_actions: list[dict[str, Any]] = []
        self.audit_log: list[dict[str, Any]] = []
        self.investigation_notes: list[dict[str, Any]] = []
        self.chat_history: list[dict[str, Any]] = [
            {
                "id": str(uuid.uuid4()),
                "role": "assistant",
                "content": "AIVA-KS Copilot initialized. I can explain kernel syscall anomalies, MITRE ATT&CK kill-chain mapping, graph blast radiuses, and policy containment actions.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
        self.reset_to_demo()

    def reset_to_demo(self):
        self.graph = BehavioralGraph(self.host_id)
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
        # Normalize event attributes for graph and MITRE mapping engines
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

        self.events.append(normalized)
        self.graph.ingest_event(normalized)
        self.graph.propagate_risk()
        self.recompute()


class SecurityEngineManager:
    def __init__(self):
        self.live_host_id = socket.gethostname()
        self.test_host_id = "test-host"
        
        # Test attack state (initialized with simulated kill-chain)
        self.test_state = SecurityState(host_id=self.test_host_id)
        self.test_state.reset_to_demo()

        # Live OS state (initialized cleanly, populated by live telemetry)
        self.live_state = SecurityState(host_id=self.live_host_id)
        self.live_state.events = []
        self.live_state.graph = BehavioralGraph(self.live_host_id)

    def get_state(self, host_mode: str = "live") -> SecurityState:
        if host_mode == "test":
            return self.test_state
        return self.live_state


manager = SecurityEngineManager()


@app.get("/api/health")
async def health(host: Optional[str] = "live"):
    st = manager.get_state(host)
    return {
        "status": "ok",
        "current_mode": host,
        "host": st.host_id,
        "live_host": manager.live_host_id,
        "test_host": manager.test_host_id,
        "nodes": len(st.graph.g.nodes),
    }


@app.post("/api/reset")
async def reset_demo(host: Optional[str] = "test"):
    st = manager.get_state(host)
    st.reset_to_demo()
    return {"status": "reset_complete", "events_count": len(st.events)}


@app.get("/api/dashboard/summary")
async def get_dashboard_summary(host: Optional[str] = "live"):
    st = manager.get_state(host)
    bundle = EvidenceExtractor().extract(st.graph, st.mitre_matches)
    narrative = TemplateNarrator().narrate(bundle) if st.events else "Listening for active kernel syscalls and process activity on host..."
    timeline = AttackNarrativeGenerator().generate_timeline(st.events)
    timeline_summary = AttackNarrativeGenerator().generate_summary(timeline)
    heatmap_json = ThreatHeatmapEngine().to_dashboard_json(st.threat_scores)

    nodes = []
    for node_id, data in st.graph.g.nodes(data=True):
        nodes.append({
            "id": str(node_id),
            "type": data.get("type", "unknown"),
            "label": data.get("label", str(node_id)),
            "risk": round(float(data.get("risk", 0.0)), 3),
            "metadata": {k: v for k, v in data.items() if k not in ["type", "label", "risk"]},
        })

    edges = []
    for u, v, k, data in st.graph.g.edges(keys=True, data=True):
        edges.append({
            "id": f"{u}->{v}:{k}",
            "source": str(u),
            "target": str(v),
            "relation": data.get("relation", "linked"),
            "weight": round(float(data.get("weight", 1.0)), 2),
        })

    mitre_list = [
        {
            "technique_id": m.technique.technique_id,
            "name": m.technique.name,
            "tactic": m.technique.tactic,
            "confidence": round(m.confidence * 100, 1),
            "description": m.rationale or f"Kill-chain phase: {m.technique.tactic}",
            "evidence": [f"Event ID {eid}" for eid in getattr(m, "evidence_event_ids", [])] or [m.rationale],
        }
        for m in st.mitre_matches
    ]

    return {
        "host_id": st.host_id,
        "host_mode": host,
        "live_host_id": manager.live_host_id,
        "test_host_id": manager.test_host_id,
        "overall_risk": round(max((n["risk"] for n in nodes), default=0.0), 3),
        "threat_heatmap": heatmap_json,
        "mitre_matches": mitre_list,
        "narrative": narrative,
        "timeline_summary": timeline_summary,
        "timeline_events": [
            {
                "timestamp": e.get("time") or e.get("timestamp", "N/A"),
                "event_type": e.get("syscall") or e.get("event_type", "unknown"),
                "pid": e.get("pid"),
                "comm": e.get("comm"),
                "anomaly_score": e.get("anomaly_score", 0.0),
                "details": {k: v for k, v in e.items() if k not in ["timestamp", "time", "event_type", "syscall", "pid", "comm", "anomaly_score"]},
            }
            for e in sorted(st.events, key=lambda x: str(x.get("time") or x.get("timestamp", "")))
        ],
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        "response_actions": st.pending_actions,
        "audit_log": st.audit_log,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "total_events": len(st.events),
            "mitre_count": len(mitre_list),
            "pending_approvals": len([a for a in st.pending_actions if a["status"] == "pending_approval"]),
        },
    }


@app.post("/api/events/ingest")
async def ingest_event(event: EventIngest, host: Optional[str] = "live"):
    event_dict = event.model_dump(exclude_none=True)
    if "timestamp" not in event_dict or not event_dict["timestamp"]:
        event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    st = manager.get_state(host)
    st.add_event(event_dict)
    return {"status": "ingested", "host_mode": host, "event": event_dict}


@app.post("/api/actions/approve")
async def approve_action(req: ActionApproveRequest, host: Optional[str] = "live"):
    st = manager.get_state(host)
    for action in st.pending_actions:
        if action["action_id"] == req.action_id:
            if req.approved:
                action["status"] = "executed"
                st.audit_log.insert(0, {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": req.approver,
                    "action_id": req.action_id,
                    "action_type": action["action_type"],
                    "target": action["target"],
                    "status": "SUCCESS",
                    "details": f"Human-in-the-loop approved and executed {action['action_type']} on {action['target']}",
                })
            else:
                action["status"] = "rejected"
                st.audit_log.insert(0, {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": req.approver,
                    "action_id": req.action_id,
                    "action_type": action["action_type"],
                    "target": action["target"],
                    "status": "REJECTED",
                    "details": f"Analyst rejected containment action {action['action_type']}",
                })
            return {"status": "updated", "action": action}
    raise HTTPException(status_code=404, detail="Action ID not found")


class CopilotQuestion(BaseModel):
    message: str


@app.post("/api/copilot/chat")
async def copilot_chat(req: CopilotQuestion, host: Optional[str] = "live"):
    st = manager.get_state(host)
    user_msg = {
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": req.message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    st.chat_history.append(user_msg)

    # Dynamic contextual response grounded in live telemetry & graph for the selected host
    q = req.message.lower()
    bundle = EvidenceExtractor().extract(st.graph, st.mitre_matches)

    if "what happened" in q or "summary" in q or "explain" in q or "attack" in q:
        techniques_summary = ", ".join(f"{t.technique.technique_id} ({t.technique.name})" for t in bundle.technique_matches) or "No critical attack techniques confirmed yet."
        chain = " -> ".join(bundle.highest_risk_path) or "Nominal execution tree"
        reply = (
            f"**Environment Assessment for Host `{st.host_id}` ({host.upper()} MODE):**\n\n"
            f"• **Identified Attack Chain:** `{chain}`\n"
            f"• **Overall Propagated Risk:** {bundle.overall_risk_score * 100:.1f}%\n"
            f"• **MITRE ATT&CK Techniques:** {techniques_summary}\n"
            f"• **Active Graph Entities:** {len(st.graph.g.nodes)} nodes, {len(st.graph.g.edges)} causal relationships\n"
            f"• **Pending Mitigations:** {len([a for a in st.pending_actions if a['status'] == 'pending_approval'])} containment action(s) awaiting approval."
        )

    elif "isolate" in q or "contain" in q or "kill" in q or "response" in q or "policy" in q:
        reply = (
            f"**Policy & Response Status for Host `{st.host_id}`:**\n\n"
            f"• There are currently **{len(st.pending_actions)}** policy actions evaluated by the Response Engine.\n"
            f"• Safety Invariant: In accordance with zero-disruption policy safeguards, destructive actions require explicit human-in-the-loop analyst authorization before enforcement."
        )
    elif "mitre" in q or "technique" in q:
        techniques_str = "\n".join([f"- **[{m.technique.technique_id}] {m.technique.name}**: {m.technique.description} (Confidence: {m.confidence*100:.0f}%)" for m in st.mitre_matches]) if st.mitre_matches else "No anomalous MITRE techniques triggered on this host."
        reply = f"**Identified MITRE ATT&CK Mapping for `{st.host_id}`:**\n\n{techniques_str}"
    else:
        reply = (
            f"Based on real-time graph behavioral analysis for host `{st.host_id}` ({host} mode):\n\n"
            f"- Graph topology: {len(st.graph.g.nodes)} nodes, {len(st.graph.g.edges)} edges\n"
            f"- Peak risk propagation score: {max((d.get('risk', 0.0) for _, d in st.graph.g.nodes(data=True)), default=0.0):.2f}\n"
            f"- Telemetry events recorded: {len(st.events)}. How would you like to investigate further?"
        )

    bot_msg = {
        "id": str(uuid.uuid4()),
        "role": "assistant",
        "content": reply,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    st.chat_history.append(bot_msg)

    return {"reply": bot_msg, "history": st.chat_history}


@app.get("/api/copilot/history")
async def copilot_history(host: Optional[str] = "live"):
    st = manager.get_state(host)
    return {"history": st.chat_history}

