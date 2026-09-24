"""CHRONOS API — Dashboard & Telemetry Ingest Router."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel

from chronos.api.state import manager
from chronos.research.explainability.evidence import EvidenceExtractor
from chronos.research.explainability.narrator import AttackNarrativeGenerator, TemplateNarrator
from chronos.research.threat_heatmap import ThreatHeatmapEngine

router = APIRouter(tags=["Dashboard"])


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


@router.get("/health")
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


@router.post("/reset")
async def reset_demo(host: Optional[str] = "test"):
    st = manager.get_state(host)
    st.reset_to_demo()
    return {"status": "reset_complete", "events_count": len(st.events)}


@router.get("/dashboard/summary")
async def get_dashboard_summary(host: Optional[str] = "live"):
    st = manager.get_state(host)
    bundle = EvidenceExtractor().extract(st.graph, st.mitre_matches)
    narrative = TemplateNarrator().narrate(bundle) if st.events else "Listening for active kernel syscalls and process activity on host..."
    timeline = AttackNarrativeGenerator().generate_timeline(st.events)
    timeline_summary = AttackNarrativeGenerator().generate_summary(timeline)
    heatmap_json = ThreatHeatmapEngine().to_dashboard_json(st.threat_scores)

    nodes = [
        {
            "id": str(node_id),
            "type": data.get("type", "unknown"),
            "label": data.get("label", str(node_id)),
            "risk": round(float(data.get("risk", 0.0)), 3),
            "metadata": {k: v for k, v in data.items() if k not in ["type", "label", "risk"]},
        }
        for node_id, data in st.graph.g.nodes(data=True)
    ]

    edges = [
        {
            "id": f"{u}->{v}:{k}",
            "source": str(u),
            "target": str(v),
            "relation": data.get("relation", "linked"),
            "weight": round(float(data.get("weight", 1.0)), 2),
        }
        for u, v, k, data in st.graph.g.edges(keys=True, data=True)
    ]

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
        "graph": {"nodes": nodes, "edges": edges},
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


@router.post("/events/ingest")
async def ingest_event(event: EventIngest, host: Optional[str] = "live"):
    event_dict = event.model_dump(exclude_none=True)
    if "timestamp" not in event_dict or not event_dict["timestamp"]:
        event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    st = manager.get_state(host)
    st.add_event(event_dict)
    return {"status": "ingested", "host_mode": host, "event": event_dict}
