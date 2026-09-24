"""CHRONOS API — UEBA Engine Router (Module 17)."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter
from chronos.api.state import manager, ueba

router = APIRouter(tags=["UEBA"])


@router.get("/ueba/anomalies")
async def get_ueba_anomalies(host: Optional[str] = "live"):
    st = manager.get_state(host)
    anomalies = ueba.analyze_events(st.events)
    return {
        "host_id": st.host_id,
        "anomaly_count": len(anomalies),
        "anomalies": [
            {
                "user_id": a.user_id,
                "user_name": a.user_name,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "anomaly_score": a.anomaly_score,
                "evidence": a.evidence,
                "timestamp": a.timestamp,
            }
            for a in anomalies
        ],
    }
