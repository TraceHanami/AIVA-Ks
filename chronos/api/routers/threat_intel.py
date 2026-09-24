"""CHRONOS API — Threat Intelligence Fusion Router (Module 11)."""
from __future__ import annotations

from fastapi import APIRouter
from chronos.api.state import threat_intel

router = APIRouter(tags=["Threat Intelligence"])


@router.get("/threat_intel/feed")
async def get_threat_intel_feed():
    return {
        "ioc_count": len(threat_intel.feed),
        "indicators": [
            {
                "indicator": i.indicator,
                "indicator_type": i.indicator_type,
                "threat_actor": i.threat_actor,
                "campaign": i.campaign,
                "severity": i.severity,
                "confidence": i.confidence,
                "description": i.description,
                "tags": i.tags,
            }
            for i in threat_intel.feed.values()
        ],
    }


@router.get("/threat_intel/lookup")
async def lookup_threat_indicator(query: str):
    hit = threat_intel.lookup(query)
    if not hit:
        return {"hit": False, "query": query}
    return {
        "hit": True,
        "indicator": {
            "indicator": hit.indicator,
            "indicator_type": hit.indicator_type,
            "threat_actor": hit.threat_actor,
            "campaign": hit.campaign,
            "severity": hit.severity,
            "confidence": hit.confidence,
            "description": hit.description,
            "tags": hit.tags,
        },
    }
