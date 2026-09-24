"""
CHRONOS Intelligence Package — Threat Intelligence Fusion Engine (Module 11).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatIndicator:
    indicator: str
    indicator_type: str      # ip | sha256 | domain | filepath
    threat_actor: str
    campaign: str
    severity: str             # CRITICAL | HIGH | MEDIUM | LOW
    confidence: float
    description: str
    tags: list[str] = field(default_factory=list)


KNOWN_IOC_FEED: dict[str, ThreatIndicator] = {
    "185.220.101.5": ThreatIndicator(
        indicator="185.220.101.5",
        indicator_type="ip",
        threat_actor="APT29 (Cozy Bear)",
        campaign="Nobelium C2 Infrastructure",
        severity="CRITICAL",
        confidence=0.95,
        description="Known C2 node hosting encrypted HTTPS command & control listeners.",
        tags=["c2", "apt29", "tor-exit-node"],
    ),
    "198.51.100.22": ThreatIndicator(
        indicator="198.51.100.22",
        indicator_type="ip",
        threat_actor="Lazarus Group",
        campaign="Operation Dream Job",
        severity="HIGH",
        confidence=0.90,
        description="Active Cobalt Strike beacon listener port 8443.",
        tags=["cobalt-strike", "lazarus", "exfil-node"],
    ),
    "45.142.214.165": ThreatIndicator(
        indicator="45.142.214.165",
        indicator_type="ip",
        threat_actor="FIN7",
        campaign="Carbanak Payment Scraping",
        severity="HIGH",
        confidence=0.88,
        description="Known bulletproof hosting node used for exfiltration.",
        tags=["fin7", "exfiltration"],
    ),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": ThreatIndicator(
        indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        indicator_type="sha256",
        threat_actor="LockBit 3.0",
        campaign="LockBit Black Ransomware",
        severity="CRITICAL",
        confidence=0.98,
        description="LockBit 3.0 encryptor payload binary.",
        tags=["ransomware", "lockbit"],
    ),
}


class ThreatIntelEngine:
    def __init__(self, custom_feed: dict[str, ThreatIndicator] | None = None):
        self.feed = custom_feed or KNOWN_IOC_FEED

    def lookup(self, key: str) -> ThreatIndicator | None:
        if not key:
            return None
        key_str = str(key).strip().lower()
        for k, indicator in self.feed.items():
            if k.lower() == key_str:
                return indicator
        return None

    def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(event)
        threat_hits = []

        target_ip = event.get("target_ip") or event.get("args", {}).get("daddr")
        if target_ip:
            hit = self.lookup(str(target_ip))
            if hit:
                threat_hits.append(hit)

        sha256 = event.get("sha256") or event.get("args", {}).get("sha256")
        if sha256:
            hit = self.lookup(str(sha256))
            if hit:
                threat_hits.append(hit)

        if threat_hits:
            top_hit = max(threat_hits, key=lambda h: h.confidence)
            enriched["threat_intel"] = {
                "hit": True,
                "threat_actor": top_hit.threat_actor,
                "campaign": top_hit.campaign,
                "severity": top_hit.severity,
                "confidence": top_hit.confidence,
                "description": top_hit.description,
                "tags": top_hit.tags,
            }
            enriched["anomaly_score"] = max(enriched.get("anomaly_score", 0.0), top_hit.confidence)

        return enriched
