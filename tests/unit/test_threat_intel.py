"""Unit tests for CHRONOS Threat Intelligence Fusion Engine."""
import pytest
from chronos.intelligence.threat_intel import ThreatIntelEngine


def test_threat_intel_lookup():
    engine = ThreatIntelEngine()
    hit = engine.lookup("185.220.101.5")
    assert hit is not None
    assert hit.threat_actor == "APT29 (Cozy Bear)"
    assert hit.severity == "CRITICAL"


def test_threat_intel_enrichment():
    engine = ThreatIntelEngine()
    event = {
        "event_type": "connect",
        "syscall": "connect",
        "pid": 4260,
        "comm": "powershell",
        "target_ip": "198.51.100.22",
        "target_port": 8443,
        "anomaly_score": 0.1,
    }
    enriched = engine.enrich_event(event)
    assert "threat_intel" in enriched
    assert enriched["threat_intel"]["threat_actor"] == "Lazarus Group"
    assert enriched["anomaly_score"] >= 0.90
