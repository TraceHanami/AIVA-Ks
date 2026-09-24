"""Unit tests for CHRONOS UEBA Engine."""
import pytest
from chronos.research.ueba_engine import UebaEngine


def test_privilege_and_credential_anomalies():
    engine = UebaEngine()
    events = [
        {
            "event_type": "execve",
            "syscall": "execve",
            "pid": 5001,
            "ppid": 100,
            "uid": 1000,
            "comm": "sudo",
            "timestamp": "2026-09-15T03:15:00Z",
        },
        {
            "event_type": "open",
            "syscall": "open",
            "pid": 5002,
            "uid": 0,
            "comm": "cat",
            "target_path": "/etc/shadow",
            "timestamp": "2026-09-15T03:16:00Z",
        },
    ]
    anomalies = engine.analyze_events(events)
    assert len(anomalies) >= 2
    types = [a.anomaly_type for a in anomalies]
    assert "privilege_escalation" in types
    assert "credential_store_access" in types
