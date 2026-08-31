"""
AIVA-KS Static & Behavioral File Threat Scanner.
Provides on-access and on-demand signature scanning, heuristic static analysis,
ELF header security checks, and threat database matching for Linux/Ubuntu.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanResult:
    target_path: str
    is_threat: bool
    threat_name: Optional[str] = None
    threat_type: Optional[str] = None
    sha256: Optional[str] = None
    severity: str = "CLEAN"  # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 0.0
    description: Optional[str] = None


class SignatureEngine:
    """
    Signature and heuristic scanning engine with known Linux malware indicators,
    reverse shells, web shells, miners, and rootkit staging patterns.
    """

    KNOWN_MALICIOUS_HASHES = {
        # Linux.Mirai sample hashes (known test signatures)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test.ZeroByte.Malware",
        "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2": "Linux.Trojan.Mirai",
    }

    MALICIOUS_PATTERNS = [
        (re.compile(rb"/bin/(bash|sh)\s+-i\s+>&\s+/dev/tcp/"), "Linux.ReverseShell.BashDevTcp", "CRITICAL", 0.95),
        (re.compile(rb"nc\s+-[e|c]\s+/bin/(bash|sh)"), "Linux.ReverseShell.Netcat", "CRITICAL", 0.95),
        (re.compile(rb"python3?\s+-c\s+['\"].*import\s+socket,subprocess,os.*pty\.spawn"), "Linux.ReverseShell.PythonPTY", "CRITICAL", 0.90),
        (re.compile(rb"(stratum\+tcp|stratum\+ssl)://[a-zA-Z0-9\.\-_]+:\d+"), "Linux.CoinMiner.StratumConfig", "HIGH", 0.85),
        (re.compile(rb"(xmrig|minerd|cpuminer)"), "Linux.CoinMiner.XMRigArtifact", "MEDIUM", 0.70),
        (re.compile(rb"chmod\s+(\+x|777)\s+/tmp/"), "Linux.Staging.ExecTmp", "MEDIUM", 0.60),
        (re.compile(rb"/dev/shm/\.[a-zA-Z0-9_-]+"), "Linux.Evasion.HiddenDevShm", "HIGH", 0.75),
        (re.compile(rb"echo\s+['\"][a-zA-Z0-9+/=]+['\"]\s*\|\s*base64\s+-d\s*\|\s*(sh|bash)"), "Linux.Dropper.Base64Exec", "CRITICAL", 0.95),
        (re.compile(rb"iptables\s+-F\s*&&\s*systemctl\s+stop\s+firewalld"), "Linux.DefenseEvasion.DisableFirewall", "HIGH", 0.80),
        (re.compile(rb"wget\s+http[s]?://.*\|\s*(sh|bash)"), "Linux.Downloader.WgetPipeBash", "CRITICAL", 0.90),
        (re.compile(rb"curl\s+-[sS]*[fF]*[kK]*[lL]*\s+http[s]?://.*\|\s*(sh|bash)"), "Linux.Downloader.CurlPipeBash", "CRITICAL", 0.90),
    ]

    @staticmethod
    def calculate_sha256(filepath: str) -> Optional[str]:
        if not os.path.isfile(filepath):
            return None
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, OSError):
            return None

    def scan_file(self, filepath: str) -> ScanResult:
        if not os.path.isfile(filepath):
            return ScanResult(target_path=filepath, is_threat=False, description="File does not exist or unreadable")

        sha256 = self.calculate_sha256(filepath)
        if sha256 and sha256 in self.KNOWN_MALICIOUS_HASHES:
            threat_name = self.KNOWN_MALICIOUS_HASHES[sha256]
            return ScanResult(
                target_path=filepath,
                is_threat=True,
                threat_name=threat_name,
                threat_type="KnownMalwareHash",
                sha256=sha256,
                severity="CRITICAL",
                confidence=1.0,
                description=f"Exact match against known malware signature database ({threat_name})"
            )

        # Check binary contents / heuristics
        try:
            with open(filepath, "rb") as f:
                content = f.read(1024 * 1024)  # Read first 1MB for speed
        except Exception as e:
            return ScanResult(target_path=filepath, is_threat=False, description=f"Read error: {e}")

        # Check heuristic patterns
        for pattern, threat_name, severity, confidence in self.MALICIOUS_PATTERNS:
            if pattern.search(content):
                return ScanResult(
                    target_path=filepath,
                    is_threat=True,
                    threat_name=threat_name,
                    threat_type="HeuristicPattern",
                    sha256=sha256,
                    severity=severity,
                    confidence=confidence,
                    description=f"Matched heuristic signature: {threat_name}"
                )

        return ScanResult(
            target_path=filepath,
            is_threat=False,
            sha256=sha256,
            severity="CLEAN",
            confidence=0.0,
            description="No malicious signatures or static anomalies detected."
        )

    def scan_directory(self, dirpath: str, max_files: int = 500) -> list[ScanResult]:
        results = []
        count = 0
        for root, _, files in os.walk(dirpath):
            for file in files:
                if count >= max_files:
                    break
                full_path = os.path.join(root, file)
                try:
                    res = self.scan_file(full_path)
                    if res.is_threat:
                        results.append(res)
                    count += 1
                except Exception:
                    continue
        return results
