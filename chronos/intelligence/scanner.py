"""
CHRONOS Intelligence Package — Signature & File Scanning Engine.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass


@dataclass
class ScanResult:
    target_path: str
    is_threat: bool
    threat_name: str | None = None
    threat_type: str | None = None
    severity: str = "CLEAN"
    confidence: float = 0.0
    sha256: str = ""
    description: str = "Clean file"


MALICIOUS_PATTERNS = [
    (re.compile(r"bash\s+-i\s+>&?\s*/dev/tcp/"), "ReverseShell.Bash.Generic", "Reverse Shell", "CRITICAL", 0.95),
    (re.compile(r"nc\s+-[eE]\s+/bin/(ba)?sh"), "ReverseShell.Netcat.Exec", "Reverse Shell", "CRITICAL", 0.95),
    (re.compile(r"stratum\+tcp://"), "CryptoMiner.Stratum.Config", "Crypto Miner", "HIGH", 0.85),
    (re.compile(r"eval\(base64_decode\("), "Dropper.Base64.PHP", "Payload Dropper", "HIGH", 0.90),
    (re.compile(r"echo\s+['\"][A-Za-z0-9+/=]+['\"]?\s*\|\s*base64"), "Linux.Dropper.Base64Exec", "Payload Dropper", "CRITICAL", 0.95),
    (re.compile(r"wget\s+.*\|\s*(ba)?sh"), "Linux.Downloader.WgetPipeBash", "Payload Dropper", "CRITICAL", 0.90),
    (re.compile(r"import\s+pty;\s*pty\.spawn\("), "InteractiveShell.Python.Spawn", "Reverse Shell Staging", "MEDIUM", 0.80),
]


class SignatureEngine:
    def scan_file(self, filepath: str) -> ScanResult:
        if not os.path.isfile(filepath):
            return ScanResult(target_path=filepath, is_threat=False, description="File not found")

        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                content_bytes = f.read()
                hasher.update(content_bytes)
            sha256_hash = hasher.hexdigest()

            text_content = content_bytes.decode("utf-8", errors="ignore")
            for pattern, threat_name, threat_type, severity, confidence in MALICIOUS_PATTERNS:
                if pattern.search(text_content):
                    return ScanResult(
                        target_path=filepath,
                        is_threat=True,
                        threat_name=threat_name,
                        threat_type=threat_type,
                        severity=severity,
                        confidence=confidence,
                        sha256=sha256_hash,
                        description=f"Signature match: {threat_name} ({threat_type})",
                    )
            return ScanResult(target_path=filepath, is_threat=False, sha256=sha256_hash)
        except Exception as e:
            return ScanResult(target_path=filepath, is_threat=False, description=f"Read error: {e}")

    def scan_directory(self, dirpath: str, max_files: int = 300) -> list[ScanResult]:
        results = []
        scanned = 0
        for root, _, files in os.walk(dirpath):
            for file in files:
                if scanned >= max_files:
                    break
                full_path = os.path.join(root, file)
                res = self.scan_file(full_path)
                if res.is_threat:
                    results.append(res)
                scanned += 1
        return results
