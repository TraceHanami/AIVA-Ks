"""
CHRONOS Intelligence — Boot & Initial State Security Scanner.

Audits Linux/Ubuntu boot parameters, kernel posture, persistence mechanisms,
sensitive file permissions, SUID hazards, and malware signatures at boot time.
"""
from __future__ import annotations

import glob
import json
import os
import re
import stat
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chronos.intelligence.scanner import SignatureEngine

DANGEROUS_CMDLINE_PARAMS = [
    ("init=/bin/sh", "Root shell init bypass parameter detected", "CRITICAL"),
    ("init=/bin/bash", "Root shell init bypass parameter detected", "CRITICAL"),
    ("single", "Single-user recovery mode boot without authentication", "HIGH"),
    ("nokaslr", "Kernel Address Space Layout Randomization (KASLR) disabled", "HIGH"),
    ("nosmap", "Supervisor Mode Access Prevention (SMAP) disabled", "HIGH"),
    ("nosmep", "Supervisor Mode Execution Prevention (SMEP) disabled", "HIGH"),
    ("mitigations=off", "All CPU speculative execution hardware mitigations disabled", "CRITICAL"),
]

GTFOBINS_SUID_HAZARDS = {
    "find", "nmap", "vim", "vi", "nano", "python", "python3", "perl",
    "ruby", "bash", "sh", "zsh", "dash", "awk", "gawk", "sed", "env",
    "tar", "zip", "gzip", "less", "more", "cp", "mv", "systemctl",
}


@dataclass
class BootFinding:
    category: str  # Kernel, Persistence, Permissions, Malware, SUID
    title: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    target_path: str | None = None
    description: str = ""
    remediation: str = ""


@dataclass
class BootScanReport:
    timestamp: str
    host: str
    duration_seconds: float
    overall_status: str  # CLEAN, WARNING, COMPROMISED
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[BootFinding] = field(default_factory=list)
    system_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


class BootSecurityScanner:
    """Automated early-boot and initialization security auditor."""

    def __init__(self):
        self.signature_scanner = SignatureEngine()

    def scan_kernel_and_cmdline(self, report: BootScanReport) -> None:
        """Audits /proc/cmdline and kernel security features."""
        # 1. Parse cmdline
        cmdline_path = "/proc/cmdline"
        if os.path.exists(cmdline_path):
            try:
                with open(cmdline_path, "r") as f:
                    cmdline = f.read().strip()
                report.system_metadata["kernel_cmdline"] = cmdline

                for flag, desc, sev in DANGEROUS_CMDLINE_PARAMS:
                    if flag in cmdline:
                        report.findings.append(BootFinding(
                            category="Kernel Posture",
                            title=f"Insecure Boot Parameter: '{flag}'",
                            severity=sev,
                            target_path="/proc/cmdline",
                            description=desc,
                            remediation=f"Remove '{flag}' from GRUB_CMDLINE_LINUX in /etc/default/grub",
                        ))
            except Exception as e:
                report.system_metadata["cmdline_error"] = str(e)

        # 2. Kernel Lockdown Check
        lockdown_path = "/sys/kernel/security/lockdown"
        if os.path.exists(lockdown_path):
            try:
                with open(lockdown_path, "r") as f:
                    content = f.read().strip()
                report.system_metadata["lockdown_state"] = content
                if "[none]" in content:
                    report.findings.append(BootFinding(
                        category="Kernel Posture",
                        title="Kernel Lockdown Inactive",
                        severity="LOW",
                        target_path=lockdown_path,
                        description="Kernel lockdown mode is disabled ([none]), allowing unsigned kmods and direct memory access.",
                        remediation="Enable kernel lockdown via kernel parameter 'lockdown=integrity' or Secure Boot.",
                    ))
            except Exception:
                pass

        # 3. Kernel Taint Check
        taint_path = "/proc/sys/kernel/tainted"
        if os.path.exists(taint_path):
            try:
                with open(taint_path, "r") as f:
                    taint_val = int(f.read().strip())
                report.system_metadata["kernel_taint"] = taint_val
                if taint_val != 0:
                    report.findings.append(BootFinding(
                        category="Kernel Posture",
                        title=f"Kernel is Tainted (Value: {taint_val})",
                        severity="MEDIUM" if taint_val < 4096 else "LOW",
                        target_path=taint_path,
                        description=f"Kernel taint flag indicates proprietary or out-of-tree kernel modules loaded.",
                        remediation="Review loaded modules using 'lsmod' and verify cryptographic signatures.",
                    ))
            except Exception:
                pass

    def scan_persistence_mechanisms(self, report: BootScanReport) -> None:
        """Audits systemd units, cron tasks, and shell startup hooks."""
        # 1. Inspect Systemd Service Unit definitions
        systemd_dirs = ["/etc/systemd/system"]
        for sdir in systemd_dirs:
            if not os.path.isdir(sdir):
                continue
            for root, _, files in os.walk(sdir):
                for file in files:
                    if file.endswith(".service"):
                        path = os.path.join(root, file)
                        try:
                            with open(path, "r", errors="ignore") as f:
                                content = f.read()
                            # Check for suspicious commands in ExecStart
                            if re.search(r"ExecStart=.*(curl|wget).*\|\s*(ba)?sh", content, re.I):
                                report.findings.append(BootFinding(
                                    category="Persistence",
                                    title=f"Dangerous Systemd ExecStart in {file}",
                                    severity="CRITICAL",
                                    target_path=path,
                                    description="Systemd service executes piped remote shell script via curl/wget.",
                                    remediation=f"Inspect and remove rogue service definition: {path}",
                                ))
                            elif re.search(r"ExecStart=.*(nc\s+-[eE]|/dev/tcp/)", content, re.I):
                                report.findings.append(BootFinding(
                                    category="Persistence",
                                    title=f"Reverse Shell Service in {file}",
                                    severity="CRITICAL",
                                    target_path=path,
                                    description="Systemd service configures an automated reverse shell.",
                                    remediation=f"Disable and quarantine service file: {path}",
                                ))
                        except Exception:
                            continue

        # 2. Inspect Cron Tabs
        cron_locations = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
        for cloc in cron_locations:
            if os.path.isfile(cloc):
                self._audit_cron_file(cloc, report)
            elif os.path.isdir(cloc):
                for cf in glob.glob(os.path.join(cloc, "*")):
                    if os.path.isfile(cf):
                        self._audit_cron_file(cf, report)

    def _audit_cron_file(self, filepath: str, report: BootScanReport) -> None:
        try:
            with open(filepath, "r", errors="ignore") as f:
                lines = f.readlines()
            for line in lines:
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                if re.search(r"(curl|wget).*\|\s*(ba)?sh", clean, re.I) or re.search(r"/dev/tcp/", clean):
                    report.findings.append(BootFinding(
                        category="Persistence",
                        title=f"Suspicious Cron Job in {os.path.basename(filepath)}",
                        severity="HIGH",
                        target_path=filepath,
                        description=f"Automated cron task contains remote script execution: {clean[:80]}",
                        remediation=f"Review cron entry in {filepath} and purge unverified schedules.",
                    ))
        except Exception:
            pass

    def scan_sensitive_file_permissions(self, report: BootScanReport) -> None:
        """Audits permissions on critical system configuration files."""
        sensitive_files = [
            ("/etc/passwd", False, True),  # path, require_root_only_write, must_exist
            ("/etc/shadow", True, True),   # sensitive, no world read/write
            ("/etc/sudoers", True, True),
        ]

        for path, restrict_read, must_exist in sensitive_files:
            if not os.path.exists(path):
                if must_exist:
                    report.findings.append(BootFinding(
                        category="Permissions",
                        title=f"Critical File Missing: {path}",
                        severity="CRITICAL",
                        target_path=path,
                        description=f"Essential system security file {path} does not exist.",
                        remediation=f"Restore {path} from system backups immediately.",
                    ))
                continue

            try:
                st = os.stat(path)
                mode = st.st_mode

                # Check world-writable
                if mode & stat.S_IWOTH:
                    report.findings.append(BootFinding(
                        category="Permissions",
                        title=f"World-Writable Critical File: {path}",
                        severity="CRITICAL",
                        target_path=path,
                        description=f"File {path} is writable by any unprivileged user.",
                        remediation=f"Run: chmod o-w {path}",
                    ))

                # Check world-readable for shadow
                if restrict_read and (mode & stat.S_IROTH):
                    report.findings.append(BootFinding(
                        category="Permissions",
                        title=f"World-Readable Sensitive File: {path}",
                        severity="CRITICAL",
                        target_path=path,
                        description=f"File {path} contains password hashes but is world-readable.",
                        remediation=f"Run: chmod 600 {path}",
                    ))
            except Exception:
                pass

    def scan_suid_privilege_hazards(self, report: BootScanReport) -> None:
        """Audits SUID binaries, especially in temp paths and known GTFOBins."""
        # Check world-writable temp directories for SUID binaries
        temp_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        for tdir in temp_dirs:
            if not os.path.isdir(tdir):
                continue
            for root, _, files in os.walk(tdir):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                        if st.st_mode & stat.S_ISUID or st.st_mode & stat.S_ISGID:
                            report.findings.append(BootFinding(
                                category="SUID Hazards",
                                title=f"SUID/SGID Binary in Temp Directory: {fp}",
                                severity="CRITICAL",
                                target_path=fp,
                                description=f"An executable with SUID privileges was found in writable path {tdir}.",
                                remediation=f"Investigate provenance and remove: rm -f {fp}",
                            ))
                    except Exception:
                        continue

    def scan_malware_signatures_in_startup(self, report: BootScanReport) -> None:
        """Scans startup directories for reverse shells and droppers using SignatureEngine."""
        targets = ["/tmp", "/dev/shm"]
        for target in targets:
            if os.path.isdir(target):
                threats = self.signature_scanner.scan_directory(target, max_files=100)
                for t in threats:
                    report.findings.append(BootFinding(
                        category="Malware Signatures",
                        title=f"Malicious Signature Detected: {t.threat_name}",
                        severity=t.severity,
                        target_path=t.target_path,
                        description=f"Signature engine identified {t.threat_name} ({t.threat_type}) in {target}.",
                        remediation=f"Quarantine or delete infected file: rm -f {t.target_path}",
                    ))

    def run_full_boot_scan(self) -> BootScanReport:
        """Executes the complete boot security scan and returns a structured report."""
        start_time = time.time()
        hostname = os.uname().nodename if hasattr(os, "uname") else "linux-host"

        report = BootScanReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host=hostname,
            duration_seconds=0.0,
            overall_status="CLEAN",
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
        )

        # Execute 5 scan phases
        self.scan_kernel_and_cmdline(report)
        self.scan_persistence_mechanisms(report)
        self.scan_sensitive_file_permissions(report)
        self.scan_suid_privilege_hazards(report)
        self.scan_malware_signatures_in_startup(report)

        report.duration_seconds = round(time.time() - start_time, 3)
        report.total_findings = len(report.findings)

        # Count severities
        for f in report.findings:
            sev = f.severity.upper()
            if sev == "CRITICAL":
                report.critical_count += 1
            elif sev == "HIGH":
                report.high_count += 1
            elif sev == "MEDIUM":
                report.medium_count += 1
            elif sev == "LOW":
                report.low_count += 1

        if report.critical_count > 0:
            report.overall_status = "COMPROMISED / CRITICAL RISKS"
        elif report.high_count > 0 or report.medium_count > 0:
            report.overall_status = "WARNINGS FOUND"
        else:
            report.overall_status = "CLEAN & SECURE"

        return report

    def render_console_summary(self, report: BootScanReport) -> str:
        """Renders an enterprise console audit banner suitable for terminal and boot logs."""
        lines = []
        lines.append("=" * 80)
        lines.append("        CHRONOS LINUX & UBUNTU BOOT SECURITY & INTEGRITY AUDITOR        ")
        lines.append("=" * 80)
        lines.append(f"  Target Host:       {report.host}")
        lines.append(f"  Audit Timestamp:   {report.timestamp}")
        lines.append(f"  Scan Duration:     {report.duration_seconds}s")
        lines.append(f"  Overall Posture:   {report.overall_status}")
        lines.append(f"  Summary:           {report.total_findings} findings "
                     f"(Critical: {report.critical_count}, High: {report.high_count}, "
                     f"Medium: {report.medium_count}, Low: {report.low_count})")
        lines.append("-" * 80)

        if not report.findings:
            lines.append("  [+] No vulnerabilities, insecure boot flags, or malware detected.")
            lines.append("  [+] System boot state is CLEAN and SECURE.")
        else:
            for idx, f in enumerate(report.findings, 1):
                color_tag = f"[{f.severity}]"
                lines.append(f"  {idx}. {color_tag:<10} {f.category} — {f.title}")
                if f.target_path:
                    lines.append(f"     Path:        {f.target_path}")
                lines.append(f"     Description: {f.description}")
                lines.append(f"     Remedy:      {f.remediation}")
                lines.append("")

        lines.append("=" * 80)
        return "\n".join(lines)


def main():
    scanner = BootSecurityScanner()
    report = scanner.run_full_boot_scan()
    print(scanner.render_console_summary(report))

    # Save audit log to /var/log or /tmp
    log_dir = "/var/log" if os.access("/var/log", os.W_OK) else "/tmp"
    log_file = os.path.join(log_dir, "chronos-boot-audit.json")
    try:
        with open(log_file, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"[*] Audit ledger written to: {log_file}")
    except Exception as e:
        print(f"[!] Warning: Could not write audit log: {e}")

    # Exit with code 2 if critical threats detected
    if report.critical_count > 0:
        sys.exit(2)
    elif report.high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
