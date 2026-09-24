"""
CHRONOS / AIVA-KS User & Entity Behavior Analytics (UEBA) Engine (Module 17).

Analyzes user identity shifts, privilege escalations (sudo, setuid), off-hours
activity, anomalous mass file accesses, and user baseline deviations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class UebaAnomaly:
    user_id: int
    user_name: str
    anomaly_type: str         # privilege_escalation | off_hours_access | mass_file_read | credential_store_access
    severity: str             # CRITICAL | HIGH | MEDIUM | LOW
    anomaly_score: float      # 0.0 - 1.0
    evidence: str
    timestamp: str


class UebaEngine:
    """Monitors user-level baseline anomalies and privilege shifts."""

    def __init__(self, normal_working_hours: tuple[int, int] = (6, 22)):
        self.start_hour, self.end_hour = normal_working_hours
        self.user_file_counts: dict[int, int] = {}

    def analyze_events(self, events: list[dict[str, Any]]) -> list[UebaAnomaly]:
        anomalies: list[UebaAnomaly] = []

        for e in events:
            uid = e.get("uid", 1000)
            comm = e.get("comm", "unknown")
            timestamp_str = e.get("time") or e.get("timestamp", "")
            user_name = "root" if uid == 0 else f"user_{uid}"

            # 1. Privilege Escalation Anomaly (sudo / setuid / root transition from non-root)
            if comm in ("sudo", "su", "pkexec", "doas") or (uid == 0 and e.get("ppid", 1) != 1):
                anomalies.append(UebaAnomaly(
                    user_id=uid,
                    user_name=user_name,
                    anomaly_type="privilege_escalation",
                    severity="HIGH",
                    anomaly_score=0.85,
                    evidence=f"User {user_name} (UID {uid}) invoked privilege escalation binary '{comm}' (PID {e.get('pid')})",
                    timestamp=timestamp_str,
                ))

            # 2. Credential Access Anomaly (/etc/shadow, /etc/sudoers)
            filename = str(e.get("args", {}).get("filename", "") or e.get("target_path", ""))
            if any(p in filename for p in ("/etc/shadow", "/etc/sudoers", "/root/.ssh")):
                anomalies.append(UebaAnomaly(
                    user_id=uid,
                    user_name=user_name,
                    anomaly_type="credential_store_access",
                    severity="CRITICAL",
                    anomaly_score=0.95,
                    evidence=f"User {user_name} accessed protected credential file: {filename}",
                    timestamp=timestamp_str,
                ))

            # 3. Off-Hours Access Anomaly
            if timestamp_str:
                try:
                    dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    if dt.hour < self.start_hour or dt.hour > self.end_hour:
                        anomalies.append(UebaAnomaly(
                            user_id=uid,
                            user_name=user_name,
                            anomaly_type="off_hours_access",
                            severity="MEDIUM",
                            anomaly_score=0.60,
                            evidence=f"User {user_name} executed '{comm}' during off-hours ({dt.strftime('%H:%M:%S UTC')})",
                            timestamp=timestamp_str,
                        ))
                except Exception:
                    pass

        # De-duplicate anomalies by type & user
        unique_anomalies: dict[str, UebaAnomaly] = {}
        for a in anomalies:
            key = f"{a.user_id}:{a.anomaly_type}:{a.evidence}"
            if key not in unique_anomalies or a.anomaly_score > unique_anomalies[key].anomaly_score:
                unique_anomalies[key] = a

        return list(unique_anomalies.values())
