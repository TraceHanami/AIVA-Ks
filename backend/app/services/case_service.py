"""
CHRONOS / AIVA-KS Investigation Workspace & Case Management Service (Module 12).

Manages formal SOC investigation cases (e.g. Case #412), evidence attachments,
analyst notes, forensic verdicts, and exportable incident case binders.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CaseNote:
    note_id: str
    author: str
    content: str
    timestamp: str


@dataclass
class Case:
    case_id: str
    title: str
    host_id: str
    severity: str             # CRITICAL | HIGH | MEDIUM | LOW
    status: str               # OPEN | INVESTIGATING | CONTAINED | CLOSED
    assigned_to: str
    created_at: str
    updated_at: str
    evidence_event_ids: list[int] = field(default_factory=list)
    mitre_technique_ids: list[str] = field(default_factory=list)
    notes: list[CaseNote] = field(default_factory=list)
    verdict: str = "Under Active Investigation"

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "host_id": self.host_id,
            "severity": self.severity,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence_event_ids": self.evidence_event_ids,
            "mitre_technique_ids": self.mitre_technique_ids,
            "notes": [
                {
                    "note_id": n.note_id,
                    "author": n.author,
                    "content": n.content,
                    "timestamp": n.timestamp,
                }
                for n in self.notes
            ],
            "verdict": self.verdict,
        }


class CaseService:
    """Manages active SOC cases in memory with persistent serialization."""

    def __init__(self):
        self.cases: dict[str, Case] = {}
        self._initialize_default_case()

    def _initialize_default_case(self):
        # Create initial default Case #412 for demonstration
        default_case = Case(
            case_id="CASE-412",
            title="Suspicious Process Injection & Exfiltration Chain on Linux Host",
            host_id="cachyos-x8664",
            severity="CRITICAL",
            status="INVESTIGATING",
            assigned_to="Lead_SOC_Analyst",
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
            evidence_event_ids=[1, 2, 3, 4, 5],
            mitre_technique_ids=["T1055", "T1041", "T1003"],
            notes=[
                CaseNote(
                    note_id="note-001",
                    author="Lead_SOC_Analyst",
                    content="CHRONOS automated graph risk score reached 96%. Process injection (T1055) detected via ptrace + RWX mprotect flags.",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            ],
            verdict="True Positive — Active Process Injection & Exfiltration Attempt",
        )
        self.cases[default_case.case_id] = default_case

    def get_case(self, case_id: str) -> Case | None:
        return self.cases.get(case_id)

    def list_cases(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.cases.values()]

    def create_case(
        self,
        title: str,
        host_id: str,
        severity: str = "HIGH",
        assigned_to: str = "SOC_Tier2_Analyst",
        evidence_event_ids: list[int] | None = None,
        mitre_technique_ids: list[str] | None = None,
    ) -> Case:
        num = len(self.cases) + 413
        case_id = f"CASE-{num}"
        now = datetime.now(timezone.utc).isoformat()

        new_case = Case(
            case_id=case_id,
            title=title,
            host_id=host_id,
            severity=severity,
            status="OPEN",
            assigned_to=assigned_to,
            created_at=now,
            updated_at=now,
            evidence_event_ids=evidence_event_ids or [],
            mitre_technique_ids=mitre_technique_ids or [],
            notes=[],
            verdict="Under Triaging",
        )
        self.cases[case_id] = new_case
        return new_case

    def add_note(self, case_id: str, author: str, content: str) -> CaseNote:
        case = self.get_case(case_id)
        if not case:
            raise KeyError(f"Case {case_id} not found")
        now = datetime.now(timezone.utc).isoformat()
        note = CaseNote(
            note_id=f"note-{uuid.uuid4().hex[:6]}",
            author=author,
            content=content,
            timestamp=now,
        )
        case.notes.append(note)
        case.updated_at = now
        return note

    def update_status(self, case_id: str, status: str, verdict: str | None = None) -> Case:
        case = self.get_case(case_id)
        if not case:
            raise KeyError(f"Case {case_id} not found")
        case.status = status
        if verdict:
            case.verdict = verdict
        case.updated_at = datetime.now(timezone.utc).isoformat()
        return case

    def export_case_binder(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        if not case:
            raise KeyError(f"Case {case_id} not found")
        return {
            "chronos_version": "2.0.0",
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "case": case.to_dict(),
        }
