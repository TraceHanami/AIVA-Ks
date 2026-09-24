"""CHRONOS API — Case Workspace Router (Module 12)."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from chronos.api.state import case_service

router = APIRouter(tags=["Cases"])


class CreateCaseRequest(BaseModel):
    title: str
    host_id: str = "cachyos-x8664"
    severity: str = "HIGH"
    assigned_to: str = "Lead_SOC_Analyst"
    evidence_event_ids: Optional[list[int]] = []
    mitre_technique_ids: Optional[list[str]] = []


class AddNoteRequest(BaseModel):
    author: str = "Lead_SOC_Analyst"
    content: str


@router.get("/cases")
async def list_cases():
    return {"cases": case_service.list_cases()}


@router.post("/cases")
async def create_case(req: CreateCaseRequest):
    c = case_service.create_case(
        title=req.title,
        host_id=req.host_id,
        severity=req.severity,
        assigned_to=req.assigned_to,
        evidence_event_ids=req.evidence_event_ids,
        mitre_technique_ids=req.mitre_technique_ids,
    )
    return {"status": "created", "case": c.to_dict()}


@router.get("/cases/{case_id}")
async def get_case(case_id: str):
    c = case_service.get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case": c.to_dict()}


@router.post("/cases/{case_id}/notes")
async def add_case_note(case_id: str, req: AddNoteRequest):
    try:
        note = case_service.add_note(case_id, author=req.author, content=req.content)
        return {"status": "note_added", "note": note.__dict__}
    except KeyError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.get("/cases/{case_id}/export")
async def export_case_binder(case_id: str):
    try:
        binder = case_service.export_case_binder(case_id)
        return binder
    except KeyError:
        raise HTTPException(status_code=404, detail="Case not found")
