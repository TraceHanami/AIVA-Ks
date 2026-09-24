"""CHRONOS API — Digital Twin Replay Router (Module 19)."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from chronos.api.state import manager, replay_service

router = APIRouter(tags=["Digital Twin Replay"])


class BuildReplayRequest(BaseModel):
    host_id: str = "cachyos-x8664"


@router.post("/replay/build")
async def build_replay_session(req: BuildReplayRequest, host: Optional[str] = "test"):
    st = manager.get_state(host)
    session_id = replay_service.build_digital_twin_replay(req.host_id, st.events)
    return {"status": "built", "session_id": session_id, "host_id": req.host_id}


@router.get("/replay/step")
async def get_replay_step(session_id: str, step: int = 1):
    sn = replay_service.get_snapshot(session_id, step)
    if not sn:
        raise HTTPException(status_code=404, detail="Replay session or step not found")
    return sn
