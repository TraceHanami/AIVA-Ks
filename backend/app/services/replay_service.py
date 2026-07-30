"""
Incident Replay Engine (backend-facing service).

Reconstructs a time-bounded view of events/graph state from Postgres
(events hypertable + attack_graphs snapshots) and paces delivery over a
WebSocket according to the requested speed multiplier, so analysts can
"scrub" through an incident like a DVR.
"""
import uuid
from datetime import datetime
from uuid import UUID

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session


class ReplayService:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def create_session(self, host_id: UUID, start: datetime, end: datetime, speed: float) -> str:
        session_id = str(uuid.uuid4())
        # In production: persist session bounds (e.g. Redis) keyed by
        # session_id, so the /stream WebSocket handler can look them up
        # and page through `events` ordered by time, sleeping
        # (event[i+1].time - event[i].time) / speed between sends.
        return session_id
