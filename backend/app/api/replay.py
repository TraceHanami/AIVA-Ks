from fastapi import APIRouter, Depends

from app.core.security import require_role
from app.schemas.schemas import ReplayRequest
from app.services.replay_service import ReplayService

router = APIRouter()


@router.post("/session")
async def start_replay(
    body: ReplayRequest,
    service: ReplayService = Depends(ReplayService),
    _user=Depends(require_role("analyst")),
):
    """
    Creates a replay session: reconstructs event/graph state for
    [start_time, end_time] at the requested playback speed. Returns a
    replay_session_id; the frontend then opens a WebSocket at
    /api/replay/stream/{replay_session_id} to receive paced events.
    """
    session_id = await service.create_session(body.host_id, body.start_time, body.end_time, body.speed)
    return {"replay_session_id": session_id}
