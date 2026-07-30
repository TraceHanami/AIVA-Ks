import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_role
from app.db.session import get_session
from app.models.orm import AttackGraph
from app.schemas.schemas import AttackGraphOut

router = APIRouter()


@router.get("/{graph_uid}", response_model=AttackGraphOut)
async def get_graph(
    graph_uid: UUID,
    session: AsyncSession = Depends(get_session),
    _user=Depends(require_role("viewer")),
):
    graph = await session.get(AttackGraph, graph_uid)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")
    payload = graph.graph_json or {"nodes": [], "edges": []}
    return AttackGraphOut(
        graph_uid=graph.graph_uid,
        host_id=graph.host_id,
        nodes=payload.get("nodes", []),
        edges=payload.get("edges", []),
        risk_score=graph.risk_score,
    )


@router.websocket("/live/{host_id}")
async def live_graph_updates(websocket: WebSocket, host_id: str):
    """
    Streams incremental graph deltas (new nodes/edges + risk updates) to the
    dashboard as the graph engine ingests events for this host. Backed by a
    Kafka consumer on `graph.updates` filtered by host_id partition key —
    shown here as a bridging task; wire the real Kafka consumer in prod.
    """
    await websocket.accept()
    try:
        while True:
            # placeholder heartbeat; replace with:
            #   async for delta in kafka_graph_updates_consumer(host_id): ...
            await asyncio.sleep(5)
            await websocket.send_text(json.dumps({"type": "heartbeat", "host_id": host_id}))
    except WebSocketDisconnect:
        pass
