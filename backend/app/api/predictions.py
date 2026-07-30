from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_role
from app.db.session import get_session
from app.models.orm import Prediction
from app.schemas.schemas import PredictionOut

router = APIRouter()


@router.get("/{graph_uid}", response_model=list[PredictionOut])
async def get_predictions_for_graph(
    graph_uid: UUID,
    session: AsyncSession = Depends(get_session),
    _user=Depends(require_role("viewer")),
):
    result = await session.execute(
        select(Prediction).where(Prediction.graph_uid == graph_uid).order_by(Prediction.predicted_at.desc())
    )
    predictions = result.scalars().all()
    if not predictions:
        raise HTTPException(status_code=404, detail="No predictions for this graph")
    return predictions
