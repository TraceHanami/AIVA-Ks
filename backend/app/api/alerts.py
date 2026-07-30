from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.security import require_role
from app.schemas.schemas import AlertOut, AlertStatusUpdate
from app.services.alert_service import AlertService

router = APIRouter()


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    status: str | None = Query(None, pattern="^(open|ack|closed|false_positive)$"),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    limit: int = Query(50, le=500),
    offset: int = 0,
    service: AlertService = Depends(AlertService),
    _user=Depends(require_role("analyst")),
):
    return await service.list_alerts(status=status, severity=severity, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: UUID,
    service: AlertService = Depends(AlertService),
    _user=Depends(require_role("analyst")),
):
    alert = await service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertOut)
async def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    service: AlertService = Depends(AlertService),
    user=Depends(require_role("analyst")),
):
    """
    Analyst triage action. Writes to `investigations` if notes/status
    transition creates a new investigation thread, and always leaves an
    audit trail via `investigations.analyst`.
    """
    alert = await service.update_status(alert_id, body, actor=user.username)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
