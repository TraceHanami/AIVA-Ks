from uuid import UUID

from fastapi import Depends
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.orm import Alert, Investigation
from app.schemas.schemas import AlertStatusUpdate


class AlertService:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def list_alerts(self, status: str | None, severity: str | None, limit: int, offset: int):
        stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
        if status:
            stmt = stmt.where(Alert.status == status)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_alert(self, alert_id: UUID):
        return await self.session.get(Alert, alert_id)

    async def update_status(self, alert_id: UUID, body: AlertStatusUpdate, actor: str):
        alert = await self.session.get(Alert, alert_id)
        if not alert:
            return None

        await self.session.execute(
            update(Alert).where(Alert.alert_id == alert_id).values(status=body.status)
        )

        if body.notes:
            self.session.add(
                Investigation(alert_id=alert_id, analyst=actor, notes=body.notes, status="open")
            )

        await self.session.commit()
        await self.session.refresh(alert)
        return alert
