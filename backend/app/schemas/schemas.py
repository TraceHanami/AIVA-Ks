from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class AlertOut(BaseModel):
    alert_id: UUID
    host_id: UUID
    graph_uid: Optional[UUID]
    prediction_id: Optional[UUID]
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|ack|closed|false_positive)$")
    analyst: Optional[str] = None
    notes: Optional[str] = None


class PredictionOut(BaseModel):
    prediction_id: UUID
    graph_uid: UUID
    model_name: str
    model_version: str
    intent_class: str
    confidence: float
    mitre_techniques: list[dict[str, Any]]
    predicted_at: datetime

    class Config:
        from_attributes = True


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    risk: float = 0.0


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    weight: float


class AttackGraphOut(BaseModel):
    graph_uid: UUID
    host_id: UUID
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    risk_score: Optional[float]


class ReplayRequest(BaseModel):
    host_id: UUID
    start_time: datetime
    end_time: datetime
    speed: float = Field(1.0, gt=0, le=50)


class ChatMessageIn(BaseModel):
    investigation_id: Optional[UUID] = None
    message: str


class ChatMessageOut(BaseModel):
    message_id: UUID
    role: str
    content: str
    retrieved_context: Optional[list[dict[str, Any]]] = None
    created_at: datetime
