import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    user_id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="viewer")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login_at = Column(DateTime(timezone=True))
    active = Column(Boolean, nullable=False, default=True)


class Host(Base):
    __tablename__ = "hosts"
    host_id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String, nullable=False)


class AttackGraph(Base):
    __tablename__ = "attack_graphs"
    graph_uid = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(PGUUID(as_uuid=True), ForeignKey("hosts.host_id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    graph_json = Column(JSONB)
    risk_score = Column(Numeric(5, 2))


class Prediction(Base):
    __tablename__ = "predictions"
    prediction_id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    graph_uid = Column(PGUUID(as_uuid=True), ForeignKey("attack_graphs.graph_uid"))
    model_name = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    intent_class = Column(String, nullable=False)
    confidence = Column(Numeric(5, 4), nullable=False)
    mitre_techniques = Column(JSONB)
    predicted_at = Column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"
    alert_id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(PGUUID(as_uuid=True), ForeignKey("hosts.host_id"), nullable=False)
    graph_uid = Column(PGUUID(as_uuid=True), ForeignKey("attack_graphs.graph_uid"))
    prediction_id = Column(PGUUID(as_uuid=True), ForeignKey("predictions.prediction_id"))
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Investigation(Base):
    __tablename__ = "investigations"
    investigation_id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(PGUUID(as_uuid=True), ForeignKey("alerts.alert_id"))
    analyst = Column(String)
    notes = Column(String)
    status = Column(String, nullable=False, default="open")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
