"""
AIVA-KS seed script — creates one admin user and a synthetic incident
(host, attack graph, prediction, alert) so the API returns real data
instead of empty lists / 404s on first run.

Usage (from backend/ with DB env vars set, or via docker exec):

    python -m scripts.seed_db --username admin --password changeme123

Safe to re-run: uses ON CONFLICT DO NOTHING for the user, and always
creates a fresh incident (so re-running gives you more sample alerts,
not duplicates of the same one causing FK errors).
"""
import argparse
import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.password import hash_password
from app.db.session import AsyncSessionLocal
from app.models.orm import Alert, AttackGraph, Host, Prediction, User

# The same synthetic attack graph used in demo_full_pipeline.py, so the
# seeded alert corresponds to a real, already-verified risk-scored graph
# rather than arbitrary placeholder numbers.
SAMPLE_GRAPH_JSON = {
    "nodes": [
        {"id": "Process:demo-host-01:4210", "type": "Process", "label": "invoice.exe", "risk": 0.05},
        {"id": "Process:demo-host-01:4260", "type": "Process", "label": "child", "risk": 0.80},
        {"id": "MemoryRegion:demo-host-01:4260:140234", "type": "MemoryRegion", "label": "RWX region", "risk": 0.56},
        {"id": "Process:demo-host-01:890", "type": "Process", "label": "ptrace_target", "risk": 0.56},
        {"id": "Socket:demo-host-01:203.0.113.55:443", "type": "Socket", "label": "203.0.113.55:443", "risk": 0.56},
        {"id": "File:demo-host-01:/etc/shadow", "type": "File", "label": "/etc/shadow", "risk": 0.39},
        {"id": "File:demo-host-01:/tmp/.cache_dump", "type": "File", "label": "/tmp/.cache_dump", "risk": 0.39},
    ],
    "edges": [
        {"source": "Process:demo-host-01:4210", "target": "Process:demo-host-01:4260", "relation": "creates", "weight": 0.05},
        {"source": "Process:demo-host-01:4260", "target": "MemoryRegion:demo-host-01:4260:140234", "relation": "loads", "weight": 0.1},
        {"source": "Process:demo-host-01:4260", "target": "Process:demo-host-01:890", "relation": "injects", "weight": 0.8},
        {"source": "Process:demo-host-01:4260", "target": "Socket:demo-host-01:203.0.113.55:443", "relation": "connects", "weight": 0.15},
        {"source": "Process:demo-host-01:890", "target": "File:demo-host-01:/etc/shadow", "relation": "reads", "weight": 0.05},
        {"source": "Process:demo-host-01:890", "target": "File:demo-host-01:/tmp/.cache_dump", "relation": "writes", "weight": 0.1},
    ],
}


async def seed_user(session: AsyncSession, username: str, password: str, role: str):
    existing = await session.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        print(f"User '{username}' already exists, skipping.")
        return
    session.add(User(username=username, password_hash=hash_password(password), role=role))
    await session.commit()
    print(f"Created user '{username}' with role '{role}'.")


async def seed_incident(session: AsyncSession):
    host = Host(host_id=uuid.uuid4(), hostname="demo-host-01")
    session.add(host)
    await session.flush()  # get host.host_id populated before FK use

    graph = AttackGraph(
        graph_uid=uuid.uuid4(), host_id=host.host_id,
        graph_json=SAMPLE_GRAPH_JSON, risk_score=0.80,
    )
    session.add(graph)
    await session.flush()

    prediction = Prediction(
        prediction_id=uuid.uuid4(), graph_uid=graph.graph_uid,
        model_name="baseline-gbt", model_version="v0.1",
        intent_class="CredentialTheft", confidence=0.75,
        mitre_techniques=[
            {"technique_id": "T1055", "confidence": 0.90},
            {"technique_id": "T1003", "confidence": 0.75},
            {"technique_id": "T1041", "confidence": 0.50},
        ],
    )
    session.add(prediction)
    await session.flush()

    alert = Alert(
        alert_id=uuid.uuid4(), host_id=host.host_id, graph_uid=graph.graph_uid,
        prediction_id=prediction.prediction_id, severity="high", status="open",
    )
    session.add(alert)
    await session.commit()

    print(f"Seeded incident: host={host.hostname} alert_id={alert.alert_id} severity=high")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="admin", choices=["viewer", "analyst", "admin"])
    parser.add_argument("--skip-incident", action="store_true")
    args = parser.parse_args()

    async with AsyncSessionLocal() as session:
        await seed_user(session, args.username, args.password, args.role)
        if not args.skip_incident:
            await seed_incident(session)


if __name__ == "__main__":
    asyncio.run(main())
