"""
CHRONOS API Application Factory.

Creates the FastAPI application instance with CORS middleware, background sensors lifespan,
and domain router mounts.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from chronos.config.settings import settings
from chronos.sensors.collector import live_collector_worker
from chronos.api.state import manager, case_service, threat_intel, ueba, replay_service

# Import domain routers
from chronos.api.routers import dashboard, cases, threat_intel as ti_router, ueba as ueba_router, actions, copilot, replay, scanner


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(live_collector_worker(manager))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Cyber Threat Understanding & Response Operating System API",
        version=settings.VERSION,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount domain routers
    app.include_router(dashboard.router, prefix="/api")
    app.include_router(cases.router, prefix="/api")
    app.include_router(ti_router.router, prefix="/api")
    app.include_router(ueba_router.router, prefix="/api")
    app.include_router(actions.router, prefix="/api")
    app.include_router(copilot.router, prefix="/api")
    app.include_router(replay.router, prefix="/api")
    app.include_router(scanner.router, prefix="/api")

    return app


app = create_app()
