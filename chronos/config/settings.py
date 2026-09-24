"""
CHRONOS Configuration Settings.

Centralized configuration using environment variables and Pydantic settings.
Isolated from business logic to ensure production-grade security and maintainability.
"""
from __future__ import annotations

import os
from pydantic import BaseModel


class Settings(BaseModel):
    # System Metadata
    PROJECT_NAME: str = "CHRONOS"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = os.getenv("CHRONOS_ENV", "development")
    DEBUG: bool = os.getenv("CHRONOS_DEBUG", "True").lower() == "true"

    # API Configuration
    API_HOST: str = os.getenv("CHRONOS_API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("CHRONOS_API_PORT", "8000"))
    API_BASE_URL: str = os.getenv("AIVA_API_URL", "http://127.0.0.1:8000")

    # Research Engine Thresholds
    DEFAULT_RISK_DECAY: float = 0.7
    MAX_RISK_ITERATIONS: int = 3
    MIN_HIGH_RISK_THRESHOLD: float = 0.5
    DEFAULT_WORKSTATION_MULTIPLIER: float = 1.0

    # Containment & Safety Invariants
    REQUIRE_APPROVAL_FOR_DESTRUCTIVE: bool = True
    QUARANTINE_DIR: str = os.getenv("CHRONOS_QUARANTINE_DIR", "/tmp/chronos_quarantine")


settings = Settings()
