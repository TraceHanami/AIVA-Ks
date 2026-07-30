"""
JWT-based auth with role-based access control.

Roles: viewer < analyst < admin
- viewer:  read-only dashboard access
- analyst: triage alerts, run replay, use copilot
- admin:   manage response policies, user management
"""
import os
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

SECRET_KEY = os.environ["AIVA_JWT_SECRET"]  # fail fast if unset — no insecure default
ALGORITHM = "HS256"

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

security_scheme = HTTPBearer()


@dataclass
class CurrentUser:
    username: str
    role: str


def decode_token(token: str) -> CurrentUser:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return CurrentUser(username=payload["sub"], role=payload.get("role", "viewer"))


def require_role(min_role: str):
    async def dependency(
        creds: HTTPAuthorizationCredentials = Depends(security_scheme),
    ) -> CurrentUser:
        user = decode_token(creds.credentials)
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK[min_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency
