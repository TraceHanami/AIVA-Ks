import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.password import verify_password
from app.db.session import get_session
from app.models.orm import User

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(User).where(User.username == body.username, User.active.is_(True))
    )
    user = result.scalar_one_or_none()

    # verify_password still runs (against a dummy hash) even when the user
    # doesn't exist, so login timing doesn't leak which usernames are valid
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dummydummydummydummydummydummy"
    password_ok = verify_password(body.password, user.password_hash if user else dummy_hash)

    if not user or not password_ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await session.execute(
        update(User).where(User.user_id == user.user_id).values(last_login_at=datetime.now(timezone.utc))
    )
    await session.commit()

    payload = {
        "sub": user.username,
        "role": user.role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    token = jwt.encode(payload, os.environ["AIVA_JWT_SECRET"], algorithm="HS256")
    return LoginResponse(access_token=token, role=user.role)
