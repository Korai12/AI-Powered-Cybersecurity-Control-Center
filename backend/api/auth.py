"""
ACCC Authentication API — backend/api/auth.py
Phase 2.1: All 4 auth endpoints (G-07, G-16)

Endpoints (registered with prefix='' — NOT /api/v1):
    POST /auth/login    — Verify credentials, return JWT + httpOnly refresh cookie
    POST /auth/refresh  — Issue new access token from refresh cookie
    POST /auth/logout   — Invalidate refresh token, clear cookie
    GET  /auth/me       — Return current user profile from Bearer token
"""

import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from config import settings
from database import get_db
from api.dependencies import get_current_user

logger = logging.getLogger("accc.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Password hashing — matches init_db bcrypt hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ──────────────────────────────────────────────────────────
# Request / Response Models
# ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    username: str


class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    role: str


# ──────────────────────────────────────────────────────────
# Redis Helper
# ──────────────────────────────────────────────────────────

async def _get_redis() -> aioredis.Redis:
    """Get async Redis connection for token storage."""
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


# ──────────────────────────────────────────────────────────
# Token Creation Helpers
# ──────────────────────────────────────────────────────────

def create_access_token(user_id: str, username: str, role: str) -> tuple[str, int]:
    """
    Create a signed JWT access token (15-min lifetime per G-16).
    Returns (token_string, expires_in_seconds).
    """
    expires_delta = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta

    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, int(expires_delta.total_seconds())


def create_refresh_token() -> str:
    """Create an opaque UUID refresh token (stored in Redis + httpOnly cookie)."""
    return str(uuid.uuid4())


# ──────────────────────────────────────────────────────────
# POST /auth/login
# ──────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify username + bcrypt password.
    Returns access_token in body + refresh_token as httpOnly cookie.
    """
    # Look up user
    result = await db.execute(
        text(
            "SELECT id, username, password_hash, role, display_name "
            "FROM users WHERE username = :uname"
        ),
        {"uname": body.username},
    )
    user = result.mappings().first()

    if user is None or not pwd_context.verify(body.password, user["password_hash"]):
        logger.warning(f"Failed login attempt for username: {body.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )


    user_id = str(user["id"])

    # Create tokens
    access_token, expires_in = create_access_token(user_id, user["username"], user["role"])
    refresh_token = create_refresh_token()

    # Store refresh token in Redis with 7-day TTL (G-16)
    r = await _get_redis()
    refresh_ttl = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    await r.set(
        f"refresh:{refresh_token}",
        user_id,
        ex=int(refresh_ttl.total_seconds()),
    )
    await r.aclose()

    # Update last_login
    await db.execute(
        text("UPDATE users SET last_login = :now WHERE id = :uid"),
        {"now": datetime.now(timezone.utc), "uid": user_id},
    )
    await db.commit()

    # Set httpOnly cookie for refresh token
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=int(refresh_ttl.total_seconds()),
        path="/auth",
    )

    logger.info(f"User '{user['username']}' logged in successfully (role: {user['role']})")

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        role=user["role"],
        username=user["username"],
    )


# ──────────────────────────────────────────────────────────
# POST /auth/refresh
# ──────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Read refresh token from httpOnly cookie, validate against Redis whitelist,
    issue new access token. Rotate refresh token for security.
    """
    refresh_tok = request.cookies.get("refresh_token")
    if not refresh_tok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token — please log in",
        )

    # Validate refresh token in Redis
    r = await _get_redis()
    user_id = await r.get(f"refresh:{refresh_tok}")

    if user_id is None:
        await r.aclose()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token — please log in again",
        )

    # Delete old refresh token (rotation)
    await r.delete(f"refresh:{refresh_tok}")

    # Look up user
    result = await db.execute(
        text("SELECT id, username, role, display_name FROM users WHERE id = :uid"),
        {"uid": user_id},
    )
    user = result.mappings().first()

    if user is None:
        await r.aclose()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )

    # Create new token pair
    access_token, expires_in = create_access_token(
        str(user["id"]), user["username"], user["role"]
    )
    new_refresh_token = create_refresh_token()

    # Store new refresh token
    refresh_ttl = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    await r.set(
        f"refresh:{new_refresh_token}",
        str(user["id"]),
        ex=int(refresh_ttl.total_seconds()),
    )
    await r.aclose()

    # Set new cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=int(refresh_ttl.total_seconds()),
        path="/auth",
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        role=user["role"],
        username=user["username"],
    )


# ──────────────────────────────────────────────────────────
# POST /auth/logout
# ──────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: dict = Depends(get_current_user),
):
    """
    Invalidate refresh token in Redis and clear httpOnly cookie.
    Requires valid access token (Bearer header).
    """
    refresh_tok = request.cookies.get("refresh_token")

    if refresh_tok:
        r = await _get_redis()
        await r.delete(f"refresh:{refresh_tok}")
        await r.aclose()

    # Clear the cookie
    response.delete_cookie(
        key="refresh_token",
        path="/auth",
    )

    logger.info(f"User '{user['username']}' logged out")

    return {"message": "Logged out successfully"}


# ──────────────────────────────────────────────────────────
# GET /auth/me
# ──────────────────────────────────────────────────────────

@router.get("/me", response_model=UserProfile)
async def get_me(user: dict = Depends(get_current_user)):
    """Return current user profile from JWT claim + DB lookup."""
    return UserProfile(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
    )