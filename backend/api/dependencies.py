"""
ACCC Authentication Dependencies
Phase 2.1: JWT validation + role-based access control (G-07)

Usage:
    @router.get('/protected')
    async def endpoint(user = Depends(get_current_user)):
        ...

    @router.post('/admin-only')
    async def endpoint(user = Depends(require_role('soc_manager'))):
        ...
"""

import logging
from typing import Optional
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db

logger = logging.getLogger("accc.auth")

# FastAPI security scheme — extracts Bearer token from Authorization header
security = HTTPBearer(auto_error=False)

# Role hierarchy: higher roles inherit all lower-role permissions
ROLE_HIERARCHY = {
    "analyst": 0,
    "senior_analyst": 1,
    "soc_manager": 2,
}


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT access token.
    Returns the payload dict or raises HTTPException.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        # Check required claims
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user_id claim",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError as e:
        logger.warning(f"JWT decode failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    FastAPI dependency: extracts Bearer JWT, validates, returns user dict.
    All protected endpoints use this.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated — Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)

    # Verify user still exists and is active
    result = await db.execute(
        text("SELECT id, username, role, display_name FROM users WHERE id = :uid"),
        {"uid": payload["user_id"]},
    )
    user_row = result.mappings().first()

    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    

    # Update last_login timestamp
    await db.execute(
        text("UPDATE users SET last_login = :now WHERE id = :uid"),
        {"now": datetime.now(timezone.utc), "uid": payload["user_id"]},
    )
    await db.commit()

    return {
        "id": str(user_row["id"]),
        "username": user_row["username"],
        "email": "",
        "role": user_row["role"],
    }


def require_role(minimum_role: str):
    """
    Factory that returns a FastAPI dependency enforcing minimum role level.

    Usage:
        @router.post('/admin-action')
        async def handler(user = Depends(require_role('soc_manager'))):
            ...
    """
    min_level = ROLE_HIERARCHY.get(minimum_role, 0)

    async def _check_role(user: dict = Depends(get_current_user)) -> dict:
        user_level = ROLE_HIERARCHY.get(user["role"], 0)
        if user_level < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions — requires {minimum_role} or higher",
            )
        return user

    return _check_role


async def get_current_user_ws(token: str, db: AsyncSession) -> Optional[dict]:
    """
    WebSocket-specific auth: validates JWT token passed as query param.
    Returns user dict or None (WebSocket can't use HTTP exceptions).
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id = payload.get("user_id")
        if not user_id:
            return None

        result = await db.execute(
            text("SELECT id, username, role FROM users WHERE id = :uid"),
            {"uid": user_id},
        )
        user_row = result.mappings().first()
        if user_row is None:
            return None

        return {
            "id": str(user_row["id"]),
            "username": user_row["username"],
            "role": user_row["role"],
        }
    except JWTError:
        return None