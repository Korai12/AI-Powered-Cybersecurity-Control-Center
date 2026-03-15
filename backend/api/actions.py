from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import (
    get_current_user,
    assert_can_create_response_action,
    assert_can_approve_response_action,
    assert_min_role,
)
from database import get_db
from models.response_action import ResponseAction
from services.response.executor import response_action_executor

logger = logging.getLogger("accc.api.actions")

router = APIRouter(tags=["actions"])


class ActionCreateRequest(BaseModel):
    incident_id: UUID
    action_type: str = Field(..., min_length=2, max_length=50)
    action_params: dict[str, Any] = Field(default_factory=dict)
    created_by: str = Field(default="analyst", pattern="^(ai|analyst)$")


@router.get("/actions", tags=["actions"])
async def list_actions(
    status: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    incident_id: UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user

    stmt = (
        select(ResponseAction)
        .order_by(desc(ResponseAction.created_at))
        .limit(limit)
        .offset(offset)
    )

    if status:
        stmt = stmt.where(ResponseAction.status == status)
    if risk_level:
        stmt = stmt.where(ResponseAction.risk_level == risk_level.upper())
    if incident_id:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)

    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return {
        "items": [item.to_dict() for item in items],
        "count": len(items),
        "limit": limit,
        "offset": offset,
    }


@router.post("/actions", tags=["actions"])
async def create_action(
    payload: ActionCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    assert_can_create_response_action(current_user)

    try:
        return await response_action_executor.create_action(
            incident_id=payload.incident_id,
            action_type=payload.action_type,
            action_params=payload.action_params,
            created_by=payload.created_by,
            requested_by=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create action: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to create action: {str(exc)}") from exc


@router.post("/actions/{action_id}/approve", tags=["actions"])
async def approve_action(
    action_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(
        select(ResponseAction).where(ResponseAction.id == action_id).limit(1)
    )
    action = result.scalars().first()

    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    assert_can_approve_response_action(current_user, action.risk_level)

    try:
        return await response_action_executor.approve_action(
            action_id=action_id,
            approved_by=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to approve action %s: %s", action_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to approve action: {str(exc)}") from exc


@router.post("/actions/{action_id}/veto", tags=["actions"])
async def veto_action(
    action_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    try:
        return await response_action_executor.veto_action(
            action_id=action_id,
            vetoed_by=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to veto action %s: %s", action_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to veto action: {str(exc)}") from exc


@router.post("/actions/{action_id}/rollback", tags=["actions"])
async def rollback_action(
    action_id: UUID,
    current_user: dict = Depends(get_current_user),
):
    assert_min_role(current_user, "senior_analyst", "Rolling back response actions")

    try:
        return await response_action_executor.rollback_action(
            action_id=action_id,
            rolled_back_by=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to roll back action %s: %s", action_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to roll back action: {str(exc)}") from exc