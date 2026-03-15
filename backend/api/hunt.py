# Stub — implemented in its respective phase
from __future__ import annotations

import asyncio
import logging
from uuid import UUID, uuid4
from api.dependencies import get_current_user, assert_can_trigger_manual_hunt
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user, require_role
from database import get_db
from models.hunt_result import HuntResult
from services.ai.hunt import run_analyst_triggered_hunt
from scheduler import get_registered_jobs

logger = logging.getLogger("accc.api.hunt")

router = APIRouter(tags=["hunt"])


class HuntRunRequest(BaseModel):
    hypothesis: str = Field(..., min_length=5, max_length=1000)
    lookback_hours: int = Field(default=2, ge=1, le=24)


@router.post("/hunt/run", tags=["hunt"])
async def trigger_hunt(
    payload: HuntRunRequest,
    current_user: dict = Depends(get_current_user),
):
    assert_can_trigger_manual_hunt(current_user)

    hunt_id = str(uuid4())


@router.get("/hunt/results", tags=["hunt"])
async def list_hunt_results(
    status: str | None = Query(default=None),
    triggered_by: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user

    stmt = select(HuntResult).order_by(desc(HuntResult.started_at)).limit(limit).offset(offset)

    if status:
        stmt = stmt.where(HuntResult.status == status)
    if triggered_by:
        stmt = stmt.where(HuntResult.triggered_by == triggered_by)

    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return {
        "items": [item.to_dict() for item in items],
        "count": len(items),
        "limit": limit,
        "offset": offset,
    }


@router.get("/hunt/results/{hunt_id}", tags=["hunt"])
async def get_hunt_result(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user

    result = await db.execute(
        select(HuntResult)
        .where(HuntResult.hunt_id == hunt_id)
        .order_by(desc(HuntResult.started_at))
        .limit(1)
    )
    row = result.scalars().first()

    if row is None:
        raise HTTPException(status_code=404, detail="Hunt result not found")

    return row.to_dict()


@router.get("/hunt/jobs", tags=["hunt"])
async def list_hunt_jobs(current_user: dict = Depends(get_current_user)):
    del current_user
    return {
        "jobs": get_registered_jobs(),
    }