# Stub — implemented in its respective phase
from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import (
    get_current_user,
    assert_can_update_asset_metadata,
)
from database import get_db
from models.asset import Asset

logger = logging.getLogger("accc.api.assets")

router = APIRouter(tags=["assets"])


class AssetUpdateRequest(BaseModel):
    criticality: Optional[str] = None
    owner: Optional[str] = None
    os: Optional[str] = None
    tags: Optional[list[str]] = None
    is_internet_facing: Optional[bool] = None
    notes: Optional[str] = None
    asset_type: Optional[str] = None


@router.get("/assets", tags=["assets"])
async def list_assets(
    criticality: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user

    stmt = select(Asset).limit(limit).offset(offset)

    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if hostname:
        stmt = stmt.where(Asset.hostname.ilike(f"%{hostname}%"))

    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return {
        "items": [item.to_dict() for item in items],
        "count": len(items),
        "limit": limit,
        "offset": offset,
    }


@router.put("/assets/{asset_id}", tags=["assets"])
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    assert_can_update_asset_metadata(current_user)

    patch_data = payload.model_dump(exclude_unset=True)
    if not patch_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    result = await db.execute(
        select(Asset).where(Asset.id == asset_id).limit(1)
    )
    asset = result.scalars().first()

    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    for field, value in patch_data.items():
        setattr(asset, field, value)

    await db.commit()
    await db.refresh(asset)

    return asset.to_dict()