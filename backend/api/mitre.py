from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user
from database import get_db
from services.mitre_heatmap import build_mitre_heatmap_payload

router = APIRouter(tags=["mitre"])


@router.get("/mitre/heatmap", tags=["mitre"])
async def get_mitre_heatmap(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user
    return await build_mitre_heatmap_payload(db)