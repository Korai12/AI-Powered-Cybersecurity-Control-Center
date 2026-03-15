# Stub — implemented in its respective phase
#Phase 5.5 

from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
#phase 6.1 
import asyncio

from sqlalchemy import select

from models.incident import Incident
from services.ai.react_agent import run_react_investigation

from api.dependencies import get_current_user, require_role
from database import get_db
from services.incident_service import (
    get_incident_detail,
    get_incident_report,
    get_incident_timeline,
    list_incidents,
    rerun_incident_correlation,
    update_incident,
)

logger = logging.getLogger("accc.api.incidents")

router = APIRouter(tags=["incidents"])


class IncidentPatchRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[UUID] = None
    analyst_notes: Optional[str] = None

class DeepInvestigateRequest(BaseModel):
    analyst_query: str

@router.get("/incidents", tags=["incidents"])
async def incidents_list(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[UUID] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user
    try:
        return await list_incidents(
            db=db,
            status=status,
            severity=severity,
            assigned_to=assigned_to,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.exception("Failed to list incidents: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to list incidents: {str(exc)}") from exc


@router.get("/incidents/{incident_id}", tags=["incidents"])
async def incident_detail(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user
    try:
        return await get_incident_detail(db=db, incident_id=incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to fetch incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch incident: {str(exc)}") from exc


@router.patch("/incidents/{incident_id}", tags=["incidents"])
async def patch_incident(
    incident_id: UUID,
    patch: IncidentPatchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    patch_data = patch.model_dump(exclude_unset=True)
    if not patch_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    try:
        return await update_incident(
            db=db,
            incident_id=incident_id,
            patch_data=patch_data,
            updated_by=current_user["username"],
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    except Exception as exc:
        logger.exception("Failed to patch incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to update incident: {str(exc)}") from exc


@router.get("/incidents/{incident_id}/timeline", tags=["incidents"])
async def incident_timeline(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user
    try:
        return await get_incident_timeline(db=db, incident_id=incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to fetch incident timeline %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch incident timeline: {str(exc)}") from exc


@router.get("/incidents/{incident_id}/report", tags=["incidents"])
async def incident_report(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user
    try:
        return await get_incident_report(db=db, incident_id=incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to generate report for incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to generate incident report: {str(exc)}") from exc


@router.post("/incidents/{incident_id}/correlate", tags=["incidents"])
async def incident_correlate(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("senior_analyst")),
):
    try:
        return await rerun_incident_correlation(
            db=db,
            incident_id=incident_id,
            requested_by=current_user["username"],
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "not found" in message.lower() else 400
        raise HTTPException(status_code=status_code, detail=message) from exc
    except Exception as exc:
        logger.exception("Failed to re-correlate incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to re-correlate incident: {str(exc)}") from exc
    
    @router.post("/incidents/{incident_id}/deep-investigate", tags=["incidents"])
async def deep_investigate_incident(
    incident_id: UUID,
    payload: DeepInvestigateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("senior_analyst")),
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id).limit(1)
    )
    incident = result.scalars().first()

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    run_id = str(UUID(int=UUID(str(incident.id)).int ^ UUID(int=0).int)) if False else None
    # Simpler/clearer UUID generation:
    from uuid import uuid4
    run_id = str(uuid4())

    incident_context = {
        "incident_id": str(incident.id),
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "description": incident.description,
        "summary": incident.ai_summary,
        "assigned_to": str(incident.assigned_to) if incident.assigned_to else None,
        "recommendations": incident.ai_recommendations or [],
        "ioc_ips": [str(ip) for ip in (incident.ioc_ips or [])],
        "mitre_tactics": incident.mitre_tactics or [],
        "mitre_techniques": incident.mitre_techniques or [],
        "kill_chain_stage": incident.kill_chain_stage,
        "attack_type": incident.attack_type,
    }

    asyncio.create_task(
        run_react_investigation(
            run_id=run_id,
            analyst_query=payload.analyst_query,
            incident_context=incident_context,
        )
    )

    return {
        "run_id": run_id,
        "status": "queued",
        "message": "Investigation started",
    }