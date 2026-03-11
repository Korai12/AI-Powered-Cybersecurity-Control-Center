"""Events API — G-08 complete endpoint list for events.

GET    /api/v1/events          — list with filters
GET    /api/v1/events/stats    — counts by severity/type
GET    /api/v1/events/{id}     — single event
POST   /api/v1/events/ingest   — single event ingest
POST   /api/v1/events/ingest/batch — batch ingest
PATCH  /api/v1/events/{id}/triage  — update triage status
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from services.ingestion.normalizer import normalize

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class IngestRequest(BaseModel):
    raw_log: str
    source_format: Optional[str] = None  # hint — auto-detected if None


class IngestBatchRequest(BaseModel):
    logs: list[str]
    source_format: Optional[str] = None


class TriageUpdate(BaseModel):
    triage_status: Optional[str] = None   # pending|triaged|escalated|closed
    is_false_positive: Optional[bool] = None
    ai_triage_notes: Optional[str] = None


class IngestResponse(BaseModel):
    event_id: str
    severity: str
    event_type: str
    triage_status: str = "pending"


class BatchIngestResponse(BaseModel):
    ingested: int
    failed: int
    event_ids: list[str]


# ── Helper ────────────────────────────────────────────────────────────────────

async def _insert_event(db: AsyncSession, ces) -> str:
    """Insert a CommonEvent into the events table, return UUID string."""
    d = ces.to_db_dict()
    result = await db.execute(text("""
        INSERT INTO events (
            timestamp, source_format, source_identifier, event_type, severity,
            raw_log, src_ip, dst_ip, src_port, dst_port, protocol,
            username, hostname, process_name, file_hash, action, rule_id,
            geo_country, geo_city, geo_lat, geo_lon, abuse_score,
            relevant_cves, mitre_tactic, mitre_technique,
            severity_score, tags, triage_status
        ) VALUES (
            :timestamp, :source_format, :source_identifier, :event_type, :severity,
            :raw_log, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
            :username, :hostname, :process_name, :file_hash, :action, :rule_id,
            :geo_country, :geo_city, :geo_lat, :geo_lon, :abuse_score,
            :relevant_cves, :mitre_tactic, :mitre_technique,
            :severity_score, :tags, :triage_status
        )
        RETURNING id
    """), {**d,
           "relevant_cves": d.get("relevant_cves") or [],
           "tags": d.get("tags") or []})
    row = result.fetchone()
    await db.commit()
    return str(row[0])


async def _publish_to_redis(event_id: str, severity: str, event_type: str):
    """Publish new event to Redis pub/sub for WebSocket bridge (Phase 4)."""
    try:
        import redis.asyncio as aioredis, os, json
        r = await aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379"))
        await r.publish("accc:events:new", json.dumps({
            "event_id": event_id, "severity": severity, "event_type": event_type
        }))
        await r.aclose()
    except Exception as exc:
        logger.debug("Redis publish skipped: %s", exc)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/events/ingest", response_model=IngestResponse, tags=["events"])
async def ingest_event(
    req: IngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single raw log. Auto-detects format, normalises to CES, stores."""
    ces = normalize(req.raw_log)
    event_id = await _insert_event(db, ces)
    background_tasks.add_task(_publish_to_redis, event_id, ces.severity, ces.event_type)
    return IngestResponse(
        event_id=event_id,
        severity=ces.severity,
        event_type=ces.event_type,
    )


@router.post("/events/ingest/batch", response_model=BatchIngestResponse, tags=["events"])
async def ingest_batch(
    req: IngestBatchRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Batch ingest up to 1000 events."""
    if len(req.logs) > 1000:
        raise HTTPException(status_code=400, detail="Batch limit is 1000 events")

    ids, failed = [], 0
    for raw in req.logs:
        try:
            ces = normalize(raw)
            eid = await _insert_event(db, ces)
            ids.append(eid)
            background_tasks.add_task(_publish_to_redis, eid, ces.severity, ces.event_type)
        except Exception as exc:
            logger.warning("Batch ingest item failed: %s", exc)
            failed += 1

    return BatchIngestResponse(ingested=len(ids), failed=failed, event_ids=ids)


@router.get("/events", tags=["events"])
async def list_events(
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    triage_status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    time_range: Optional[int] = Query(None, description="Last N minutes"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List events with optional filters."""
    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity.upper()
    if event_type:
        conditions.append("event_type = :event_type")
        params["event_type"] = event_type
    if triage_status:
        conditions.append("triage_status = :triage_status")
        params["triage_status"] = triage_status
    if source:
        conditions.append("source_identifier ILIKE :source")
        params["source"] = f"%{source}%"
    if time_range:
        conditions.append("timestamp >= NOW() - INTERVAL ':time_range minutes'")
        params["time_range"] = time_range

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    result = await db.execute(text(f"""
        SELECT id, timestamp, source_format, source_identifier, event_type,
               severity, src_ip, dst_ip, username, hostname, triage_status,
               mitre_tactic, mitre_technique, severity_score, tags, incident_id
        FROM events
        {where}
        ORDER BY timestamp DESC
        LIMIT :limit OFFSET :offset
    """), params)

    rows = result.mappings().all()
    count_result = await db.execute(text(f"SELECT COUNT(*) FROM events {where}"), params)
    total = count_result.scalar()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [_row_to_dict(r) for r in rows],
    }


@router.get("/events/stats", tags=["events"])
async def event_stats(
    time_range: int = Query(60, description="Last N minutes"),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated event counts for dashboard KPIs."""
    result = await db.execute(text("""
        SELECT
            COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical_count,
            COUNT(*) FILTER (WHERE severity='HIGH')     AS high_count,
            COUNT(*) FILTER (WHERE severity='MEDIUM')   AS medium_count,
            COUNT(*) FILTER (WHERE severity='LOW')      AS low_count,
            COUNT(*) FILTER (WHERE triage_status='pending') AS pending_count,
            COUNT(*) FILTER (WHERE is_false_positive=TRUE)  AS false_positive_count,
            COUNT(*) AS total_count
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '1 hour' * :hours
    """), {"hours": time_range / 60})
    row = result.mappings().fetchone()

    by_type = await db.execute(text("""
        SELECT event_type, COUNT(*) as count
        FROM events
        WHERE timestamp >= NOW() - INTERVAL '1 hour' * :hours
        GROUP BY event_type
        ORDER BY count DESC
        LIMIT 10
    """), {"hours": time_range / 60})

    return {
        "time_range_minutes": time_range,
        "counts": dict(row) if row else {},
        "top_event_types": [{"type": r.event_type, "count": r.count}
                             for r in by_type.fetchall()],
    }


@router.get("/events/{event_id}", tags=["events"])
async def get_event(event_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get single event with full detail."""
    result = await db.execute(
        text("SELECT * FROM events WHERE id = :id"), {"id": str(event_id)}
    )
    row = result.mappings().fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return _row_to_dict(row)


@router.patch("/events/{event_id}/triage", tags=["events"])
async def triage_event(
    event_id: UUID,
    update: TriageUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update triage status, false-positive flag, or AI notes for an event."""
    updates, params = [], {"id": str(event_id)}
    if update.triage_status is not None:
        valid = {"pending", "triaged", "escalated", "closed"}
        if update.triage_status not in valid:
            raise HTTPException(status_code=400, detail=f"triage_status must be one of {valid}")
        updates.append("triage_status = :triage_status")
        params["triage_status"] = update.triage_status
    if update.is_false_positive is not None:
        updates.append("is_false_positive = :is_fp")
        params["is_fp"] = update.is_false_positive
    if update.ai_triage_notes is not None:
        updates.append("ai_triage_notes = :notes")
        params["notes"] = update.ai_triage_notes

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    result = await db.execute(
        text(f"UPDATE events SET {', '.join(updates)} WHERE id = :id RETURNING id"),
        params,
    )
    if not result.fetchone():
        raise HTTPException(status_code=404, detail="Event not found")
    await db.commit()
    return {"status": "updated", "event_id": str(event_id)}


def _row_to_dict(row) -> dict:
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        elif hasattr(v, "__str__") and not isinstance(v, (str, int, float, bool, list, dict, type(None))):
            d[k] = str(v)
    return d