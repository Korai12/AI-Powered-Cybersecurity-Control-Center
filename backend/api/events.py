from __future__ import annotations
from api.dependencies import get_current_user, assert_can_triage_alerts
import json
import logging
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user
from database import get_db
from services.ai.triage import triage_event_by_id
from services.ingestion.enrichment import enrich_event_after_ingest
from services.ingestion.normalizer import normalize

logger = logging.getLogger(__name__)
router = APIRouter()


class IngestRequest(BaseModel):
    raw_log: str
    source_format: Optional[str] = None


class IngestBatchRequest(BaseModel):
    logs: list[str]
    source_format: Optional[str] = None


class TriageUpdate(BaseModel):
    triage_status: Optional[str] = None
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


def _parse_time_range_to_minutes(value: Optional[str | int]) -> int:
    if value is None:
        return 60
    if isinstance(value, int):
        return value

    raw = str(value).strip().lower()
    if raw.isdigit():
        return int(raw)
    if raw.endswith("m") and raw[:-1].isdigit():
        return int(raw[:-1])
    if raw.endswith("h") and raw[:-1].isdigit():
        return int(raw[:-1]) * 60
    if raw.endswith("d") and raw[:-1].isdigit():
        return int(raw[:-1]) * 60 * 24

    return 60


def _serialise_scalar(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)

    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return value

    if isinstance(value, (list, tuple)):
        return [_serialise_scalar(item) for item in value]

    if value.__class__.__name__ in {"IPv4Address", "IPv6Address"}:
        return str(value)

    return value


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {key: _serialise_scalar(value) for key, value in dict(row).items()}


async def _insert_event(db: AsyncSession, ces) -> str:
    d = ces.to_db_dict()
    result = await db.execute(
        text(
            """
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
            """
        ),
        {
            **d,
            "relevant_cves": d.get("relevant_cves") or [],
            "tags": d.get("tags") or [],
        },
    )
    row = result.fetchone()
    await db.commit()
    return str(row[0])


async def _publish_to_redis(event_id: str, severity: str, event_type: str):
    try:
        import os

        import redis.asyncio as aioredis

        r = await aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379"))
        await r.publish(
            "accc:events:new",
            json.dumps(
                {
                    "event_id": event_id,
                    "severity": severity,
                    "event_type": event_type,
                    "published_at": datetime.utcnow().isoformat() + "Z",
                }
            ),
        )
        await r.aclose()
    except Exception as exc:
        logger.debug("Redis publish skipped: %s", exc)


async def _ingest_one(raw_log: str, db: AsyncSession, background_tasks: BackgroundTasks) -> tuple[str, Any]:
    ces = normalize(raw_log)
    event_id = await _insert_event(db, ces)

    background_tasks.add_task(_publish_to_redis, event_id, ces.severity, ces.event_type)
    background_tasks.add_task(enrich_event_after_ingest, event_id)

    return event_id, ces


@router.post("/events/ingest", response_model=IngestResponse, tags=["events"])
async def ingest_event(
    req: IngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    event_id, ces = await _ingest_one(req.raw_log, db, background_tasks)

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
    if len(req.logs) > 1000:
        raise HTTPException(status_code=400, detail="Batch limit is 1000 events")

    ids: list[str] = []
    failed = 0

    for raw in req.logs:
        try:
            event_id, _ = await _ingest_one(raw, db, background_tasks)
            ids.append(event_id)
        except Exception as exc:
            logger.warning("Batch ingest item failed: %s", exc)
            failed += 1

    return BatchIngestResponse(ingested=len(ids), failed=failed, event_ids=ids)


@router.post("/events/upload", tags=["events"])
async def upload_events_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    del current_user

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    text_content = raw_bytes.decode("utf-8", errors="ignore").strip()
    if not text_content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    logs: list[str] = []

    if file.filename and file.filename.lower().endswith(".json"):
        try:
            parsed = json.loads(text_content)
            if isinstance(parsed, list):
                logs = [json.dumps(item) if not isinstance(item, str) else item for item in parsed]
            elif isinstance(parsed, dict):
                logs = [json.dumps(parsed)]
            else:
                logs = [text_content]
        except json.JSONDecodeError:
            logs = [line for line in text_content.splitlines() if line.strip()]
    else:
        logs = [line for line in text_content.splitlines() if line.strip()]

    if not logs:
        raise HTTPException(status_code=400, detail="No ingestible records found in uploaded file")

    if len(logs) > 1000:
        raise HTTPException(status_code=400, detail="Upload limit is 1000 events")

    ingested_ids: list[str] = []
    failed = 0

    for raw in logs:
        try:
            event_id, _ = await _ingest_one(raw, db, background_tasks)
            ingested_ids.append(event_id)
        except Exception as exc:
            logger.warning("Upload ingest failed: %s", exc)
            failed += 1

    return {
        "filename": file.filename,
        "ingested": len(ingested_ids),
        "failed": failed,
        "event_ids": ingested_ids,
    }


@router.get("/events", tags=["events"])
async def list_events(
    severity: Optional[str] = Query(None, description="Single severity or comma-separated severities"),
    event_type: Optional[str] = Query(None),
    type_: Optional[str] = Query(None, alias="type"),
    triage_status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    time_range: Optional[str] = Query(None, description="Examples: 60, 60m, 24h, 7d"),
    geo: bool = Query(False, description="Only return events with geo coordinates"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    conditions: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if severity:
        severities = [item.strip().upper() for item in severity.split(",") if item.strip()]
        if severities:
            placeholders = []
            for index, item in enumerate(severities):
                key = f"severity_{index}"
                params[key] = item
                placeholders.append(f":{key}")
            conditions.append(f"severity IN ({', '.join(placeholders)})")

    requested_event_type = event_type or type_
    if requested_event_type:
        types = [item.strip() for item in requested_event_type.split(",") if item.strip()]
        if types:
            placeholders = []
            for index, item in enumerate(types):
                key = f"event_type_{index}"
                params[key] = item
                placeholders.append(f":{key}")
            conditions.append(f"event_type IN ({', '.join(placeholders)})")

    if triage_status:
        conditions.append("triage_status = :triage_status")
        params["triage_status"] = triage_status

    if source:
        conditions.append("source_identifier ILIKE :source")
        params["source"] = f"%{source}%"

    if time_range:
        params["time_range"] = _parse_time_range_to_minutes(time_range)
        conditions.append("timestamp >= NOW() - (:time_range * INTERVAL '1 minute')")

    if geo:
        conditions.append("geo_lat IS NOT NULL AND geo_lon IS NOT NULL")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    result = await db.execute(
        text(
            f"""
            SELECT id, timestamp, ingested_at, source_format, source_identifier, event_type,
                   severity, raw_log, src_ip, dst_ip, src_port, dst_port, protocol,
                   username, hostname, process_name, file_hash, action, rule_id,
                   geo_country, geo_city, geo_lat, geo_lon, abuse_score,
                   relevant_cves, mitre_tactic, mitre_technique, severity_score,
                   is_false_positive, incident_id, triage_status, ai_triage_notes, tags
            FROM events
            {where}
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        params,
    )
    rows = result.mappings().all()

    count_params = {k: v for k, v in params.items() if k not in {"limit", "offset"}}
    count_result = await db.execute(text(f"SELECT COUNT(*) FROM events {where}"), count_params)
    total = int(count_result.scalar() or 0)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [_row_to_dict(row) for row in rows],
    }


@router.get("/events/stats", tags=["events"])
async def event_stats(
    time_range: str = Query("60", description="Examples: 60, 60m, 24h, 7d"),
    db: AsyncSession = Depends(get_db),
):
    minutes = _parse_time_range_to_minutes(time_range)

    result = await db.execute(
        text(
            """
            SELECT
                COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical_count,
                COUNT(*) FILTER (WHERE severity='HIGH')     AS high_count,
                COUNT(*) FILTER (WHERE severity='MEDIUM')   AS medium_count,
                COUNT(*) FILTER (WHERE severity='LOW')      AS low_count,
                COUNT(*) FILTER (WHERE severity='INFO')     AS info_count,
                COUNT(*) FILTER (WHERE triage_status='pending') AS pending_count,
                COUNT(*) FILTER (WHERE is_false_positive=TRUE)  AS false_positive_count,
                COUNT(*) AS total_count
            FROM events
            WHERE timestamp >= NOW() - (:minutes * INTERVAL '1 minute')
            """
        ),
        {"minutes": minutes},
    )
    row = result.mappings().fetchone()

    by_type = await db.execute(
        text(
            """
            SELECT event_type, COUNT(*) as count
            FROM events
            WHERE timestamp >= NOW() - (:minutes * INTERVAL '1 minute')
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
            """
        ),
        {"minutes": minutes},
    )
    type_rows = by_type.fetchall()

    trend = await db.execute(
        text(
            """
            SELECT
                date_trunc('hour', timestamp) AS bucket,
                COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity='HIGH') AS high,
                COUNT(*) FILTER (WHERE severity='MEDIUM') AS medium,
                COUNT(*) FILTER (WHERE severity='LOW') AS low,
                COUNT(*) FILTER (WHERE severity='INFO') AS info,
                COUNT(*) AS total
            FROM events
            WHERE timestamp >= NOW() - (:minutes * INTERVAL '1 minute')
            GROUP BY 1
            ORDER BY 1
            """
        ),
        {"minutes": minutes},
    )

    counts = {key: int(value or 0) for key, value in dict(row or {}).items()}

    return {
        "time_range_minutes": minutes,
        "counts": counts,
        "top_event_types": [{"type": r.event_type, "count": r.count} for r in type_rows],
        "event_type_distribution": [
            {"name": r.event_type or "unknown", "value": int(r.count or 0)} for r in type_rows
        ],
        "severity_trend": [
            {
                "bucket": item["bucket"].isoformat() if item["bucket"] else None,
                "CRITICAL": int(item["critical"] or 0),
                "HIGH": int(item["high"] or 0),
                "MEDIUM": int(item["medium"] or 0),
                "LOW": int(item["low"] or 0),
                "INFO": int(item["info"] or 0),
                "total": int(item["total"] or 0),
            }
            for item in trend.mappings().all()
        ],
    }


@router.get("/events/{event_id}/triage", tags=["events"])
async def run_ai_triage(
    event_id: UUID,
    force: bool = Query(False, description="Re-run AI triage even if the event is already triaged"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        return await triage_event_by_id(
            db=db,
            event_id=str(event_id),
            analyst_id=current_user["id"],
            force=force,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("AI triage failed for %s: %s", event_id, exc)
        raise HTTPException(status_code=500, detail=f"AI triage failed: {str(exc)}") from exc


@router.get("/events/{event_id}", tags=["events"])
async def get_event(event_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        text("SELECT * FROM events WHERE id = :id"),
        {"id": str(event_id)},
    )
    row = result.mappings().fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return _row_to_dict(row)


@router.patch("/events/{event_id}/triage", tags=["events"])
async def update_triage_fields(
    event_id: UUID,
    update: TriageUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    updates = []
    params = {"id": str(event_id)}

    if update.triage_status is not None:
        valid = {"pending", "triaged", "escalated", "closed"}
        if update.triage_status not in valid:
            raise HTTPException(status_code=400, detail=f"triage_status must be one of {valid}")
        updates.append("triage_status = :triage_status")
        params["triage_status"] = update.triage_status

    if update.is_false_positive is not None:
        updates.append("is_false_positive = :is_false_positive")
        params["is_false_positive"] = update.is_false_positive

    if update.ai_triage_notes is not None:
        updates.append("ai_triage_notes = :ai_triage_notes")
        params["ai_triage_notes"] = update.ai_triage_notes

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    result = await db.execute(
        text(f"UPDATE events SET {', '.join(updates)} WHERE id = :id RETURNING id"),
        params,
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    await db.commit()
    return {"status": "updated", "event_id": str(event_id), "updated_by": current_user["username"]}