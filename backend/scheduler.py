from __future__ import annotations

"""
APScheduler orchestration for ACCC.
Phase 2.4 completes the full scheduler registration set while keeping
later-phase jobs safe to run before their full implementations exist.
"""

import asyncio
import importlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import text

from config import settings
from database import async_session_factory

logger = logging.getLogger("accc.scheduler")

_scheduler = AsyncIOScheduler(timezone="UTC")
BASELINE_TTL_SECONDS = 60 * 60 * 2


async def _call_optional(module_name: str, func_name: str, *args, **kwargs) -> dict[str, Any]:
    try:
        module = importlib.import_module(module_name)
        func = getattr(module, func_name)
    except (ModuleNotFoundError, AttributeError) as exc:
        logger.info("Scheduler job skipped — %s.%s unavailable: %s", module_name, func_name, exc)
        return {"status": "skipped", "reason": f"{module_name}.{func_name} unavailable"}

    try:
        result = func(*args, **kwargs)
        if asyncio.iscoroutine(result):
            result = await result
        return {"status": "ok", "result": result}
    except Exception as exc:
        logger.exception("Scheduler job failed for %s.%s: %s", module_name, func_name, exc)
        return {"status": "error", "reason": str(exc)}


async def job_alert_triage() -> dict[str, Any]:
    return await _call_optional("services.ai.triage", "triage_pending_events", limit=25)


async def job_correlation_engine() -> dict[str, Any]:
    return await _call_optional("services.ai.correlation", "run_correlation_pass")


async def job_baseline_refresh() -> dict[str, Any]:
    query = text(
        """
        WITH entities AS (
            SELECT 'src_ip' AS entity_type,
                   host(src_ip) AS entity_value,
                   COUNT(*)::int AS total_count,
                   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '15 minutes')::int AS recent_15m_count
            FROM events
            WHERE timestamp >= NOW() - INTERVAL '2 hours' AND src_ip IS NOT NULL
            GROUP BY host(src_ip)

            UNION ALL

            SELECT 'username' AS entity_type,
                   username AS entity_value,
                   COUNT(*)::int AS total_count,
                   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '15 minutes')::int AS recent_15m_count
            FROM events
            WHERE timestamp >= NOW() - INTERVAL '2 hours' AND username IS NOT NULL AND username <> ''
            GROUP BY username

            UNION ALL

            SELECT 'hostname' AS entity_type,
                   hostname AS entity_value,
                   COUNT(*)::int AS total_count,
                   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '15 minutes')::int AS recent_15m_count
            FROM events
            WHERE timestamp >= NOW() - INTERVAL '2 hours' AND hostname IS NOT NULL AND hostname <> ''
            GROUP BY hostname
        )
        SELECT entity_type, entity_value, total_count, recent_15m_count
        FROM entities
        WHERE entity_value IS NOT NULL AND entity_value <> ''
        ORDER BY total_count DESC
        """
    )

    entities_processed = 0
    anomalies_detected = 0
    samples: list[dict[str, Any]] = []

    async with async_session_factory() as db:
        result = await db.execute(query)
        rows = result.mappings().all()

    try:
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    except Exception as exc:
        logger.warning("Baseline refresh Redis unavailable: %s", exc)
        redis_client = None

    for row in rows:
        total_count = int(row["total_count"] or 0)
        recent_15m_count = int(row["recent_15m_count"] or 0)
        baseline_hourly_rate = round(total_count / 2.0, 2)
        current_hourly_rate = round(recent_15m_count * 4.0, 2)
        ratio = round(current_hourly_rate / baseline_hourly_rate, 2) if baseline_hourly_rate > 0 else None
        anomaly = bool(
            recent_15m_count >= 3
            and baseline_hourly_rate > 0
            and current_hourly_rate >= baseline_hourly_rate * 3
        )

        payload = {
            "entity_type": row["entity_type"],
            "entity_value": row["entity_value"],
            "window_hours": 2,
            "total_count": total_count,
            "recent_15m_count": recent_15m_count,
            "baseline_hourly_rate": baseline_hourly_rate,
            "current_hourly_rate": current_hourly_rate,
            "ratio": ratio,
            "anomaly": anomaly,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        entities_processed += 1

        if anomaly:
            anomalies_detected += 1
            logger.warning(
                "Baseline anomaly: %s=%s current=%s baseline=%s ratio=%s",
                payload["entity_type"],
                payload["entity_value"],
                payload["current_hourly_rate"],
                payload["baseline_hourly_rate"],
                payload["ratio"],
            )

        if len(samples) < 5:
            samples.append(payload)

        if redis_client is not None:
            try:
                await redis_client.setex(
                    f"entity_baseline:{payload['entity_type']}:{payload['entity_value']}",
                    BASELINE_TTL_SECONDS,
                    json.dumps(payload, ensure_ascii=False),
                )
            except Exception as exc:
                logger.debug(
                    "Failed to cache baseline for %s=%s: %s",
                    payload["entity_type"],
                    payload["entity_value"],
                    exc,
                )

    summary = {
        "job": "baseline_refresh",
        "status": "ok",
        "entities_processed": entities_processed,
        "anomalies_detected": anomalies_detected,
        "sample": samples,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    if redis_client is not None:
        try:
            await redis_client.setex(
                "entity_baseline:last_refresh",
                BASELINE_TTL_SECONDS,
                json.dumps(summary, ensure_ascii=False),
            )
            await redis_client.aclose()
        except Exception:
            pass

    return summary


async def job_threat_hunting() -> dict[str, Any]:
    return await _call_optional("services.ai.hunt", "run_scheduled_hunt")


async def job_security_posture() -> dict[str, Any]:
    return await _call_optional("services.posture_score", "compute_and_cache_posture_score")


async def job_entity_graph_update() -> dict[str, Any]:
    return await _call_optional("services.entity_service", "refresh_entity_graph")


async def job_abuseipdb_cache_cleanup() -> dict[str, Any]:
    try:
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await r.set("abuseipdb:daily_count", 0)
        await r.set("abuseipdb:last_reset", datetime.now(timezone.utc).isoformat())
        await r.aclose()
        return {"status": "ok", "counter_reset": True}
    except Exception as exc:
        logger.warning("AbuseIPDB cache cleanup skipped: %s", exc)
        return {"status": "skipped", "reason": str(exc)}


async def job_close_stale_incidents() -> dict[str, Any]:
    async with async_session_factory() as db:
        result = await db.execute(
            text(
                """
                UPDATE incidents
                SET status = 'closed',
                    resolved_at = COALESCE(resolved_at, NOW()),
                    updated_at = NOW()
                WHERE status IN ('open', 'investigating', 'triaged')
                  AND updated_at < NOW() - INTERVAL '7 days'
                RETURNING id
                """
            )
        )
        rows = result.fetchall()
        await db.commit()

    return {"status": "ok", "closed_count": len(rows)}


async def trigger_analyst_hunt(analyst_id: str, hypothesis: str) -> str:
    import uuid

    hunt_id = str(uuid.uuid4())
    asyncio.create_task(_run_analyst_hunt(hunt_id, analyst_id, hypothesis))
    return hunt_id


async def _run_analyst_hunt(hunt_id: str, analyst_id: str, hypothesis: str) -> None:
    result = await _call_optional(
        "services.ai.hunt",
        "run_analyst_triggered_hunt",
        hunt_id,
        analyst_id,
        hypothesis,
    )
    if result.get("status") == "skipped":
        logger.info("Analyst hunt %s queued but hunt service is not implemented yet", hunt_id)


def get_registered_jobs() -> list[dict[str, Any]]:
    jobs = []
    for job in _scheduler.get_jobs():
        jobs.append(
            {
                "id": job.id,
                "name": job.name,
                "trigger": str(job.trigger),
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
            }
        )
    return jobs


async def start_scheduler() -> None:
    if _scheduler.running:
        logger.info("APScheduler already running — skipping duplicate start")
        return

    _scheduler.add_job(
        job_alert_triage,
        IntervalTrigger(seconds=30),
        id="alert_triage",
        replace_existing=True,
        misfire_grace_time=10,
    )
    _scheduler.add_job(
        job_correlation_engine,
        IntervalTrigger(minutes=2),
        id="correlation_pass",
        replace_existing=True,
        misfire_grace_time=30,
    )
    _scheduler.add_job(
        job_baseline_refresh,
        IntervalTrigger(minutes=15),
        id="baseline_refresh",
        replace_existing=True,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        job_threat_hunting,
        IntervalTrigger(minutes=30),
        id="scheduled_hunt",
        replace_existing=True,
        misfire_grace_time=120,
    )
    _scheduler.add_job(
        job_security_posture,
        IntervalTrigger(minutes=15),
        id="posture_score",
        replace_existing=True,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        job_entity_graph_update,
        IntervalTrigger(minutes=5),
        id="entity_graph_refresh",
        replace_existing=True,
        misfire_grace_time=30,
    )
    _scheduler.add_job(
        job_abuseipdb_cache_cleanup,
        CronTrigger(hour=0, minute=0),
        id="abuseipdb_daily_reset",
        replace_existing=True,
    )
    _scheduler.add_job(
        job_close_stale_incidents,
        CronTrigger(hour=2, minute=0),
        id="stale_incident_cleanup",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info("APScheduler started — %s jobs registered", len(_scheduler.get_jobs()))


async def stop_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")