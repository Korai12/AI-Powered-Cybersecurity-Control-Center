from __future__ import annotations

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import text

from config import settings
from database import async_session_factory

logger = logging.getLogger("accc.baseline")

BASELINE_TTL_SECONDS = 60 * 60 * 2
DEFAULT_WINDOW_HOURS = 2
DEFAULT_RECENT_MINUTES = 15
MAX_ROWS = 10000


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _baseline_key(entity_type: str, entity_value: str) -> str:
    return f"entity_baseline:{entity_type}:{entity_value}"


def _empty_stats(entity_type: str, entity_value: str) -> dict[str, Any]:
    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "total_events": 0,
        "recent_events": 0,
        "event_types": defaultdict(int),
        "severities": defaultdict(int),
        "dst_ports": defaultdict(int),
        "active_hours": defaultdict(int),
        "first_seen": None,
        "last_seen": None,
    }


def _record_activity(
    stats: dict[str, Any],
    row: dict[str, Any],
    recent_cutoff: datetime,
) -> None:
    ts = row.get("timestamp")
    if not isinstance(ts, datetime):
        return

    stats["total_events"] += 1
    if ts >= recent_cutoff:
        stats["recent_events"] += 1

    event_type = str(row.get("event_type") or "unknown")
    severity = str(row.get("severity") or "unknown").upper()
    dst_port = row.get("dst_port")

    stats["event_types"][event_type] += 1
    stats["severities"][severity] += 1

    if dst_port is not None:
        stats["dst_ports"][str(dst_port)] += 1

    stats["active_hours"][str(ts.hour)] += 1

    first_seen = stats["first_seen"]
    last_seen = stats["last_seen"]

    if first_seen is None or ts < first_seen:
        stats["first_seen"] = ts
    if last_seen is None or ts > last_seen:
        stats["last_seen"] = ts


def _top_items(counter_like: dict[str, int], limit: int = 5) -> list[dict[str, Any]]:
    items = sorted(counter_like.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"name": key, "count": int(value)} for key, value in items[:limit]]


def _build_payload(
    stats: dict[str, Any],
    window_hours: int,
    recent_minutes: int,
) -> dict[str, Any]:
    total_events = int(stats["total_events"])
    recent_events = int(stats["recent_events"])

    baseline_hourly_rate = round(total_events / max(window_hours, 1), 2)
    current_hourly_rate = round((recent_events / max(recent_minutes, 1)) * 60.0, 2)

    anomaly_ratio = 0.0
    if baseline_hourly_rate > 0:
        anomaly_ratio = round(current_hourly_rate / baseline_hourly_rate, 2)

    anomaly = bool(
        total_events >= 4
        and recent_events >= 3
        and baseline_hourly_rate > 0
        and current_hourly_rate >= baseline_hourly_rate * 3
    )

    return {
        "entity_type": stats["entity_type"],
        "entity_value": stats["entity_value"],
        "total_events": total_events,
        "recent_events": recent_events,
        "baseline_hourly_rate": baseline_hourly_rate,
        "current_hourly_rate": current_hourly_rate,
        "anomaly_ratio": anomaly_ratio,
        "anomaly": anomaly,
        "common_event_types": _top_items(dict(stats["event_types"]), limit=5),
        "common_severities": _top_items(dict(stats["severities"]), limit=5),
        "common_dst_ports": _top_items(dict(stats["dst_ports"]), limit=5),
        "active_hours": _top_items(dict(stats["active_hours"]), limit=8),
        "first_seen": _iso(stats["first_seen"]),
        "last_seen": _iso(stats["last_seen"]),
        "window_hours": window_hours,
        "recent_minutes": recent_minutes,
    }


async def refresh_baselines(
    window_hours: int = DEFAULT_WINDOW_HOURS,
    recent_minutes: int = DEFAULT_RECENT_MINUTES,
) -> dict[str, Any]:
    now = _utc_now()
    recent_cutoff = now - timedelta(minutes=recent_minutes)

    async with async_session_factory() as db:
        result = await db.execute(
            text(
                """
                SELECT
                    timestamp,
                    host(src_ip) AS src_ip,
                    host(dst_ip) AS dst_ip,
                    dst_port,
                    username,
                    hostname,
                    event_type,
                    severity
                FROM events
                WHERE timestamp >= NOW() - (:window_hours * INTERVAL '1 hour')
                ORDER BY timestamp DESC
                LIMIT :max_rows
                """
            ),
            {
                "window_hours": int(window_hours),
                "max_rows": MAX_ROWS,
            },
        )
        rows = result.mappings().all()

    entities: dict[tuple[str, str], dict[str, Any]] = {}

    def ensure(entity_type: str, entity_value: str | None) -> dict[str, Any] | None:
        value = (entity_value or "").strip()
        if not value:
            return None
        key = (entity_type, value)
        if key not in entities:
            entities[key] = _empty_stats(entity_type, value)
        return entities[key]

    for row in rows:
        row_dict = dict(row)

        stats_ip = ensure("ip", row_dict.get("src_ip"))
        if stats_ip is not None:
            _record_activity(stats_ip, row_dict, recent_cutoff)

        stats_user = ensure("user", row_dict.get("username"))
        if stats_user is not None:
            _record_activity(stats_user, row_dict, recent_cutoff)

        stats_host = ensure("host", row_dict.get("hostname"))
        if stats_host is not None:
            _record_activity(stats_host, row_dict, recent_cutoff)

    payloads = [
        _build_payload(stats, window_hours=window_hours, recent_minutes=recent_minutes)
        for stats in entities.values()
    ]
    payloads.sort(key=lambda item: (-item["total_events"], item["entity_type"], item["entity_value"]))

    anomalies = [
        {
            "entity_type": item["entity_type"],
            "entity_value": item["entity_value"],
            "recent_events": item["recent_events"],
            "total_events": item["total_events"],
            "baseline_hourly_rate": item["baseline_hourly_rate"],
            "current_hourly_rate": item["current_hourly_rate"],
            "anomaly_ratio": item["anomaly_ratio"],
            "common_event_types": item["common_event_types"],
            "common_severities": item["common_severities"],
            "last_seen": item["last_seen"],
        }
        for item in payloads
        if item["anomaly"]
    ]
    anomalies.sort(key=lambda item: (-item["anomaly_ratio"], -item["recent_events"], item["entity_type"], item["entity_value"]))

    summary = {
        "status": "ok",
        "refreshed_at": _iso(now),
        "window_hours": int(window_hours),
        "recent_minutes": int(recent_minutes),
        "events_scanned": len(rows),
        "entities_processed": len(payloads),
        "anomalies_detected": len(anomalies),
        "ttl_seconds": BASELINE_TTL_SECONDS,
    }

    redis_client = None
    try:
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

        for payload in payloads:
            await redis_client.setex(
                _baseline_key(payload["entity_type"], payload["entity_value"]),
                BASELINE_TTL_SECONDS,
                json.dumps(payload),
            )

        await redis_client.setex(
            "entity_baseline:last_refresh",
            BASELINE_TTL_SECONDS,
            json.dumps(summary),
        )
        await redis_client.setex(
            "entity_baseline:anomalies",
            BASELINE_TTL_SECONDS,
            json.dumps(anomalies),
        )
        await redis_client.setex(
            "entity_baseline:samples",
            BASELINE_TTL_SECONDS,
            json.dumps(payloads[:25]),
        )
    except Exception as exc:
        logger.warning("Baseline refresh Redis write skipped: %s", exc)
        summary["redis_write"] = "skipped"
        summary["redis_error"] = str(exc)
    finally:
        if redis_client is not None:
            await redis_client.aclose()

    return summary


async def get_baseline_snapshot(limit: int = 8) -> dict[str, Any]:
    redis_client = None
    try:
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

        raw_summary = await redis_client.get("entity_baseline:last_refresh")
        raw_anomalies = await redis_client.get("entity_baseline:anomalies")
        raw_samples = await redis_client.get("entity_baseline:samples")

        summary = json.loads(raw_summary) if raw_summary else {
            "status": "empty",
            "entities_processed": 0,
            "anomalies_detected": 0,
            "window_hours": DEFAULT_WINDOW_HOURS,
            "recent_minutes": DEFAULT_RECENT_MINUTES,
        }
        anomalies = json.loads(raw_anomalies) if raw_anomalies else []
        samples = json.loads(raw_samples) if raw_samples else []

        return {
            "summary": summary,
            "anomalies_count": len(anomalies),
            "sample_anomalies": anomalies[:limit],
            "sample_entities": samples[:limit],
        }
    except Exception as exc:
        logger.warning("Baseline snapshot read failed: %s", exc)
        return {
            "summary": {
                "status": "error",
                "entities_processed": 0,
                "anomalies_detected": 0,
                "window_hours": DEFAULT_WINDOW_HOURS,
                "recent_minutes": DEFAULT_RECENT_MINUTES,
                "error": str(exc),
            },
            "anomalies_count": 0,
            "sample_anomalies": [],
            "sample_entities": [],
        }
    finally:
        if redis_client is not None:
            await redis_client.aclose()


async def get_dashboard_anomalies(limit: int = 8) -> list[dict[str, Any]]:
    redis_client = None
    try:
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        raw_anomalies = await redis_client.get("entity_baseline:anomalies")
        anomalies = json.loads(raw_anomalies) if raw_anomalies else []
        return anomalies[:limit]
    except Exception as exc:
        logger.warning("Baseline anomalies read failed: %s", exc)
        return []
    finally:
        if redis_client is not None:
            await redis_client.aclose()