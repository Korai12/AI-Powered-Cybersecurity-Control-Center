from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user
from database import get_db
from services.baseline import get_baseline_snapshot, get_dashboard_anomalies

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_dashboard_summary(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    del current_user

    kpi_result = await db.execute(
        text(
            """
            SELECT
                COUNT(*) AS total_events,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_events,
                COUNT(*) FILTER (WHERE severity = 'HIGH') AS high_events,
                COUNT(*) FILTER (WHERE triage_status IN ('pending', 'escalated')) AS active_alerts
            FROM events
            WHERE timestamp >= NOW() - (:hours * INTERVAL '1 hour')
            """
        ),
        {"hours": hours},
    )
    kpis = dict(kpi_result.mappings().first() or {})

    incidents_result = await db.execute(
        text(
            """
            SELECT
                COUNT(*) FILTER (WHERE status NOT IN ('resolved', 'closed')) AS open_incidents,
                COALESCE(
                    AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60.0)
                        FILTER (WHERE resolved_at IS NOT NULL),
                    0
                ) AS mean_time_to_respond_minutes
            FROM incidents
            """
        )
    )
    incident_metrics = dict(incidents_result.mappings().first() or {})
    kpis.update(incident_metrics)

    trend_result = await db.execute(
        text(
            """
            SELECT
                date_trunc('hour', timestamp) AS bucket,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH') AS high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium,
                COUNT(*) FILTER (WHERE severity = 'LOW') AS low,
                COUNT(*) FILTER (WHERE severity = 'INFO') AS info,
                COUNT(*) AS total
            FROM events
            WHERE timestamp >= NOW() - (:hours * INTERVAL '1 hour')
            GROUP BY 1
            ORDER BY 1 ASC
            """
        ),
        {"hours": hours},
    )
    severity_trend = [
        {
            "bucket": row["bucket"].isoformat() if row["bucket"] else None,
            "CRITICAL": int(row["critical"] or 0),
            "HIGH": int(row["high"] or 0),
            "MEDIUM": int(row["medium"] or 0),
            "LOW": int(row["low"] or 0),
            "INFO": int(row["info"] or 0),
            "total": int(row["total"] or 0),
        }
        for row in trend_result.mappings().all()
    ]

    type_result = await db.execute(
        text(
            """
            SELECT event_type, COUNT(*) AS count
            FROM events
            WHERE timestamp >= NOW() - (:hours * INTERVAL '1 hour')
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 8
            """
        ),
        {"hours": hours},
    )
    event_type_distribution = [
        {"name": row["event_type"] or "unknown", "value": int(row["count"] or 0)}
        for row in type_result.mappings().all()
    ]

    latest_result = await db.execute(
        text(
            """
            SELECT id, timestamp, ingested_at, source_identifier, event_type, severity,
                   src_ip, dst_ip, username, hostname, geo_country, geo_city,
                   geo_lat, geo_lon, abuse_score, relevant_cves, severity_score,
                   triage_status, ai_triage_notes, incident_id
            FROM events
            ORDER BY timestamp DESC
            LIMIT 20
            """
        )
    )
    latest_events = []
    for row in latest_result.mappings().all():
        latest_events.append(
            {
                "id": str(row["id"]),
                "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
                "ingested_at": row["ingested_at"].isoformat() if row["ingested_at"] else None,
                "source_identifier": row["source_identifier"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "src_ip": str(row["src_ip"]) if row["src_ip"] else None,
                "dst_ip": str(row["dst_ip"]) if row["dst_ip"] else None,
                "username": row["username"],
                "hostname": row["hostname"],
                "geo_country": row["geo_country"],
                "geo_city": row["geo_city"],
                "geo_lat": row["geo_lat"],
                "geo_lon": row["geo_lon"],
                "abuse_score": row["abuse_score"],
                "relevant_cves": row["relevant_cves"] or [],
                "severity_score": row["severity_score"],
                "triage_status": row["triage_status"],
                "ai_triage_notes": row["ai_triage_notes"],
                "incident_id": str(row["incident_id"]) if row["incident_id"] else None,
            }
        )

    baseline_snapshot = await get_baseline_snapshot(limit=8)
    anomalies = await get_dashboard_anomalies(limit=8)

    return {
        "window_hours": hours,
        "kpis": {
            "total_events": int(kpis.get("total_events") or 0),
            "critical_events": int(kpis.get("critical_events") or 0),
            "high_events": int(kpis.get("high_events") or 0),
            "active_alerts": int(kpis.get("active_alerts") or 0),
            "open_incidents": int(kpis.get("open_incidents") or 0),
            "mean_time_to_respond_minutes": round(float(kpis.get("mean_time_to_respond_minutes") or 0), 2),
        },
        "severity_trend": severity_trend,
        "event_type_distribution": event_type_distribution,
        "latest_events": latest_events,
        "baseline": baseline_snapshot,
        "anomalies": anomalies,
        "ws_events_path": "/ws/events",
    }
