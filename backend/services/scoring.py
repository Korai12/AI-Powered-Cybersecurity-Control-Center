from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

BASE_SCORE_MAP = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
}

ASSET_CRITICALITY_MAP = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5,
}


def _normalise_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return datetime.now(timezone.utc)


async def _asset_criticality_multiplier(db: AsyncSession, event: dict[str, Any]) -> float:
    hostname = str(event.get("hostname")).strip() if event.get("hostname") else None
    dst_ip = str(event.get("dst_ip")).strip() if event.get("dst_ip") else None
    src_ip = str(event.get("src_ip")).strip() if event.get("src_ip") else None

    found_values: list[float] = []

    if hostname:
        result = await db.execute(
            text(
                """
                SELECT criticality
                FROM assets
                WHERE hostname = :hostname
                LIMIT 1
                """
            ),
            {"hostname": hostname},
        )
        row = result.mappings().first()
        if row:
            found_values.append(ASSET_CRITICALITY_MAP.get(str(row["criticality"]).lower(), 1.0))

    if dst_ip:
        result = await db.execute(
            text(
                """
                SELECT criticality
                FROM assets
                WHERE ip_address = CAST(:dst_ip AS inet)
                LIMIT 1
                """
            ),
            {"dst_ip": dst_ip},
        )
        row = result.mappings().first()
        if row:
            found_values.append(ASSET_CRITICALITY_MAP.get(str(row["criticality"]).lower(), 1.0))

    if src_ip:
        result = await db.execute(
            text(
                """
                SELECT criticality
                FROM assets
                WHERE ip_address = CAST(:src_ip AS inet)
                LIMIT 1
                """
            ),
            {"src_ip": src_ip},
        )
        row = result.mappings().first()
        if row:
            found_values.append(ASSET_CRITICALITY_MAP.get(str(row["criticality"]).lower(), 1.0))

    return max(found_values) if found_values else 1.0


def _time_context_multiplier(timestamp_value: Any) -> float:
    ts = _normalise_timestamp(timestamp_value).astimezone(timezone.utc)
    if 0 <= ts.hour < 6:
        return 1.5
    if ts.weekday() >= 5:
        return 1.2
    return 1.0


async def _frequency_multiplier(db: AsyncSession, event: dict[str, Any]) -> float:
    src_ip = event.get("src_ip")
    ts = _normalise_timestamp(event.get("timestamp"))
    if not src_ip:
        return 1.0

    result = await db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM events
            WHERE src_ip = CAST(:src_ip AS inet)
              AND timestamp >= CAST(:ts AS timestamptz) - INTERVAL '5 minutes'
              AND timestamp <= CAST(:ts AS timestamptz)
            """
        ),
        {
            "src_ip": src_ip,
            "ts": ts,
        },
    )
    count = int(result.scalar() or 0)
    return min(2.0, 1.0 + (0.1 * count))


async def _cvss_multiplier(db: AsyncSession, relevant_cves: list[str]) -> float:
    if not relevant_cves:
        return 1.0

    max_cvss = 0.0
    for cve_id in relevant_cves[:10]:
        result = await db.execute(
            text(
                """
                SELECT COALESCE(cvss_score, cvss_v3_score)
                FROM cve_cache
                WHERE cve_id = :cve_id
                """
            ),
            {"cve_id": cve_id},
        )
        value = result.scalar()
        try:
            score = float(value) if value is not None else 0.0
        except (TypeError, ValueError):
            score = 0.0
        max_cvss = max(max_cvss, score)

    if max_cvss >= 9.0:
        return 2.0
    if max_cvss >= 7.0:
        return 1.5
    if max_cvss >= 4.0:
        return 1.2
    return 1.0


def reputation_multiplier(abuse_score: Optional[int]) -> float:
    try:
        score = int(abuse_score) if abuse_score is not None else 0
    except (TypeError, ValueError):
        score = 0

    if score <= 0:
        return 1.0

    return round(min(1.8, 1.0 + (min(score, 80) / 80.0) * 0.8), 2)


async def compute_contextual_severity_score(db: AsyncSession, event: dict[str, Any]) -> dict[str, Any]:
    base_score = BASE_SCORE_MAP.get(str(event.get("severity") or "MEDIUM").upper(), 4.0)
    asset_multiplier = await _asset_criticality_multiplier(db, event)
    time_multiplier = _time_context_multiplier(event.get("timestamp"))
    frequency_factor = await _frequency_multiplier(db, event)
    cvss_multiplier = await _cvss_multiplier(db, list(event.get("relevant_cves") or []))
    rep_multiplier = reputation_multiplier(event.get("abuse_score"))

    final_score = round(
        base_score
        * asset_multiplier
        * time_multiplier
        * frequency_factor
        * cvss_multiplier
        * rep_multiplier,
        2,
    )

    return {
        "base_score": base_score,
        "asset_criticality": asset_multiplier,
        "time_context": time_multiplier,
        "frequency_factor": frequency_factor,
        "cvss_multiplier": cvss_multiplier,
        "reputation_score": rep_multiplier,
        "final_score": final_score,
    }