from __future__ import annotations

import json
import logging
import re
from datetime import date, datetime
from typing import Any, Optional

import httpx
import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import async_session_factory

logger = logging.getLogger("accc.intel.nvd")

CVE_CACHE_TTL_SECONDS = 60 * 60 * 24
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


async def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def normalize_cve_id(cve_id: str) -> str:
    value = (cve_id or "").strip().upper()
    if not CVE_RE.fullmatch(value):
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    return value


def _normalize_published_date(value: Any) -> Optional[date]:
    if not value:
        return None

    if isinstance(value, date) and not isinstance(value, datetime):
        return value

    if isinstance(value, datetime):
        return value.date()

    text_value = str(value).strip()
    if not text_value:
        return None

    try:
        return datetime.fromisoformat(text_value.replace("Z", "+00:00")).date()
    except ValueError:
        pass

    try:
        return date.fromisoformat(text_value[:10])
    except ValueError:
        return None


async def _redis_cache_get(
    redis_client: aioredis.Redis,
    cve_id: str,
) -> Optional[dict[str, Any]]:
    cached = await redis_client.get(f"cve:{cve_id}")
    if not cached:
        return None

    try:
        payload = json.loads(cached)
        payload["source"] = payload.get("source") or "cache"
        payload["cached"] = True
        return payload
    except json.JSONDecodeError:
        return None


async def _db_cache_get(db: AsyncSession, cve_id: str) -> Optional[dict[str, Any]]:
    result = await db.execute(
        text(
            """
            SELECT cve_id, cvss_score, cvss_v3_score, severity, is_exploited,
                   affected_products, description, published_date, cached_at
            FROM cve_cache
            WHERE cve_id = :cve_id
              AND cached_at >= NOW() - INTERVAL '24 hours'
            """
        ),
        {"cve_id": cve_id},
    )
    row = result.mappings().first()
    if not row:
        return None

    return {
        "cve_id": row["cve_id"],
        "description": row["description"],
        "cvss_score": row["cvss_score"] or row["cvss_v3_score"],
        "severity": row["severity"],
        "is_exploited": bool(row["is_exploited"]),
        "affected_products": row["affected_products"] or [],
        "published_date": row["published_date"].isoformat() if row["published_date"] else None,
        "source": "db_cache",
        "cached": True,
    }


async def _persist_db_cache(db: AsyncSession, payload: dict[str, Any]) -> None:
    published_date = _normalize_published_date(payload.get("published_date"))

    await db.execute(
        text(
            """
            INSERT INTO cve_cache (
                cve_id, cvss_score, cvss_v3_score, severity, is_exploited,
                affected_products, description, published_date, cached_at
            )
            VALUES (
                :cve_id, :cvss_score, :cvss_score, :severity, :is_exploited,
                CAST(:affected_products AS jsonb), :description, :published_date, NOW()
            )
            ON CONFLICT (cve_id)
            DO UPDATE SET
                cvss_score = EXCLUDED.cvss_score,
                cvss_v3_score = EXCLUDED.cvss_v3_score,
                severity = EXCLUDED.severity,
                is_exploited = EXCLUDED.is_exploited,
                affected_products = EXCLUDED.affected_products,
                description = EXCLUDED.description,
                published_date = EXCLUDED.published_date,
                cached_at = NOW()
            """
        ),
        {
            "cve_id": payload["cve_id"],
            "cvss_score": payload.get("cvss_score"),
            "severity": payload.get("severity"),
            "is_exploited": bool(payload.get("is_exploited")),
            "affected_products": json.dumps(payload.get("affected_products") or []),
            "description": payload.get("description"),
            "published_date": published_date,
        },
    )
    await db.commit()


def _pick_english_description(descriptions: list[dict[str, Any]]) -> str:
    for entry in descriptions or []:
        if entry.get("lang") == "en" and entry.get("value"):
            return str(entry["value"])
    if descriptions:
        return str(descriptions[0].get("value") or "")
    return ""


def _extract_cvss(metrics: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    metric_sets = [
        metrics.get("cvssMetricV40") or [],
        metrics.get("cvssMetricV31") or [],
        metrics.get("cvssMetricV30") or [],
        metrics.get("cvssMetricV2") or [],
    ]

    for metric_list in metric_sets:
        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")

        try:
            numeric = float(score) if score is not None else None
        except (TypeError, ValueError):
            numeric = None

        return numeric, severity

    return None, None


def _extract_affected_products(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    def walk_nodes(nodes: list[dict[str, Any]]) -> None:
        for node in nodes or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                entry = {
                    "criteria": criteria,
                    "vendor": parts[3] if len(parts) > 3 else None,
                    "product": parts[4] if len(parts) > 4 else None,
                    "version": parts[5] if len(parts) > 5 else None,
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                }
                if entry not in results:
                    results.append(entry)
            walk_nodes(node.get("nodes") or [])

    for configuration in configurations or []:
        walk_nodes(configuration.get("nodes") or [])

    return results[:50]


async def _lookup_cve_inner(cve_id: str, db: AsyncSession) -> Optional[dict[str, Any]]:
    normalised = normalize_cve_id(cve_id)
    redis_client: Optional[aioredis.Redis] = None

    try:
        redis_client = await _get_redis()

        cached = await _redis_cache_get(redis_client, normalised)
        if cached:
            return cached

        db_cached = await _db_cache_get(db, normalised)
        if db_cached:
            await redis_client.setex(
                f"cve:{normalised}",
                CVE_CACHE_TTL_SECONDS,
                json.dumps(db_cached, ensure_ascii=False),
            )
            return db_cached

        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.get(NVD_CVE_API_URL, params={"cveId": normalised})

        response.raise_for_status()
        payload = response.json() or {}
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return None

        record = vulnerabilities[0].get("cve") or {}
        score, severity = _extract_cvss(record.get("metrics") or {})
        exploited = bool(
            record.get("cisaExploitAdd")
            or record.get("cisaRequiredAction")
            or payload.get("cisaExploitAdd")
        )

        result = {
            "cve_id": record.get("id") or normalised,
            "description": _pick_english_description(record.get("descriptions") or []),
            "cvss_score": score,
            "severity": severity,
            "is_exploited": exploited,
            "affected_products": _extract_affected_products(record.get("configurations") or []),
            "published_date": record.get("published"),
            "source": "live",
            "cached": False,
        }

        await redis_client.setex(
            f"cve:{normalised}",
            CVE_CACHE_TTL_SECONDS,
            json.dumps(result, ensure_ascii=False),
        )
        await _persist_db_cache(db, result)
        return result

    except Exception as exc:
        logger.warning("NVD CVE lookup failed for %s: %s", cve_id, exc)
        return None
    finally:
        if redis_client is not None:
            await redis_client.aclose()


async def lookup_cve(cve_id: str, *, db: Optional[AsyncSession] = None) -> Optional[dict[str, Any]]:
    if db is not None:
        return await _lookup_cve_inner(cve_id, db)

    async with async_session_factory() as owned_db:
        return await _lookup_cve_inner(cve_id, owned_db)


def extract_cve_ids(text_value: str) -> list[str]:
    return [match.upper() for match in CVE_RE.findall(text_value or "")]