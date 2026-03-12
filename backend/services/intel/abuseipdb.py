from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any, Optional

import httpx
import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import async_session_factory

logger = logging.getLogger("accc.intel.abuseipdb")

ABUSE_CACHE_TTL_SECONDS = 60 * 60
ABUSE_DAILY_LIMIT_GUARD = 950
ABUSE_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_MAX_AGE_DAYS = 90


async def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def _normalize_ip(ip: Any) -> str:
    return str(ip or "").strip()


def is_public_ip(ip: Any) -> bool:
    try:
        return ipaddress.ip_address(_normalize_ip(ip)).is_global
    except ValueError:
        return False


async def _redis_cache_get(
    redis_client: aioredis.Redis,
    ip: str,
) -> Optional[dict[str, Any]]:
    cached = await redis_client.get(f"abuseipdb:{ip}")
    if not cached:
        return None

    try:
        payload = json.loads(cached)
        payload["source"] = payload.get("source") or "cache"
        payload["cached"] = True
        return payload
    except json.JSONDecodeError:
        return None


async def _db_cache_get(db: AsyncSession, ip: str) -> Optional[dict[str, Any]]:
    result = await db.execute(
        text(
            """
            SELECT ip, abuse_score, is_tor, is_vpn, country, isp, cached_at
            FROM ip_reputation_cache
            WHERE ip = CAST(:ip AS inet)
              AND cached_at >= NOW() - INTERVAL '1 hour'
            """
        ),
        {"ip": ip},
    )
    row = result.mappings().first()
    if not row:
        return None

    return {
        "ip": str(row["ip"]),
        "abuse_score": row["abuse_score"],
        "country_code": row["country"],
        "isp": row["isp"],
        "is_tor": bool(row["is_tor"]),
        "is_vpn": bool(row["is_vpn"]),
        "total_reports": None,
        "last_reported": None,
        "source": "db_cache",
        "cached": True,
        "looked_up_at": row["cached_at"].isoformat() if row["cached_at"] else None,
    }


async def _daily_guard(redis_client: aioredis.Redis) -> bool:
    current = await redis_client.get("abuseipdb:daily_count")
    try:
        count = int(current or 0)
    except ValueError:
        count = 0
    return count >= ABUSE_DAILY_LIMIT_GUARD


async def _increment_daily_counter(redis_client: aioredis.Redis) -> None:
    value = await redis_client.incr("abuseipdb:daily_count")
    if value == 1:
        await redis_client.expire("abuseipdb:daily_count", 86400)


async def _persist_db_cache(db: AsyncSession, payload: dict[str, Any]) -> None:
    await db.execute(
        text(
            """
            INSERT INTO ip_reputation_cache (ip, abuse_score, is_tor, is_vpn, country, isp, cached_at)
            VALUES (CAST(:ip AS inet), :abuse_score, :is_tor, :is_vpn, :country, :isp, NOW())
            ON CONFLICT (ip)
            DO UPDATE SET
                abuse_score = EXCLUDED.abuse_score,
                is_tor = EXCLUDED.is_tor,
                is_vpn = EXCLUDED.is_vpn,
                country = EXCLUDED.country,
                isp = EXCLUDED.isp,
                cached_at = NOW()
            """
        ),
        {
            "ip": payload["ip"],
            "abuse_score": payload.get("abuse_score"),
            "is_tor": bool(payload.get("is_tor")),
            "is_vpn": bool(payload.get("is_vpn")),
            "country": payload.get("country_code"),
            "isp": payload.get("isp"),
        },
    )
    await db.commit()


async def _lookup_abuseipdb_inner(ip: str, db: AsyncSession) -> Optional[dict[str, Any]]:
    if not ip or not is_public_ip(ip):
        return None

    redis_client: Optional[aioredis.Redis] = None
    try:
        redis_client = await _get_redis()

        cached = await _redis_cache_get(redis_client, ip)
        if cached:
            return cached

        db_cached = await _db_cache_get(db, ip)
        if db_cached:
            await redis_client.setex(
                f"abuseipdb:{ip}",
                ABUSE_CACHE_TTL_SECONDS,
                json.dumps(db_cached, ensure_ascii=False),
            )
            return db_cached

        if await _daily_guard(redis_client):
            logger.info("AbuseIPDB live lookup skipped for %s because the daily guard is active", ip)
            return None

        if not settings.ABUSEIPDB_API_KEY:
            logger.info("AbuseIPDB API key missing — lookup for %s degraded gracefully", ip)
            return None

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                ABUSE_API_URL,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": ABUSE_MAX_AGE_DAYS,
                },
                headers={
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
            )

        if response.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit for %s", ip)
            return None

        response.raise_for_status()
        data = (response.json() or {}).get("data") or {}
        usage_type = str(data.get("usageType") or "")

        payload = {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": usage_type,
            "is_tor": bool(data.get("isTor")),
            "is_vpn": bool(data.get("isTor")) or ("vpn" in usage_type.lower()) or ("proxy" in usage_type.lower()),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "source": "live",
            "cached": False,
        }

        await _increment_daily_counter(redis_client)
        await redis_client.setex(
            f"abuseipdb:{ip}",
            ABUSE_CACHE_TTL_SECONDS,
            json.dumps(payload, ensure_ascii=False),
        )
        await _persist_db_cache(db, payload)
        return payload

    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None
    finally:
        if redis_client is not None:
            await redis_client.aclose()


async def lookup_abuseipdb(ip: Any, *, db: Optional[AsyncSession] = None) -> Optional[dict[str, Any]]:
    ip = _normalize_ip(ip)
    if db is not None:
        return await _lookup_abuseipdb_inner(ip, db)

    async with async_session_factory() as owned_db:
        return await _lookup_abuseipdb_inner(ip, owned_db)


async def get_abuse_score(ip: Optional[Any], *, db: Optional[AsyncSession] = None) -> Optional[int]:
    if not ip:
        return None

    result = await lookup_abuseipdb(ip, db=db)
    if not result:
        return None

    try:
        value = result.get("abuse_score")
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None