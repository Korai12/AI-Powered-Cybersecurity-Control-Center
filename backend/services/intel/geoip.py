from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import redis.asyncio as aioredis

from config import settings

logger = logging.getLogger("accc.intel.geoip")

GEOIP_CACHE_TTL_SECONDS = 60 * 60 * 24
GEOIP_RATE_LIMIT_PER_MINUTE = 40
GEOIP_FIELDS = "status,message,country,countryCode,city,lat,lon,isp,proxy,query"
GEOIP_URL_TEMPLATE = f"http://ip-api.com/json/{{ip}}?fields={GEOIP_FIELDS}"


async def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def _normalize_ip(ip: Any) -> str:
    return str(ip or "").strip()


def is_private_or_reserved_ip(ip: Any) -> bool:
    try:
        parsed = ipaddress.ip_address(_normalize_ip(ip))
        return bool(
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
            or parsed.is_link_local
        )
    except ValueError:
        return True


async def _get_cached_geoip(
    redis_client: aioredis.Redis,
    ip: str,
) -> Optional[dict[str, Any]]:
    cached = await redis_client.get(f"geo:{ip}")
    if not cached:
        return None

    try:
        payload = json.loads(cached)
        payload["source"] = payload.get("source") or "cache"
        payload["cached"] = True
        return payload
    except json.JSONDecodeError:
        return None


async def _minute_rate_guard(redis_client: aioredis.Redis) -> bool:
    minute_key = datetime.now(timezone.utc).strftime("geoip:rate:%Y%m%d%H%M")
    current = await redis_client.get(minute_key)
    try:
        count = int(current or 0)
    except ValueError:
        count = 0
    return count >= GEOIP_RATE_LIMIT_PER_MINUTE


async def _increment_minute_counter(redis_client: aioredis.Redis) -> None:
    minute_key = datetime.now(timezone.utc).strftime("geoip:rate:%Y%m%d%H%M")
    value = await redis_client.incr(minute_key)
    if value == 1:
        await redis_client.expire(minute_key, 120)


async def lookup_geoip(ip: Any) -> Optional[dict[str, Any]]:
    ip = _normalize_ip(ip)
    if not ip or is_private_or_reserved_ip(ip):
        return None

    redis_client: Optional[aioredis.Redis] = None
    try:
        redis_client = await _get_redis()

        cached = await _get_cached_geoip(redis_client, ip)
        if cached:
            return cached

        if await _minute_rate_guard(redis_client):
            logger.info("GeoIP live lookup skipped for %s due to minute rate guard", ip)
            return None

        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(GEOIP_URL_TEMPLATE.format(ip=ip))
            response.raise_for_status()
            data = response.json()

        if data.get("status") != "success":
            logger.info("GeoIP lookup for %s returned non-success status: %s", ip, data)
            return None

        payload = {
            "ip": ip,
            "geo_country": data.get("countryCode"),
            "geo_country_name": data.get("country"),
            "geo_city": data.get("city"),
            "geo_lat": data.get("lat"),
            "geo_lon": data.get("lon"),
            "isp": data.get("isp"),
            "is_proxy": bool(data.get("proxy")),
            "looked_up_at": datetime.now(timezone.utc).isoformat(),
            "source": "live",
            "cached": False,
        }

        await _increment_minute_counter(redis_client)
        await redis_client.setex(
            f"geo:{ip}",
            GEOIP_CACHE_TTL_SECONDS,
            json.dumps(payload, ensure_ascii=False),
        )
        return payload

    except Exception as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
        return None
    finally:
        if redis_client is not None:
            await redis_client.aclose()


async def enrich_event_geo_fields(ip: Optional[Any]) -> dict[str, Any]:
    result = await lookup_geoip(ip)
    if not result:
        return {}

    return {
        "geo_country": result.get("geo_country"),
        "geo_city": result.get("geo_city"),
        "geo_lat": result.get("geo_lat"),
        "geo_lon": result.get("geo_lon"),
    }