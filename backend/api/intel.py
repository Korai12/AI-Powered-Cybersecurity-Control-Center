from __future__ import annotations

import asyncio
import ipaddress

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_current_user
from services.intel.abuseipdb import lookup_abuseipdb
from services.intel.geoip import lookup_geoip
from services.intel.nvd_cve import lookup_cve, normalize_cve_id

router = APIRouter(tags=["intel"])


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}") from exc


@router.get("/intel/ip/{ip}")
async def get_ip_intel(
    ip: str,
    current_user: dict = Depends(get_current_user),
):
    normalised_ip = _validate_ip(ip)

    geo, reputation = await asyncio.gather(
        lookup_geoip(normalised_ip),
        lookup_abuseipdb(normalised_ip),
    )

    return {
        "ip": normalised_ip,
        "geo": geo,
        "reputation": reputation,
        "available": bool(geo or reputation),
        "degraded": not bool(geo or reputation),
    }


@router.get("/intel/cve/{cve_id}")
async def get_cve_intel(
    cve_id: str,
    current_user: dict = Depends(get_current_user),
):
    try:
        normalised = normalize_cve_id(cve_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = await lookup_cve(normalised)
    if result:
        return {"available": True, "degraded": False, **result}

    return {
        "available": False,
        "degraded": True,
        "cve_id": normalised,
        "message": "Live or cached CVE data is unavailable right now.",
    }