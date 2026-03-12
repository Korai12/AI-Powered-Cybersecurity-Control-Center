from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import text

from database import async_session_factory
from services.intel.abuseipdb import lookup_abuseipdb
from services.intel.geoip import enrich_event_geo_fields
from services.intel.nvd_cve import extract_cve_ids, lookup_cve
from services.scoring import compute_contextual_severity_score

logger = logging.getLogger("accc.ingestion.enrichment")

TEXT_FIELDS_FOR_CVE = ("raw_log", "rule_id", "process_name", "event_type", "action")

CVE_HINTS = {
    "log4shell": ["CVE-2021-44228"],
    "log4j": ["CVE-2021-44228"],
    "jndi": ["CVE-2021-44228"],
    "proxyshell": ["CVE-2021-34473"],
    "apache": ["CVE-2021-41773"],
    "httpd": ["CVE-2021-41773"],
}


def _infer_cve_candidates(event: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    for field in TEXT_FIELDS_FOR_CVE:
        value = str(event.get(field) or "")
        for cve_id in extract_cve_ids(value):
            if cve_id not in seen:
                seen.add(cve_id)
                candidates.append(cve_id)

    haystack = " ".join(str(event.get(field) or "") for field in TEXT_FIELDS_FOR_CVE).lower()
    for hint, mapped in CVE_HINTS.items():
        if hint in haystack:
            for cve_id in mapped:
                if cve_id not in seen:
                    seen.add(cve_id)
                    candidates.append(cve_id)

    if not candidates and str(event.get("dst_port") or "") in {"80", "443"}:
        process_name = str(event.get("process_name") or "").lower()
        if "apache" in process_name or "httpd" in process_name:
            candidates.append("CVE-2021-41773")

    return candidates[:5]


async def enrich_event_after_ingest(event_id: str) -> dict[str, Any]:
    try:
        async with async_session_factory() as db:
            result = await db.execute(
                text("SELECT * FROM events WHERE id = :id"),
                {"id": event_id},
            )
            row = result.mappings().first()
            if not row:
                return {"status": "missing", "event_id": event_id}

            event = dict(row)
            src_ip = str(event.get("src_ip")).strip() if event.get("src_ip") else None

            geo_task = enrich_event_geo_fields(src_ip)
            abuse_task = lookup_abuseipdb(src_ip, db=db)

            geo_data, abuse_data = await asyncio.gather(
                geo_task,
                abuse_task,
                return_exceptions=True,
            )

            if isinstance(geo_data, Exception):
                logger.warning("Geo enrichment failed for %s: %s", event_id, geo_data)
                geo_data = {}

            if isinstance(abuse_data, Exception):
                logger.warning("AbuseIPDB enrichment failed for %s: %s", event_id, abuse_data)
                abuse_data = None

            cve_ids = _infer_cve_candidates(event)
            cve_details: list[dict[str, Any]] = []

            if cve_ids:
                cve_results = await asyncio.gather(
                    *(lookup_cve(cve_id, db=db) for cve_id in cve_ids),
                    return_exceptions=True,
                )
                for item in cve_results:
                    if isinstance(item, Exception):
                        logger.warning("CVE enrichment subtask failed for %s: %s", event_id, item)
                        continue
                    if item:
                        cve_details.append(item)

            abuse_score = None
            if isinstance(abuse_data, dict):
                abuse_score = abuse_data.get("abuse_score")

            event["geo_country"] = geo_data.get("geo_country") or event.get("geo_country")
            event["geo_city"] = geo_data.get("geo_city") or event.get("geo_city")
            event["geo_lat"] = geo_data.get("geo_lat") if geo_data.get("geo_lat") is not None else event.get("geo_lat")
            event["geo_lon"] = geo_data.get("geo_lon") if geo_data.get("geo_lon") is not None else event.get("geo_lon")
            event["abuse_score"] = abuse_score if abuse_score is not None else event.get("abuse_score")
            event["relevant_cves"] = [item["cve_id"] for item in cve_details] or list(event.get("relevant_cves") or [])

            scoring = await compute_contextual_severity_score(db, event)

            await db.execute(
                text(
                    """
                    UPDATE events
                    SET geo_country = :geo_country,
                        geo_city = :geo_city,
                        geo_lat = :geo_lat,
                        geo_lon = :geo_lon,
                        abuse_score = :abuse_score,
                        relevant_cves = :relevant_cves,
                        severity_score = :severity_score
                    WHERE id = :event_id
                    """
                ),
                {
                    "event_id": event_id,
                    "geo_country": event.get("geo_country"),
                    "geo_city": event.get("geo_city"),
                    "geo_lat": event.get("geo_lat"),
                    "geo_lon": event.get("geo_lon"),
                    "abuse_score": event.get("abuse_score"),
                    "relevant_cves": event.get("relevant_cves") or [],
                    "severity_score": scoring["final_score"],
                },
            )
            await db.commit()

            return {
                "status": "ok",
                "event_id": event_id,
                "geo": bool(geo_data),
                "abuse": bool(abuse_data),
                "cves": [item["cve_id"] for item in cve_details],
                "severity_score": scoring["final_score"],
            }

    except Exception as exc:
        logger.warning("Event enrichment failed for %s: %s", event_id, exc)
        return {
            "status": "error",
            "event_id": event_id,
            "error": str(exc),
        }