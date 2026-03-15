# Stub — implemented in its respective phase
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session_factory
from models.event import Event
from models.incident import Incident
from services.ai.openai_helper import chat_completion_text

logger = logging.getLogger("accc.ai.report")

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "report.txt"


def _load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8").strip()


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _sort_events(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda event: event.timestamp or datetime.now(timezone.utc))


def _event_to_payload(event: Event) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source_format": event.source_format,
        "source_identifier": event.source_identifier,
        "event_type": event.event_type,
        "severity": event.severity,
        "raw_log": (event.raw_log or "")[:1200] if event.raw_log else None,
        "src_ip": str(event.src_ip) if event.src_ip else None,
        "dst_ip": str(event.dst_ip) if event.dst_ip else None,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "username": event.username,
        "hostname": event.hostname,
        "process_name": event.process_name,
        "file_hash": event.file_hash,
        "action": event.action,
        "rule_id": event.rule_id,
        "geo_country": event.geo_country,
        "geo_city": event.geo_city,
        "abuse_score": event.abuse_score,
        "relevant_cves": event.relevant_cves or [],
        "mitre_tactic": event.mitre_tactic,
        "mitre_technique": event.mitre_technique,
        "severity_score": event.severity_score,
        "triage_status": event.triage_status,
        "ai_triage_notes": event.ai_triage_notes,
        "tags": event.tags or [],
    }


def _incident_to_payload(incident: Incident) -> dict[str, Any]:
    return {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "assigned_to": str(incident.assigned_to) if incident.assigned_to else None,
        "event_count": incident.event_count,
        "affected_assets": incident.affected_assets or [],
        "affected_users": incident.affected_users or [],
        "ioc_ips": [str(ip) for ip in (incident.ioc_ips or [])],
        "ioc_domains": incident.ioc_domains or [],
        "ioc_hashes": incident.ioc_hashes or [],
        "mitre_tactics": incident.mitre_tactics or [],
        "mitre_techniques": incident.mitre_techniques or [],
        "kill_chain_stage": incident.kill_chain_stage,
        "attack_type": incident.attack_type,
        "ai_summary": incident.ai_summary,
        "ai_recommendations": incident.ai_recommendations or [],
        "confidence_score": incident.confidence_score,
        "false_positive_probability": incident.false_positive_probability,
        "report_generated_at": (
            incident.report_generated_at.isoformat() if incident.report_generated_at else None
        ),
    }


async def _get_incident(db: AsyncSession, incident_id: str | UUID) -> Incident | None:
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _get_incident_events(db: AsyncSession, incident_id: UUID) -> list[Event]:
    stmt = (
        select(Event)
        .where(Event.incident_id == incident_id)
        .order_by(Event.timestamp.asc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


def _build_user_payload(incident: Incident, events: list[Event]) -> dict[str, Any]:
    return {
        "incident": _incident_to_payload(incident),
        "events": [_event_to_payload(event) for event in _sort_events(events)],
        "report_requirements": {
            "sections": [
                "Executive Summary",
                "Timeline Narrative",
                "IOC Inventory",
                "Affected Assets and Users",
                "MITRE ATT&CK Mapping",
                "Recommended Actions",
            ]
        },
    }


async def generate_incident_report(
    incident_id: str | UUID,
    db: AsyncSession | None = None,
) -> dict[str, Any]:
    """
    Generate a full AI narrative report for one incident.

    Plan-only implementation:
    - Generates the report on demand from incident + correlated events
    - Updates incidents.report_generated_at
    - Does not add new storage beyond the documented schema
    """
    owns_session = db is None

    async def _run(session: AsyncSession) -> dict[str, Any]:
        incident = await _get_incident(session, incident_id)
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")

        events = await _get_incident_events(session, incident.id)

        prompt = _load_prompt()
        payload = _build_user_payload(incident, events)

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
        ]

        report_text = await chat_completion_text(
            messages=messages,
            temperature=0.2,
            max_tokens=2200,
        )

        incident.report_generated_at = datetime.now(timezone.utc)
        await session.flush()
        await session.commit()

        logger.info("Generated incident report for incident %s", incident.id)

        return {
            "incident_id": str(incident.id),
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "event_count": len(events),
            "report": report_text,
            "report_generated_at": (
                incident.report_generated_at.isoformat() if incident.report_generated_at else None
            ),
        }

    if owns_session:
        async with async_session_factory() as session:
            try:
                return await _run(session)
            except Exception:
                await session.rollback()
                logger.exception("Incident report generation failed")
                raise

    try:
        return await _run(db)
    except Exception:
        await db.rollback()
        logger.exception("Incident report generation failed")
        raise