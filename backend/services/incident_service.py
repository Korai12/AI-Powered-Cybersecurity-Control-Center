from __future__ import annotations

import logging
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.event import Event
from models.incident import Incident
from services.ai.correlation import _call_llm_for_cluster, _call_llm_for_recommendations
from services.ai.report_gen import generate_incident_report

logger = logging.getLogger("accc.incidents")

VALID_INCIDENT_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}

VALID_RECOMMENDATION_PRIORITIES = {"IMMEDIATE", "SHORT_TERM", "LONG_TERM"}

RECOMMENDATION_PRIORITY_ORDER = {
    "IMMEDIATE": 0,
    "SHORT_TERM": 1,
    "LONG_TERM": 2,
}

TACTIC_TO_KILL_CHAIN_STAGE = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Reconnaissance",
    "Initial Access": "Initial Access",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion": "Defense Evasion",
    "Credential Access": "Credential Access",
    "Discovery": "Discovery",
    "Lateral Movement": "Lateral Movement",
    "Collection": "Collection",
    "Command and Control": "Command and Control",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
}

KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _sort_recommendations(recommendations: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not recommendations:
        return []

    return sorted(
        recommendations,
        key=lambda item: RECOMMENDATION_PRIORITY_ORDER.get(
            str(item.get("priority", "")).upper(),
            99,
        ),
    )


def _dedupe_preserve_order(values: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []

    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _safe_ip_list(values: list[Any]) -> list[str]:
    result: list[str] = []

    for value in values:
        if value is None:
            continue
        try:
            result.append(str(ip_address(str(value).strip())))
        except ValueError:
            continue

    return _dedupe_preserve_order(result)


def _event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "ingested_at": event.ingested_at.isoformat() if event.ingested_at else None,
        "source_format": event.source_format,
        "source_identifier": event.source_identifier,
        "event_type": event.event_type,
        "severity": event.severity,
        "raw_log": event.raw_log,
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
        "geo_lat": event.geo_lat,
        "geo_lon": event.geo_lon,
        "abuse_score": event.abuse_score,
        "relevant_cves": event.relevant_cves or [],
        "mitre_tactic": event.mitre_tactic,
        "mitre_technique": event.mitre_technique,
        "severity_score": event.severity_score,
        "is_false_positive": event.is_false_positive,
        "incident_id": str(event.incident_id) if event.incident_id else None,
        "triage_status": event.triage_status,
        "ai_triage_notes": event.ai_triage_notes,
        "tags": event.tags or [],
    }


def _incident_to_dict(incident: Incident) -> dict[str, Any]:
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
        "ai_recommendations": _sort_recommendations(incident.ai_recommendations or []),
        "confidence_score": incident.confidence_score,
        "false_positive_probability": incident.false_positive_probability,
        "is_campaign": incident.is_campaign,
        "campaign_id": str(incident.campaign_id) if incident.campaign_id else None,
        "report_generated_at": incident.report_generated_at.isoformat() if incident.report_generated_at else None,
    }


def _extract_asset(event: Event) -> str | None:
    if event.hostname:
        return str(event.hostname).strip()
    if event.dst_ip:
        return str(event.dst_ip)
    return None


def _collect_assets(events: list[Event]) -> list[str]:
    return _dedupe_preserve_order([_extract_asset(event) for event in events])


def _collect_users(events: list[Event]) -> list[str]:
    return _dedupe_preserve_order([event.username for event in events])


def _collect_ips(events: list[Event]) -> list[str]:
    values: list[Any] = []

    for event in events:
        values.append(event.src_ip)
        values.append(event.dst_ip)

    return _safe_ip_list(values)


def _collect_tactics(events: list[Event]) -> list[str]:
    return _dedupe_preserve_order([event.mitre_tactic for event in events])


def _collect_techniques(events: list[Event]) -> list[str]:
    return _dedupe_preserve_order([event.mitre_technique for event in events])


def _infer_kill_chain_stage(events: list[Event]) -> str | None:
    stages: list[str] = []

    for event in events:
        tactic = (event.mitre_tactic or "").strip()
        mapped = TACTIC_TO_KILL_CHAIN_STAGE.get(tactic)
        if mapped:
            stages.append(mapped)

    if not stages:
        return None

    furthest_index = max(
        (KILL_CHAIN_ORDER.index(stage) for stage in stages if stage in KILL_CHAIN_ORDER),
        default=-1,
    )
    if furthest_index >= 0:
        return KILL_CHAIN_ORDER[furthest_index]

    return stages[-1]


def _incident_phase_for_event(event: Event) -> str:
    tactic = (event.mitre_tactic or "").strip()
    return TACTIC_TO_KILL_CHAIN_STAGE.get(tactic, "Unknown")


def _build_incident_filters(
    status: str | None = None,
    severity: str | None = None,
    assigned_to: UUID | None = None,
) -> list[Any]:
    filters: list[Any] = []

    if status:
        filters.append(Incident.status == status.lower())
    if severity:
        filters.append(Incident.severity == severity.upper())
    if assigned_to:
        filters.append(Incident.assigned_to == assigned_to)

    return filters


async def _get_incident_or_raise(db: AsyncSession, incident_id: str | UUID) -> Incident:
    stmt = select(Incident).where(Incident.id == incident_id)
    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()

    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    return incident


async def _get_incident_events(db: AsyncSession, incident_id: UUID) -> list[Event]:
    stmt = (
        select(Event)
        .where(Event.incident_id == incident_id)
        .order_by(Event.timestamp.asc(), Event.ingested_at.asc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def list_incidents(
    db: AsyncSession,
    status: str | None = None,
    severity: str | None = None,
    assigned_to: UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    filters = _build_incident_filters(status=status, severity=severity, assigned_to=assigned_to)

    count_stmt = select(func.count()).select_from(Incident)
    if filters:
        count_stmt = count_stmt.where(*filters)

    total_result = await db.execute(count_stmt)
    total = int(total_result.scalar() or 0)

    stmt = select(Incident).order_by(Incident.created_at.desc()).limit(limit).offset(offset)
    if filters:
        stmt = stmt.where(*filters)

    result = await db.execute(stmt)
    incidents = list(result.scalars().all())

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "incidents": [_incident_to_dict(incident) for incident in incidents],
    }


async def get_incident_detail(db: AsyncSession, incident_id: str | UUID) -> dict[str, Any]:
    incident = await _get_incident_or_raise(db, incident_id)
    events = await _get_incident_events(db, incident.id)

    detail = _incident_to_dict(incident)
    detail["events"] = [_event_to_dict(event) for event in events]
    detail["timeline_ref"] = f"/api/v1/incidents/{incident.id}/timeline"
    detail["report_ref"] = f"/api/v1/incidents/{incident.id}/report"

    return detail


async def update_incident(
    db: AsyncSession,
    incident_id: str | UUID,
    patch_data: dict[str, Any],
    updated_by: str,
) -> dict[str, Any]:
    incident = await _get_incident_or_raise(db, incident_id)
    warnings: list[str] = []
    now = datetime.now(timezone.utc)

    if "status" in patch_data:
        status = str(patch_data["status"]).strip().lower()
        if status not in VALID_INCIDENT_STATUSES:
            raise ValueError("status must be one of: open, investigating, contained, resolved, closed")
        incident.status = status
        incident.resolved_at = now if status in {"resolved", "closed"} else None

    if "assigned_to" in patch_data:
        incident.assigned_to = patch_data["assigned_to"]

    if "analyst_notes" in patch_data and patch_data["analyst_notes"] is not None:
        warnings.append(
            "analyst_notes was accepted by the API, but the current documented incidents schema has no notes column, so it was not persisted."
        )

    incident.updated_at = now

    await db.commit()
    await db.refresh(incident)

    result = {
        "status": "updated",
        "updated_by": updated_by,
        "incident": _incident_to_dict(incident),
    }
    if warnings:
        result["warnings"] = warnings

    return result


async def get_incident_timeline(db: AsyncSession, incident_id: str | UUID) -> dict[str, Any]:
    incident = await _get_incident_or_raise(db, incident_id)
    events = await _get_incident_events(db, incident.id)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for index, event in enumerate(events):
        phase = _incident_phase_for_event(event)
        phase_index = KILL_CHAIN_ORDER.index(phase) if phase in KILL_CHAIN_ORDER else len(KILL_CHAIN_ORDER)

        nodes.append(
            {
                "id": str(event.id),
                "position": {"x": index * 260, "y": phase_index * 110},
                "data": {
                    "label": event.event_type or "event",
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "severity": event.severity,
                    "mitre_tactic": event.mitre_tactic,
                    "mitre_technique": event.mitre_technique,
                    "kill_chain_stage": phase,
                    "event": _event_to_dict(event),
                },
            }
        )

        if index > 0:
            prev = events[index - 1]
            edges.append(
                {
                    "id": f"e-{prev.id}-{event.id}",
                    "source": str(prev.id),
                    "target": str(event.id),
                    "animated": False,
                }
            )

    return {
        "incident_id": str(incident.id),
        "incident_title": incident.title,
        "kill_chain_stage": incident.kill_chain_stage,
        "nodes": nodes,
        "edges": edges,
        "event_count": len(events),
    }


async def get_incident_report(db: AsyncSession, incident_id: str | UUID) -> dict[str, Any]:
    return await generate_incident_report(incident_id=incident_id, db=db)


async def rerun_incident_correlation(
    db: AsyncSession,
    incident_id: str | UUID,
    requested_by: str,
) -> dict[str, Any]:
    incident = await _get_incident_or_raise(db, incident_id)
    events = await _get_incident_events(db, incident.id)

    if not events:
        raise ValueError("Incident has no correlated events to re-evaluate")

    llm_output = await _call_llm_for_cluster(events)
    now = datetime.now(timezone.utc)

    if not llm_output.get("is_incident", False):
        confidence = float(llm_output.get("confidence") or 0.0)
        incident.false_positive_probability = round(1.0 - confidence, 4)
        incident.updated_at = now
        await db.commit()
        await db.refresh(incident)

        return {
            "status": "not_reaffirmed",
            "requested_by": requested_by,
            "incident": _incident_to_dict(incident),
            "correlation_result": llm_output,
        }

    recommendations = await _call_llm_for_recommendations(events, llm_output)

    incident.title = llm_output.get("title") or incident.title
    incident.description = llm_output.get("description") or incident.description
    incident.severity = (llm_output.get("severity") or incident.severity or "MEDIUM").upper()
    incident.event_count = len(events)
    incident.affected_assets = _dedupe_preserve_order(
        (llm_output.get("affected_assets") or []) + _collect_assets(events)
    )
    incident.affected_users = _collect_users(events)
    incident.ioc_ips = _safe_ip_list((llm_output.get("ioc_ips") or []) + _collect_ips(events))
    incident.mitre_tactics = _collect_tactics(events)
    incident.mitre_techniques = _collect_techniques(events)
    incident.kill_chain_stage = llm_output.get("kill_chain_stage") or _infer_kill_chain_stage(events)
    incident.attack_type = llm_output.get("attack_type") or incident.attack_type
    incident.ai_summary = llm_output.get("description") or incident.ai_summary
    incident.ai_recommendations = recommendations
    incident.confidence_score = float(llm_output.get("confidence") or 0.0)
    incident.false_positive_probability = round(1.0 - incident.confidence_score, 4)
    incident.updated_at = now

    await db.commit()
    await db.refresh(incident)

    return {
        "status": "re-correlated",
        "requested_by": requested_by,
        "incident": _incident_to_dict(incident),
        "correlation_result": llm_output,
    }