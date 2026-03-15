from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session_factory
from models.event import Event
from models.incident import Incident
from services.ai.openai_helper import chat_completion_json

logger = logging.getLogger("accc.ai.correlation")

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "correlation.txt"

CORRELATION_WINDOW_MINUTES = 30
LOOKBACK_HOURS = 2
MAX_EVENTS_PER_PASS = 250
MIN_CLUSTER_SIZE = 2

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
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

VALID_KILL_CHAIN_STAGES = set(KILL_CHAIN_ORDER)


def _sort_recommendations(recommendations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        recommendations,
        key=lambda item: RECOMMENDATION_PRIORITY_ORDER.get(
            str(item.get("priority", "")).upper(),
            99,
        ),
    )


def _normalize_recommendations(values: Any) -> list[dict[str, str]]:
    if not isinstance(values, list):
        return []

    normalized: list[dict[str, str]] = []

    for item in values:
        if not isinstance(item, dict):
            continue

        priority = str(item.get("priority") or "").strip().upper()
        action = str(item.get("action") or "").strip()
        rationale = str(item.get("rationale") or "").strip()
        timeframe = str(item.get("timeframe") or "").strip()

        if priority not in VALID_RECOMMENDATION_PRIORITIES:
            continue
        if not action or not rationale or not timeframe:
            continue

        normalized.append(
            {
                "priority": priority,
                "action": action,
                "rationale": rationale,
                "timeframe": timeframe,
            }
        )

    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for item in normalized:
        key = (
            item["priority"],
            item["action"],
            item["rationale"],
            item["timeframe"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return _sort_recommendations(deduped)


async def _call_llm_for_recommendations(
    cluster: list[Event],
    incident_context: dict[str, Any],
) -> list[dict[str, str]]:
    prompt = """
You are a SOC mitigation recommendation engine.

Your task is to generate ranked mitigation recommendations for a correlated cybersecurity incident.

Rules:
- Return JSON only.
- Return exactly this schema:
{
  "recommendations": [
    {
      "priority": "IMMEDIATE|SHORT_TERM|LONG_TERM",
      "action": "string",
      "rationale": "string",
      "timeframe": "string"
    }
  ]
}
- Recommendations must be grounded in the supplied incident and event data.
- Priorities must be:
  - IMMEDIATE for urgent containment
  - SHORT_TERM for investigation and near-term hardening
  - LONG_TERM for durable prevention and resilience
- Keep actions concrete and analyst-usable.
- Do not invent assets, users, or IOCs not present in the evidence.
"""

    payload = {
        "incident_context": incident_context,
        "cluster_summary": _cluster_summary(cluster),
        "events": [_event_to_payload(event) for event in cluster],
    }

    messages = [
        {"role": "system", "content": prompt.strip()},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
    ]

    result = await chat_completion_json(
        messages=messages,
        temperature=0.2,
        max_tokens=900,
    )

    return _normalize_recommendations(result.get("recommendations"))


def _load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8").strip()


def _dedupe_preserve_order(values: Iterable[Any]) -> list[Any]:
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


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _event_time(event: Event) -> datetime:
    ts = _as_utc(event.timestamp)
    if ts is None:
        return datetime.now(timezone.utc)
    return ts


def _time_delta_minutes(a: Event, b: Event) -> float:
    return abs((_event_time(a) - _event_time(b)).total_seconds()) / 60.0


def _extract_asset(event: Event) -> str | None:
    if event.hostname:
        return str(event.hostname).strip()
    if event.dst_ip:
        return str(event.dst_ip)
    return None


def _event_to_payload(event: Event) -> dict[str, Any]:
    payload = event.to_dict()
    payload["raw_log"] = (event.raw_log or "")[:1000] if event.raw_log else None
    payload["target_asset"] = _extract_asset(event)
    return payload


def _shared_nonempty(left: str | None, right: str | None) -> bool:
    return bool(left and right and left == right)


def _same_src_ip(left: Event, right: Event) -> bool:
    return bool(left.src_ip and right.src_ip and str(left.src_ip) == str(right.src_ip))


def _same_username(left: Event, right: Event) -> bool:
    return _shared_nonempty(left.username, right.username)


def _same_asset(left: Event, right: Event) -> bool:
    return _shared_nonempty(_extract_asset(left), _extract_asset(right))


def _same_dst_ip(left: Event, right: Event) -> bool:
    return bool(left.dst_ip and right.dst_ip and str(left.dst_ip) == str(right.dst_ip))


def _has_mitre_progression(left: Event, right: Event) -> bool:
    if not (left.mitre_tactic or left.mitre_technique):
        return False
    if not (right.mitre_tactic or right.mitre_technique):
        return False
    if _time_delta_minutes(left, right) > CORRELATION_WINDOW_MINUTES:
        return False

    shares_anchor = (
        _same_src_ip(left, right)
        or _same_username(left, right)
        or _same_asset(left, right)
    )
    if not shares_anchor:
        return False

    if left.mitre_technique and right.mitre_technique:
        if left.mitre_technique == right.mitre_technique:
            return True

    if left.mitre_tactic and right.mitre_tactic:
        return True

    return False


def _is_related(left: Event, right: Event) -> bool:
    if left.id == right.id:
        return True

    if _time_delta_minutes(left, right) > CORRELATION_WINDOW_MINUTES:
        return False

    if _same_src_ip(left, right):
        return True

    if _same_username(left, right):
        return True

    if _same_asset(left, right):
        if _same_dst_ip(left, right):
            return True
        if _shared_nonempty(left.event_type, right.event_type):
            return True
        if _has_mitre_progression(left, right):
            return True

    if _has_mitre_progression(left, right):
        return True

    return False


def _build_candidate_clusters(events: list[Event]) -> list[list[Event]]:
    if not events:
        return []

    visited: set[str] = set()
    event_map = {str(event.id): event for event in events}
    ordered_ids = [str(event.id) for event in events]
    clusters: list[list[Event]] = []

    for root_id in ordered_ids:
        if root_id in visited:
            continue

        queue = [event_map[root_id]]
        component_ids: set[str] = set()

        while queue:
            current = queue.pop(0)
            current_id = str(current.id)

            if current_id in component_ids:
                continue

            component_ids.add(current_id)
            visited.add(current_id)

            for candidate in events:
                candidate_id = str(candidate.id)
                if candidate_id in component_ids:
                    continue
                if _is_related(current, candidate):
                    queue.append(candidate)

        cluster = sorted(
            [event_map[event_id] for event_id in component_ids],
            key=_event_time,
        )

        if len(cluster) >= MIN_CLUSTER_SIZE:
            clusters.append(cluster)

    return clusters


def _collect_assets(cluster: list[Event]) -> list[str]:
    return _dedupe_preserve_order(_extract_asset(event) for event in cluster)


def _collect_users(cluster: list[Event]) -> list[str]:
    return _dedupe_preserve_order(event.username for event in cluster)


def _collect_ips(cluster: list[Event]) -> list[str]:
    values: list[str] = []

    for event in cluster:
        if event.src_ip:
            values.append(str(event.src_ip))
        if event.dst_ip:
            values.append(str(event.dst_ip))

    return _dedupe_preserve_order(values)


def _collect_tactics(cluster: list[Event]) -> list[str]:
    return _dedupe_preserve_order(event.mitre_tactic for event in cluster)


def _collect_techniques(cluster: list[Event]) -> list[str]:
    return _dedupe_preserve_order(event.mitre_technique for event in cluster)


def _infer_kill_chain_stage_from_cluster(cluster: list[Event]) -> str | None:
    stages: list[str] = []

    for event in cluster:
        tactic = (event.mitre_tactic or "").strip()
        if tactic in TACTIC_TO_KILL_CHAIN_STAGE:
            stages.append(TACTIC_TO_KILL_CHAIN_STAGE[tactic])

    if not stages:
        return None

    furthest_index = max(
        (KILL_CHAIN_ORDER.index(stage) for stage in stages if stage in KILL_CHAIN_ORDER),
        default=-1,
    )

    if furthest_index >= 0:
        return KILL_CHAIN_ORDER[furthest_index]

    return stages[-1]


def _cluster_summary(cluster: list[Event]) -> dict[str, Any]:
    earliest = _event_time(cluster[0]) if cluster else None
    latest = _event_time(cluster[-1]) if cluster else None

    return {
        "window_minutes": CORRELATION_WINDOW_MINUTES,
        "event_count": len(cluster),
        "earliest_timestamp": earliest.isoformat() if earliest else None,
        "latest_timestamp": latest.isoformat() if latest else None,
        "shared_src_ips": _dedupe_preserve_order(
            str(event.src_ip) for event in cluster if event.src_ip
        ),
        "shared_usernames": _collect_users(cluster),
        "target_assets": _collect_assets(cluster),
        "mitre_tactics": _collect_tactics(cluster),
        "mitre_techniques": _collect_techniques(cluster),
        "event_types": _dedupe_preserve_order(event.event_type for event in cluster),
        "severities": _dedupe_preserve_order(event.severity for event in cluster),
    }


def _sanitize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no", ""}:
            return False

    if isinstance(value, (int, float)):
        return value != 0

    return False


def _sanitize_severity(value: Any, cluster: list[Event]) -> str:
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in VALID_SEVERITIES:
            return normalized

    scores = [event.severity_score for event in cluster if event.severity_score is not None]
    if scores:
        highest = max(scores)
        if highest >= 8.5:
            return "CRITICAL"
        if highest >= 6.5:
            return "HIGH"
        if highest >= 4.0:
            return "MEDIUM"

    return "LOW"


def _sanitize_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0

    if confidence < 0.0:
        return 0.0
    if confidence > 1.0:
        return 1.0

    return round(confidence, 4)


def _sanitize_ip_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []

    result: list[str] = []

    for item in values:
        try:
            parsed = str(ip_address(str(item).strip()))
            result.append(parsed)
        except ValueError:
            continue

    return _dedupe_preserve_order(result)


def _sanitize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return _dedupe_preserve_order(str(item).strip() for item in values if item is not None)


def _sanitize_kill_chain_stage(value: Any, fallback: str | None) -> str | None:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized in VALID_KILL_CHAIN_STAGES:
            return normalized
    return fallback


def _normalize_llm_output(llm_result: dict[str, Any], cluster: list[Event]) -> dict[str, Any]:
    deterministic_assets = _collect_assets(cluster)
    deterministic_ips = _collect_ips(cluster)
    deterministic_stage = _infer_kill_chain_stage_from_cluster(cluster)

    title = str(llm_result.get("title") or "").strip()
    if not title:
        first_asset = deterministic_assets[0] if deterministic_assets else "multiple assets"
        title = f"Correlated security incident involving {first_asset}"

    description = str(llm_result.get("description") or "").strip()
    if not description:
        description = "Multiple related security events were correlated into a single incident candidate."

    affected_assets = _dedupe_preserve_order(
        _sanitize_string_list(llm_result.get("affected_assets")) + deterministic_assets
    )

    ioc_ips = _dedupe_preserve_order(
        _sanitize_ip_list(llm_result.get("ioc_ips")) + deterministic_ips
    )

    return {
        "is_incident": _sanitize_bool(llm_result.get("is_incident", False)),
        "title": title,
        "description": description,
        "severity": _sanitize_severity(llm_result.get("severity"), cluster),
        "confidence": _sanitize_confidence(llm_result.get("confidence")),
        "kill_chain_stage": _sanitize_kill_chain_stage(
            llm_result.get("kill_chain_stage"),
            deterministic_stage,
        ),
        "attack_type": str(llm_result.get("attack_type") or "").strip() or None,
        "affected_assets": affected_assets,
        "ioc_ips": ioc_ips,
    }


async def _call_llm_for_cluster(cluster: list[Event]) -> dict[str, Any]:
    prompt = _load_prompt()

    payload = {
        "cluster_summary": _cluster_summary(cluster),
        "events": [_event_to_payload(event) for event in cluster],
    }

    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)},
    ]

    result = await chat_completion_json(
        messages=messages,
        temperature=0.1,
        max_tokens=900,
    )

    return _normalize_llm_output(result, cluster)


async def _fetch_candidate_events(
    db: AsyncSession,
    lookback_hours: int = LOOKBACK_HOURS,
    max_events: int = MAX_EVENTS_PER_PASS,
) -> list[Event]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    stmt = (
        select(Event)
        .where(Event.timestamp >= cutoff)
        .where(or_(Event.is_false_positive.is_(False), Event.is_false_positive.is_(None)))
        .where(Event.incident_id.is_(None))
        .where(or_(Event.triage_status.is_(None), Event.triage_status != "closed"))
        .order_by(Event.timestamp.asc())
        .limit(max_events)
    )

    result = await db.execute(stmt)
    return list(result.scalars().all())


async def _create_incident_from_cluster(
    db: AsyncSession,
    cluster: list[Event],
    llm_output: dict[str, Any],
) -> Incident:
    try:
        recommendations = await _call_llm_for_recommendations(cluster, llm_output)
    except Exception:
        logger.exception("Failed to generate recommendations for cluster")
        recommendations = []

    incident = Incident(
        title=llm_output["title"],
        description=llm_output["description"],
        severity=llm_output["severity"],
        status="open",
        event_count=len(cluster),
        affected_assets=llm_output["affected_assets"],
        affected_users=_collect_users(cluster),
        ioc_ips=llm_output["ioc_ips"],
        mitre_tactics=_collect_tactics(cluster),
        mitre_techniques=_collect_techniques(cluster),
        kill_chain_stage=llm_output["kill_chain_stage"],
        attack_type=llm_output["attack_type"],
        ai_summary=llm_output["description"],
        ai_recommendations=recommendations,
        confidence_score=llm_output["confidence"],
    )

    db.add(incident)
    await db.flush()

    event_ids = [event.id for event in cluster]

    await db.execute(
        update(Event)
        .where(Event.id.in_(event_ids))
        .values(incident_id=incident.id)
    )

    logger.info("Created incident %s with %s events", incident.id, len(cluster))
    return incident


async def _process_clusters(db: AsyncSession, clusters: list[list[Event]]) -> dict[str, Any]:
    created_incident_ids: list[str] = []
    rejected_clusters = 0

    for cluster in clusters:
        llm_output = await _call_llm_for_cluster(cluster)

        if not llm_output["is_incident"]:
            rejected_clusters += 1
            continue

        incident = await _create_incident_from_cluster(db, cluster, llm_output)
        created_incident_ids.append(str(incident.id))

    return {
        "created_incident_ids": created_incident_ids,
        "rejected_clusters": rejected_clusters,
    }


async def run_correlation_pass(
    db: AsyncSession | None = None,
    lookback_hours: int = LOOKBACK_HOURS,
    max_events: int = MAX_EVENTS_PER_PASS,
) -> dict[str, Any]:
    async def _run(session: AsyncSession) -> dict[str, Any]:
        events = await _fetch_candidate_events(session, lookback_hours, max_events)
        clusters = _build_candidate_clusters(events)
        processed = await _process_clusters(session, clusters)

        await session.commit()

        summary = {
            "candidate_events": len(events),
            "candidate_clusters": len(clusters),
            "created_incidents": len(processed["created_incident_ids"]),
            "created_incident_ids": processed["created_incident_ids"],
            "rejected_clusters": processed["rejected_clusters"],
        }

        logger.info("Correlation pass complete: %s", summary)
        return summary

    owns_session = db is None

    if owns_session:
        async with async_session_factory() as session:
            try:
                return await _run(session)
            except Exception:
                await session.rollback()
                logger.exception("Correlation pass failed")
                raise

    try:
        return await _run(db)
    except Exception:
        await db.rollback()
        logger.exception("Correlation pass failed")
        raise