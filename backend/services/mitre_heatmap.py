from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.event import Event

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
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

MITRE_SEED_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "seed" / "mitre_techniques.json"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialize_event(event: Event) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "event_type": event.event_type,
        "severity": event.severity,
        "hostname": event.hostname,
        "username": event.username,
        "src_ip": str(event.src_ip) if event.src_ip else None,
        "dst_ip": str(event.dst_ip) if event.dst_ip else None,
        "rule_id": event.rule_id,
        "incident_id": str(event.incident_id) if event.incident_id else None,
        "mitre_tactic": event.mitre_tactic,
        "mitre_technique": event.mitre_technique,
    }


def _normalize_tactic(value: str | None) -> str:
    tactic = (value or "Unknown").strip()
    return tactic if tactic else "Unknown"


def _sort_tactic_key(tactic: str) -> tuple[int, str]:
    try:
        return (TACTIC_ORDER.index(tactic), tactic)
    except ValueError:
        return (len(TACTIC_ORDER), tactic)


def _load_seed_catalog() -> tuple[list[dict[str, Any]], str]:
    if MITRE_SEED_PATH.exists():
        raw = json.loads(MITRE_SEED_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            normalized: list[dict[str, Any]] = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                technique_id = str(item.get("id") or "").strip().upper()
                if not technique_id:
                    continue
                normalized.append(
                    {
                        "id": technique_id,
                        "name": str(item.get("name") or technique_id).strip(),
                        "tactic": _normalize_tactic(str(item.get("tactic") or "Unknown")),
                        "description": str(item.get("description") or "").strip(),
                        "detection": str(item.get("detection") or "").strip(),
                    }
                )
            return normalized, "seed_file"

    return [], "runtime_fallback"


async def build_mitre_heatmap_payload(db: AsyncSession) -> dict[str, Any]:
    result = await db.execute(
        select(Event)
        .where(Event.mitre_technique.isnot(None))
        .order_by(Event.timestamp.desc())
    )
    events = list(result.scalars().all())

    events_by_technique: dict[str, list[Event]] = defaultdict(list)
    inferred_metadata: dict[str, dict[str, str]] = {}

    for event in events:
        technique_id = str(event.mitre_technique or "").strip().upper()
        if not technique_id:
            continue

        events_by_technique[technique_id].append(event)

        if technique_id not in inferred_metadata:
            inferred_metadata[technique_id] = {
                "name": technique_id,
                "tactic": _normalize_tactic(event.mitre_tactic),
                "description": "",
                "detection": "",
            }

    catalog, catalog_source = _load_seed_catalog()

    if not catalog:
        catalog = [
            {
                "id": technique_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "description": meta["description"],
                "detection": meta["detection"],
            }
            for technique_id, meta in inferred_metadata.items()
        ]

    catalog_by_id = {item["id"]: item for item in catalog}

    for technique_id, meta in inferred_metadata.items():
        if technique_id not in catalog_by_id:
            catalog_by_id[technique_id] = {
                "id": technique_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "description": meta["description"],
                "detection": meta["detection"],
            }

    cells: list[dict[str, Any]] = []

    for technique_id, item in catalog_by_id.items():
        matched_events = events_by_technique.get(technique_id, [])
        tactic = _normalize_tactic(item.get("tactic"))

        cells.append(
            {
                "technique_id": technique_id,
                "name": str(item.get("name") or technique_id),
                "tactic": tactic,
                "description": str(item.get("description") or ""),
                "detection": str(item.get("detection") or ""),
                "detection_count": len(matched_events),
                "coverage_gap": len(matched_events) == 0,
                "events": [_serialize_event(event) for event in matched_events],
            }
        )

    cells.sort(key=lambda item: (_sort_tactic_key(item["tactic"]), item["technique_id"]))

    tactics = sorted({cell["tactic"] for cell in cells}, key=_sort_tactic_key)
    max_detection_count = max((cell["detection_count"] for cell in cells), default=0)
    coverage_gap_count = sum(1 for cell in cells if cell["coverage_gap"])

    return {
        "generated_at": _utc_now(),
        "catalog_source": catalog_source,
        "total_techniques": len(cells),
        "coverage_gap_count": coverage_gap_count,
        "covered_techniques": len(cells) - coverage_gap_count,
        "max_detection_count": max_detection_count,
        "tactics": tactics,
        "cells": cells,
    }