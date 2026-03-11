"""Common Event Schema (CES) — G-04 CRITICAL.

The CES is the normalized Python dataclass that every log parser produces,
regardless of input format. It maps directly to the events table columns.

All parsers must import CommonEvent and populate every field they can
extract; unpopulated optional fields default to None.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import importlib, logging

logger = logging.getLogger(__name__)


@dataclass
class CommonEvent:
    """Normalized event — every parser returns this exact structure."""

    # ── Required fields (always populated) ──────────────────────────────────
    timestamp:         datetime
    source_format:     str           # json | cef | syslog | windows_evtlog | cloudtrail | csv
    source_identifier: str           # device name, IP, or file path
    event_type:        str           # auth_failure | port_scan | malware | lateral_movement | etc.
    severity:          str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    raw_log:           str           # verbatim original — never modified

    # ── Network ─────────────────────────────────────────────────────────────
    src_ip:       Optional[str]  = None
    dst_ip:       Optional[str]  = None
    src_port:     Optional[int]  = None
    dst_port:     Optional[int]  = None
    protocol:     Optional[str]  = None

    # ── Identity / host ──────────────────────────────────────────────────────
    username:     Optional[str]  = None
    hostname:     Optional[str]  = None
    process_name: Optional[str]  = None
    file_hash:    Optional[str]  = None

    # ── Action ───────────────────────────────────────────────────────────────
    action:       Optional[str]  = None   # allow | deny | block | alert
    rule_id:      Optional[str]  = None

    # ── Geo enrichment (populated by enrichment.py, Phase 3) ─────────────────
    geo_country:  Optional[str]  = None
    geo_city:     Optional[str]  = None
    geo_lat:      Optional[float] = None
    geo_lon:      Optional[float] = None

    # ── Threat enrichment (populated by enrichment.py, Phase 3) ──────────────
    abuse_score:   Optional[int]  = None
    relevant_cves: list           = field(default_factory=list)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    mitre_tactic:    Optional[str] = None
    mitre_technique: Optional[str] = None

    # ── Scoring / triage ─────────────────────────────────────────────────────
    severity_score: Optional[float] = None

    # ── Error tracking ───────────────────────────────────────────────────────
    parse_error: Optional[str] = None

    # ── Tags ─────────────────────────────────────────────────────────────────
    tags: list = field(default_factory=list)

    def to_db_dict(self) -> dict:
        """Return dict suitable for inserting into the events table."""
        return {
            "timestamp":         self.timestamp,
            "source_format":     self.source_format,
            "source_identifier": self.source_identifier,
            "event_type":        self.event_type,
            "severity":          self.severity,
            "raw_log":           self.raw_log,
            "src_ip":            self.src_ip,
            "dst_ip":            self.dst_ip,
            "src_port":          self.src_port,
            "dst_port":          self.dst_port,
            "protocol":          self.protocol,
            "username":          self.username,
            "hostname":          self.hostname,
            "process_name":      self.process_name,
            "file_hash":         self.file_hash,
            "action":            self.action,
            "rule_id":           self.rule_id,
            "geo_country":       self.geo_country,
            "geo_city":          self.geo_city,
            "geo_lat":           self.geo_lat,
            "geo_lon":           self.geo_lon,
            "abuse_score":       self.abuse_score,
            "relevant_cves":     self.relevant_cves or [],
            "mitre_tactic":      self.mitre_tactic,
            "mitre_technique":   self.mitre_technique,
            "severity_score":    self.severity_score,
            "tags":              self.tags or [],
            "triage_status":     "pending",
        }


# ── Parser auto-detection (G-04 order) ────────────────────────────────────────
_PARSER_ORDER = [
    ("cef",            lambda s: "CEF:" in s),
    ("syslog",         lambda s: s.startswith("<") and any(m in s for m in ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"])),
    ("windows_evtlog", lambda s: _is_json(s) and "EventID" in s),
    ("cloudtrail",     lambda s: _is_json(s) and "eventVersion" in s and "eventName" in s),
    ("generic_json",   lambda s: _is_json(s) and "timestamp" in s.lower()),
    ("csv",            lambda s: "," in s and not s.strip().startswith("{")),
]


def _is_json(s: str) -> bool:
    import json
    try:
        json.loads(s)
        return True
    except Exception:
        return False


def normalize(raw_log: str) -> CommonEvent:
    """Auto-detect format and parse raw_log into a CommonEvent.

    Follows the detection order from G-04:
    CEF → Syslog → Windows Event Log → CloudTrail → Generic JSON → CSV → quarantine
    """
    raw_log = raw_log.strip()
    if not raw_log:
        return CommonEvent(
            timestamp=datetime.utcnow(),
            source_format="unknown",
            source_identifier="unknown",
            event_type="empty_log",
            severity="LOW",
            raw_log=raw_log,
            parse_error="empty_input",
        )

    for fmt, detector in _PARSER_ORDER:
        if detector(raw_log):
            try:
                module = importlib.import_module(f"services.ingestion.parsers.{fmt}")
                return module.parse(raw_log)
            except Exception as exc:
                logger.warning("Parser %s failed: %s", fmt, exc)
                # Fall through to next parser

    # Nothing matched — quarantine (G-04: DO NOT DROP)
    logger.warning("Unknown log format, quarantining: %.100s", raw_log)
    return CommonEvent(
        timestamp=datetime.utcnow(),
        source_format="unknown",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error="unknown_format",
    )
