"""Syslog RFC 5424 / RFC 3164 parser.
Severity mapping: emerg/alert/crit=CRITICAL, err=HIGH, warning=MEDIUM, notice/info/debug=LOW
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from services.ingestion.normalizer import CommonEvent

# Priority keyword → severity
_KEYWORD_SEV = {
    "emerg": "CRITICAL", "emergency": "CRITICAL",
    "alert": "CRITICAL",
    "crit": "CRITICAL", "critical": "CRITICAL",
    "err": "HIGH", "error": "HIGH",
    "warn": "MEDIUM", "warning": "MEDIUM",
    "notice": "LOW",
    "info": "LOW", "information": "LOW",
    "debug": "LOW",
}

# Syslog facility/severity from PRI value
_PRI_SEV = ["CRITICAL", "CRITICAL", "CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW", "LOW"]

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
_RFC5424 = re.compile(
    r"<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]\s*)?(.*)",
    re.DOTALL,
)

# RFC 3164: <PRI>MONTH DAY HH:MM:SS HOSTNAME TAG: MSG
_RFC3164 = re.compile(
    r"<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)",
    re.DOTALL,
)


def parse(raw_log: str) -> CommonEvent:
    try:
        m5 = _RFC5424.match(raw_log.strip())
        if m5:
            return _parse_rfc5424(raw_log, m5)

        m3 = _RFC3164.match(raw_log.strip())
        if m3:
            return _parse_rfc3164(raw_log, m3)

        return _fallback(raw_log)
    except Exception as exc:
        return _fallback(raw_log, str(exc))


def _parse_rfc5424(raw_log: str, m) -> CommonEvent:
    pri, version, timestamp_str, hostname, appname, procid, msgid, msg = m.groups()

    severity = _pri_to_sev(int(pri))
    timestamp = _parse_iso(timestamp_str)
    event_type = _classify_message(msg, appname)
    src_ip, username = _extract_ip_user(msg)
    action = _extract_action(msg)

    return CommonEvent(
        timestamp=timestamp,
        source_format="syslog",
        source_identifier=hostname if hostname != "-" else "unknown",
        event_type=event_type,
        severity=severity,
        raw_log=raw_log,
        src_ip=src_ip,
        username=username,
        hostname=hostname if hostname != "-" else None,
        process_name=appname if appname != "-" else None,
        action=action,
    )


def _parse_rfc3164(raw_log: str, m) -> CommonEvent:
    pri, timestamp_str, hostname, tag, msg = m.groups()

    severity = _pri_to_sev(int(pri))
    timestamp = _parse_rfc3164_time(timestamp_str)
    event_type = _classify_message(msg, tag)
    src_ip, username = _extract_ip_user(msg)
    action = _extract_action(msg)

    return CommonEvent(
        timestamp=timestamp,
        source_format="syslog",
        source_identifier=hostname,
        event_type=event_type,
        severity=severity,
        raw_log=raw_log,
        src_ip=src_ip,
        username=username,
        hostname=hostname,
        process_name=tag.strip(),
        action=action,
    )


def _pri_to_sev(pri: int) -> str:
    """Convert PRI value to ACCC severity. PRI = facility*8 + severity_level."""
    sev_level = pri % 8
    return _PRI_SEV[min(sev_level, 7)]


def _parse_iso(ts: str) -> datetime:
    if ts == "-":
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_rfc3164_time(ts: str) -> datetime:
    try:
        return datetime.strptime(ts.strip(), "%b %d %H:%M:%S").replace(
            year=datetime.now().year, tzinfo=timezone.utc
        )
    except ValueError:
        return datetime.now(timezone.utc)


def _classify_message(msg: str, appname: str) -> str:
    msg_l = (msg + " " + appname).lower()
    if any(x in msg_l for x in ["authentication failure", "failed password", "invalid user", "login fail"]):
        return "auth_failure"
    if any(x in msg_l for x in ["port scan", "nmap", "scanning"]):
        return "port_scan"
    if any(x in msg_l for x in ["accepted password", "session opened", "logged in"]):
        return "auth_success"
    if any(x in msg_l for x in ["connection refused", "connection reset"]):
        return "connection_event"
    if any(x in msg_l for x in ["sudo", "su:", "privilege"]):
        return "privilege_escalation"
    if any(x in msg_l for x in ["kernel", "oom", "segfault"]):
        return "system_error"
    return "syslog_event"


def _extract_ip_user(msg: str):
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", msg)
    src_ip = ip_match.group(1) if ip_match else None
    user_match = re.search(r"(?:user|for|from user)\s+(\S+)", msg, re.IGNORECASE)
    username = user_match.group(1) if user_match else None
    return src_ip, username


def _extract_action(msg: str) -> str | None:
    msg_l = msg.lower()
    if any(x in msg_l for x in ["blocked", "denied", "reject"]):
        return "block"
    if any(x in msg_l for x in ["allowed", "accepted", "permit"]):
        return "allow"
    return None


def _fallback(raw_log: str, err: str = "syslog_parse_error") -> CommonEvent:
    return CommonEvent(
        timestamp=datetime.now(timezone.utc),
        source_format="syslog",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error=err,
    )