"""AWS CloudTrail JSON parser.
Severity: errorCode null=INFO/LOW, else HIGH. Sensitive APIs=HIGH regardless.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from services.ingestion.normalizer import CommonEvent

# API calls that always warrant HIGH severity even without error
_SENSITIVE_APIS = {
    "CreateUser", "DeleteUser", "AttachUserPolicy", "PutUserPolicy",
    "CreateAccessKey", "DeleteAccessKey",
    "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
    "CreateRole", "DeleteRole", "AttachRolePolicy", "PutRolePolicy",
    "CreateGroup", "AddUserToGroup",
    "StopLogging", "DeleteTrail", "UpdateTrail",
    "DeleteLogGroup", "DisableRule",
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
    "RunInstances", "TerminateInstances",
    "GetSecretValue", "DeleteSecret", "PutSecretValue",
    "ConsoleLogin",
}

_EVENTNAME_TYPE = {
    "ConsoleLogin": "auth_success",
    "ConsoleLoginFailed": "auth_failure",
    "AssumeRole": "credential_access",
    "GetSecretValue": "credential_access",
    "CreateUser": "account_creation",
    "DeleteUser": "account_deletion",
    "StopLogging": "defense_evasion",
    "DeleteTrail": "defense_evasion",
    "RunInstances": "resource_creation",
    "TerminateInstances": "resource_deletion",
    "AuthorizeSecurityGroupIngress": "network_change",
}


def parse(raw_log: str) -> CommonEvent:
    try:
        data = json.loads(raw_log)
        event_name = data.get("eventName", "UnknownAPI")
        error_code = data.get("errorCode")
        error_msg = data.get("errorMessage", "")

        # Severity determination
        if error_code:
            severity = "HIGH"
        elif event_name in _SENSITIVE_APIS:
            severity = "HIGH"
        else:
            severity = "LOW"

        # Timestamp
        ts_str = data.get("eventTime")
        timestamp = _parse_ts(ts_str)

        # Source identifier
        source_ip = (data.get("sourceIPAddress") or
                     data.get("requestParameters", {}).get("sourceIPAddress") or
                     "unknown")
        source_id = source_ip

        # Event type
        event_type = _EVENTNAME_TYPE.get(event_name, _camel_to_snake(event_name))

        # Identity
        user_identity = data.get("userIdentity") or {}
        username = (user_identity.get("userName") or
                    user_identity.get("principalId") or
                    user_identity.get("type"))

        # Process / service
        process_name = data.get("eventSource", "").replace(".amazonaws.com", "")

        # Hostname from requestParameters if available
        req_params = data.get("requestParameters") or {}
        hostname = (req_params.get("instanceId") or
                    req_params.get("resourceId") or
                    data.get("recipientAccountId"))

        return CommonEvent(
            timestamp=timestamp,
            source_format="cloudtrail",
            source_identifier=source_id,
            event_type=event_type,
            severity=severity,
            raw_log=raw_log,
            src_ip=source_ip if _is_ip(source_ip) else None,
            username=username,
            hostname=hostname,
            process_name=process_name,
            tags=_build_tags(data, error_code),
        )
    except Exception as exc:
        return _fallback(raw_log, str(exc))


def _parse_ts(ts_str: str | None) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _camel_to_snake(name: str) -> str:
    import re
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def _is_ip(val: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val or ""))


def _build_tags(data: dict, error_code: str | None) -> list:
    tags = [f"region:{data.get('awsRegion', 'unknown')}"]
    if error_code:
        tags.append(f"error:{error_code}")
    if data.get("userIdentity", {}).get("type") == "Root":
        tags.append("root_access")
    return tags


def _fallback(raw_log: str, err: str = "cloudtrail_parse_error") -> CommonEvent:
    return CommonEvent(
        timestamp=datetime.now(timezone.utc),
        source_format="cloudtrail",
        source_identifier="unknown",
        event_type="unknown",
        severity="MEDIUM",
        raw_log=raw_log,
        parse_error=err,
    )