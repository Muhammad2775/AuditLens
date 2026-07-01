from __future__ import annotations

from Models import Event
from Utilities.time_utils import parse_timestamp
from Utilities.text_utils import normalize_whitespace

def normalize_severity(value: str) -> str:
    value = (value or "").strip().lower()
    if value in {"low", "medium", "high", "critical"}:
        return value
    return "low"

def infer_event_category(action: str, message: str, process_name: str = "") -> str:
    text = f"{action} {message} {process_name}".lower()

    if any(term in text for term in ["login", "authentication", "password"]):
        return "authentication"
    if any(term in text for term in ["group_change", "privilege", "administrators", "sudo"]):
        return "privilege"
    if any(term in text for term in ["powershell", "cmd.exe", "process", "process execution"]):
        return "process_execution"
    if any(term in text for term in ["file_access", "download", "audit archive", "sensitive"]):
        return "resource_access"
    if any(term in text for term in ["policy", "playbook", "rule"]):
        return "policy"
    return "system_activity"

def normalize_event(record: dict, source_file: str) -> Event:
    timestamp_raw = (
        record.get("timestamp")
        or record.get("time")
        or record.get("date")
        or ""
    )

    if not timestamp_raw:
        raise ValueError(f"Missing timestamp in {source_file}")

    timestamp = parse_timestamp(str(timestamp_raw))

    host = normalize_whitespace(str(record.get("host", "")))
    user = normalize_whitespace(str(record.get("user", "")))
    ip_address = normalize_whitespace(str(record.get("ip_address", record.get("ip", ""))))
    action = normalize_whitespace(str(record.get("action", "")))
    severity = normalize_severity(str(record.get("severity", "")))
    message = normalize_whitespace(str(record.get("message", "")))
    session_id = normalize_whitespace(str(record.get("session_id", "")))
    outcome = normalize_whitespace(str(record.get("outcome", "")))
    process_name = normalize_whitespace(str(record.get("process_name", "")))
    parent_process_name = normalize_whitespace(str(record.get("parent_process_name", "")))

    if not action and record.get("record_kind") == "event":
        action = normalize_whitespace(str(record.get("event", "")))

    category = normalize_whitespace(str(record.get("event_category", "")))
    if not category:
        category = infer_event_category(action, message, process_name)

    raw = dict(record)
    raw["source_file"] = source_file

    return Event(
        timestamp=timestamp,
        source_file=source_file,
        source_type=str(record.get("source_type", "event")),
        host=host,
        user=user,
        ip_address=ip_address,
        action=action,
        severity=severity,
        event_category=category,
        message=message,
        session_id=session_id,
        outcome=outcome,
        process_name=process_name,
        parent_process_name=parent_process_name,
        raw=raw,
    )
