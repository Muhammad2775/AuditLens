from __future__ import annotations

from collections import defaultdict

from Configuration import BRUTE_FORCE_FAILED_THRESHOLD
from Models import DetectionResult, Event
from Utilities.time_utils import minutes_between

def _is_failed_login(event: Event) -> bool:
    text = f"{event.action} {event.message} {event.outcome}".lower()
    return (
        "failed_login" in text
        or ("login_attempt" in text and "failure" in text)
        or "invalid password" in text
        or ("failed" in text and "login" in text)
    )

def _is_successful_login(event: Event) -> bool:
    text = f"{event.action} {event.message} {event.outcome}".lower()
    return (
        "successful_login" in text
        or ("login_attempt" in text and "success" in text)
        or "login successful" in text
        or ("success" in text and "login" in text)
    )

def detect_brute_force(events: list[Event]) -> DetectionResult:
    groups: dict[str, list[Event]] = defaultdict(list)

    for event in sorted(events, key=lambda e: e.timestamp):
        key = "|".join([event.user, event.ip_address, event.host]).strip("|") or event.source_file
        groups[key].append(event)

    details: list[str] = []
    evidence: list[Event] = []

    for key, seq in groups.items():
        failures = []
        success = None

        for event in seq:
            if _is_failed_login(event):
                failures.append(event)
            elif _is_successful_login(event) and len(failures) >= BRUTE_FORCE_FAILED_THRESHOLD:
                success = event
                break

        if success and failures:
            if minutes_between(failures[-1].timestamp, success.timestamp) <= 15:
                details.append(
                    f"{key}: {len(failures)} failed login(s) followed by success at {success.timestamp.isoformat()}."
                )
                evidence.extend(failures)
                evidence.append(success)

    triggered = bool(details)
    confidence = 0.92 if triggered else 0.0
    summary = (
        "Failed logins were followed by a successful login, which is consistent with a brute-force or credential-guessing pattern."
        if triggered
        else "No brute-force pattern detected."
    )
    recommendation = (
        "Verify whether the account, source IP, and login timing are expected before escalation."
        if triggered
        else ""
    )

    return DetectionResult(
        name="brute_force",
        triggered=triggered,
        confidence=confidence,
        summary=summary,
        details=details,
        evidence=evidence,
        recommendation=recommendation,
    )

def detect_privilege_escalation(events: list[Event]) -> DetectionResult:
    evidence: list[Event] = []
    details: list[str] = []

    for event in events:
        text = f"{event.action} {event.message} {event.event_category}".lower()
        if event.event_category == "privilege" or "administrators group" in text or "group_change" in text:
            evidence.append(event)
            details.append(
                f"{event.timestamp.isoformat()}: privilege-related event on {event.host} by {event.user}."
            )

    triggered = bool(details)
    confidence = 0.88 if triggered else 0.0
    summary = (
        "Privilege-related activity was detected, including a potential group membership change."
        if triggered
        else "No privilege escalation detected."
    )
    recommendation = (
        "Confirm approval records and compare the event against the access-control policy."
        if triggered
        else ""
    )

    return DetectionResult(
        name="privilege_escalation",
        triggered=triggered,
        confidence=confidence,
        summary=summary,
        details=details,
        evidence=evidence,
        recommendation=recommendation,
    )

def detect_suspicious_process_chain(events: list[Event]) -> DetectionResult:
    evidence: list[Event] = []
    details: list[str] = []

    ordered = sorted(events, key=lambda e: e.timestamp)
    for event in ordered:
        process = (event.process_name or "").lower()
        parent = (event.parent_process_name or "").lower()
        if process == "cmd.exe" and parent == "winword.exe":
            evidence.append(event)
            details.append(
                f"{event.timestamp.isoformat()}: cmd.exe launched from winword.exe on {event.host}."
            )
        if process == "powershell.exe" and parent == "cmd.exe":
            evidence.append(event)
            details.append(
                f"{event.timestamp.isoformat()}: powershell.exe launched from cmd.exe on {event.host}."
            )
        if process == "net.exe" and parent == "powershell.exe":
            evidence.append(event)
            details.append(
                f"{event.timestamp.isoformat()}: net.exe launched from powershell.exe on {event.host}."
            )

    triggered = any("cmd.exe launched from winword.exe" in d for d in details) and any(
        "powershell.exe launched from cmd.exe" in d for d in details
    )
    confidence = 0.9 if triggered else 0.0
    summary = (
        "Suspicious process chaining was detected, consistent with document-to-shell execution."
        if triggered
        else "No suspicious process chain detected."
    )
    recommendation = (
        "Check whether the source document or user action is expected and isolate the host if necessary."
        if triggered
        else ""
    )

    return DetectionResult(
        name="suspicious_process_chain",
        triggered=triggered,
        confidence=confidence,
        summary=summary,
        details=details,
        evidence=evidence,
        recommendation=recommendation,
    )

def detect_restricted_access(events: list[Event]) -> DetectionResult:
    evidence: list[Event] = []
    details: list[str] = []

    for event in events:
        text = f"{event.action} {event.message} {event.event_category}".lower()
        if any(term in text for term in ["audit archive", "sensitive", "restricted", "confidential"]):
            evidence.append(event)
            details.append(
                f"{event.timestamp.isoformat()}: restricted or sensitive access on {event.host} by {event.user}."
            )

    triggered = bool(details)
    confidence = 0.8 if triggered else 0.0
    summary = (
        "Sensitive or restricted resource access was observed."
        if triggered
        else "No restricted access detected."
    )
    recommendation = (
        "Verify whether this access is approved and whether it matches the expected role or maintenance window."
        if triggered
        else ""
    )

    return DetectionResult(
        name="restricted_access",
        triggered=triggered,
        confidence=confidence,
        summary=summary,
        details=details,
        evidence=evidence,
        recommendation=recommendation,
    )

def run_all_detections(events: list[Event]) -> list[DetectionResult]:
    return [
        detect_brute_force(events),
        detect_privilege_escalation(events),
        detect_suspicious_process_chain(events),
        detect_restricted_access(events),
    ]
