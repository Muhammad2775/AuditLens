from __future__ import annotations

from Models import Event
from Utilities.time_utils import format_timestamp

def build_timeline(events: list[Event]) -> list[str]:
    lines: list[str] = []
    for event in sorted(events, key=lambda e: e.timestamp):
        actor = event.user or event.process_name or event.host or "unknown"
        target = event.host or event.ip_address or ""
        msg = event.message or event.action
        lines.append(
            f"{format_timestamp(event.timestamp)} | actor={actor} | target={target} | action={event.action} | {msg}"
        )
    return lines
