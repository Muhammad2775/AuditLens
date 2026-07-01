from __future__ import annotations

from datetime import datetime, timezone

def parse_timestamp(value: str) -> datetime:
    value = (value or "").strip()
    if not value:
        raise ValueError("Empty timestamp")

    candidates = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
    ]

    for fmt in candidates:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError(f"Unsupported timestamp format: {value}") from exc

def format_timestamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def minutes_between(a: datetime, b: datetime) -> float:
    return abs((b - a).total_seconds()) / 60.0

def within_window(a: datetime, b: datetime, minutes: int) -> bool:
    return minutes_between(a, b) <= minutes

def now_utc() -> datetime:
    return datetime.now(timezone.utc)