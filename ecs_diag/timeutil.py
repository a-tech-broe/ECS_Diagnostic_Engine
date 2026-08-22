"""Timestamp parsing shared by the live collectors and the fixture loader."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_RELATIVE = re.compile(r"^\s*([+-])\s*(\d+(?:\.\d+)?)\s*([smhd])\s*$", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_time(value: Any, now: Optional[datetime] = None) -> Optional[datetime]:
    """Parse a timestamp from ISO-8601, epoch seconds, a datetime, or "-6m".

    The relative form keeps checked-in fixtures perpetually fresh, so the demo
    report always looks like an incident that is happening right now.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        rel = _RELATIVE.match(value)
        if rel:
            sign, amount, unit = rel.groups()
            delta = timedelta(seconds=float(amount) * _UNITS[unit.lower()])
            base = now or datetime.now(timezone.utc)
            return base - delta if sign == "-" else base + delta
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def humanize_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "unknown"
    seconds = float(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


_DURATION = re.compile(r"(\d+(?:\.\d+)?)\s*([smhdw])", re.IGNORECASE)
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str, default: float = 0.0) -> float:
    """Parse a Prometheus-style duration ("15m", "1h30m", "7d") into seconds."""
    if text is None:
        return default
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        return float(text)
    matches = _DURATION.findall(str(text))
    if not matches:
        return default
    return sum(float(amount) * _DURATION_UNITS[unit.lower()] for amount, unit in matches)
