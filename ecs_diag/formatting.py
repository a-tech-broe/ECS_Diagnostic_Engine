"""Number and unit formatting shared by rules (evidence strings) and reports."""

from __future__ import annotations

from typing import Optional


def num(value: Optional[float], digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if value != value:  # NaN
        return "n/a"
    if abs(value) >= 1000:
        return f"{value:,.0f}"
    if float(value).is_integer():
        return f"{value:.0f}"
    return f"{value:.{digits}f}"


def pct(value: Optional[float], digits: int = 1) -> str:
    return "n/a" if value is None else f"{num(value, digits)}%"


def seconds(value: Optional[float]) -> str:
    """Render a duration in the unit an engineer would use out loud."""
    if value is None:
        return "n/a"
    if value < 1:
        return f"{value * 1000:.0f}ms"
    return f"{value:.2f}s"


def delta(value: Optional[float], digits: int = 0) -> str:
    if value is None:
        return "n/a"
    if value in (float("inf"), float("-inf")):
        return "new"
    sign = "+" if value >= 0 else ""
    return f"{sign}{value:.{digits}f}%"


def bytes_human(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TiB"


def plural(count: float, singular: str, plural_form: Optional[str] = None) -> str:
    word = singular if count == 1 else (plural_form or f"{singular}s")
    return f"{num(count)} {word}"
