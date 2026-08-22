"""Fixture-backed collectors: run the whole engine offline from JSON on disk.

A fixture directory may contain any of::

    services.json      raw DescribeServices shape, or a bare list of services
    tasks.json         {"<service>": {"running": [...], "stopped": [...]}}
    alb.json           {"<service>": {"target_groups": [...], "http_5xx": 12, ...}}
    prometheus.json    {"<service>": {"cpu_pct": {"value": 96, "baseline": 58}}}
    splunk.json        {"<service>": {"level_counts": {...}, "top_errors": [...]}}

Single-service fixtures may drop the service key and give the payload directly.
Timestamps accept ISO-8601, epoch seconds, or relative offsets like ``-6m``,
which keeps a checked-in incident looking like it is happening right now.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from ..models import (
    AlbSnapshot,
    LogPattern,
    LogSnapshot,
    MetricSample,
    MetricsSnapshot,
    ServiceSnapshot,
    TargetGroupHealth,
)
from ..timeutil import parse_time
from .base import CollectorError
from .ecs import parse_service, parse_task


class FixtureStore:
    """Loads and caches the JSON documents that back the offline collectors."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        if not self.path.exists():
            raise CollectorError(f"fixture path does not exist: {self.path}")
        self._cache: dict[str, Any] = {}

    def document(self, name: str) -> Any:
        if name in self._cache:
            return self._cache[name]
        candidate = self.path if self.path.is_file() and self.path.name == name else self.path / name
        data: Any = {}
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text())
            except json.JSONDecodeError as exc:
                raise CollectorError(f"invalid JSON in {candidate}: {exc}") from exc
        self._cache[name] = data
        return data

    def for_service(self, name: str, service: str, marker_keys: tuple[str, ...]) -> Any:
        """Return the per-service slice of a document, tolerating the flat form."""
        data = self.document(name)
        if not isinstance(data, dict) or not data:
            return data
        if service in data:
            return data[service]
        if any(key in data for key in marker_keys):
            return data          # flat, single-service document
        return {}


class FixtureEcsCollector:
    def __init__(self, store: FixtureStore, cluster_default: str = "fixture"):
        self.store = store
        self.cluster_default = cluster_default

    def _raw_services(self) -> list[dict[str, Any]]:
        data = self.store.document("services.json")
        if isinstance(data, dict):
            data = data.get("services", [])
        if not isinstance(data, list):
            raise CollectorError("services.json must be a list or a {'services': [...]} object")
        return data

    def list_services(self, cluster: str) -> list[str]:
        return [s.get("serviceName", "unknown") for s in self._raw_services()]

    def describe_services(self, cluster: str, services: list[str]) -> list[ServiceSnapshot]:
        wanted = {s.rsplit("/", 1)[-1] for s in services}
        snapshots = []
        for raw in self._raw_services():
            name = raw.get("serviceName", "unknown")
            if wanted and name not in wanted:
                continue
            snapshots.append(parse_service(raw, cluster or self.cluster_default))
        missing = wanted - {s.service_name for s in snapshots}
        if missing:
            raise CollectorError(
                f"no fixture for service(s): {', '.join(sorted(missing))} in {self.store.path}"
            )
        return snapshots

    def enrich_tasks(self, snapshot: ServiceSnapshot) -> ServiceSnapshot:
        payload = self.store.for_service("tasks.json", snapshot.service_name, ("running", "stopped"))
        if isinstance(payload, dict):
            snapshot.running_tasks = [parse_task(t) for t in payload.get("running", []) or []]
            snapshot.stopped_tasks = [parse_task(t) for t in payload.get("stopped", []) or []]
        snapshot.tasks_collected = True
        return snapshot


class FixtureAlbCollector:
    def __init__(self, store: FixtureStore):
        self.store = store

    def collect(self, snapshot: ServiceSnapshot, window_minutes: int) -> Optional[AlbSnapshot]:
        payload = self.store.for_service(
            "alb.json", snapshot.service_name, ("target_groups", "request_count", "http_5xx")
        )
        if not payload:
            return None
        alb = AlbSnapshot(
            request_count=_float(payload.get("request_count")),
            http_4xx=_float(payload.get("http_4xx")),
            http_5xx=_float(payload.get("http_5xx")),
            target_5xx=_float(payload.get("target_5xx")),
            target_connection_errors=_float(payload.get("target_connection_errors")),
            target_response_time_p95=_float(payload.get("target_response_time_p95")),
        )
        for tg in payload.get("target_groups", []) or []:
            alb.target_groups.append(
                TargetGroupHealth(
                    target_group_arn=tg.get("target_group_arn", "fixture"),
                    target_group_name=tg.get("target_group_name"),
                    healthy=int(tg.get("healthy", 0) or 0),
                    unhealthy=int(tg.get("unhealthy", 0) or 0),
                    initial=int(tg.get("initial", 0) or 0),
                    draining=int(tg.get("draining", 0) or 0),
                    unused=int(tg.get("unused", 0) or 0),
                    unhealthy_reasons=list(tg.get("unhealthy_reasons", []) or []),
                )
            )
        return alb


class FixtureMetricCollector:
    def __init__(self, store: FixtureStore):
        self.store = store

    def collect(self, cluster: str, service: str) -> MetricsSnapshot:
        payload = self.store.for_service("prometheus.json", service, ("cpu_pct", "memory_pct", "latency_p95"))
        if not payload:
            return MetricsSnapshot(available=False, error="no Prometheus fixture for this service")
        snapshot = MetricsSnapshot()
        for name, raw in payload.items():
            if isinstance(raw, dict):
                snapshot.samples[name] = MetricSample(
                    name=name,
                    value=_float(raw.get("value")),
                    baseline=_float(raw.get("baseline")),
                    unit=raw.get("unit", ""),
                    query=raw.get("query"),
                    error=raw.get("error"),
                    series=_series(raw.get("series")),
                )
            else:
                snapshot.samples[name] = MetricSample(name=name, value=_float(raw))
        return snapshot


class FixtureLogCollector:
    def __init__(self, store: FixtureStore):
        self.store = store

    def collect(self, cluster: str, service: str) -> LogSnapshot:
        payload = self.store.for_service(
            "splunk.json", service, ("level_counts", "top_errors", "top_exceptions")
        )
        if not payload:
            return LogSnapshot(available=False, error="no Splunk fixture for this service")
        return LogSnapshot(
            level_counts={str(k).upper(): int(v) for k, v in (payload.get("level_counts") or {}).items()},
            top_errors=_patterns(payload.get("top_errors")),
            top_exceptions=_patterns(payload.get("top_exceptions")),
            sample_messages=[str(m) for m in payload.get("sample_messages", []) or []],
        )


def _series(raw: Any) -> list[tuple[float, float]]:
    """Series points accept epoch seconds or a relative stamp like "-4m"."""
    points: list[tuple[float, float]] = []
    for item in raw or []:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        stamp, value = item
        when = parse_time(stamp)
        if when is None:
            continue
        numeric = _float(value)
        if numeric is not None:
            points.append((when.timestamp(), numeric))
    return sorted(points)


def _patterns(raw: Any) -> list[LogPattern]:
    patterns: list[LogPattern] = []
    for item in raw or []:
        if isinstance(item, dict):
            text = item.get("text") or item.get("error") or item.get("exception") or ""
            patterns.append(LogPattern(text=str(text), count=int(item.get("count", 0) or 0)))
        else:
            patterns.append(LogPattern(text=str(item)))
    return patterns


def _float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
