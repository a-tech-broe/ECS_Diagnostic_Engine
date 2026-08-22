"""Prometheus collection through the HTTP API (/api/v1/query and /api/v1/query_range).

Baselines are taken with the *same* PromQL evaluated at ``now - baseline_offset``
via the instant query's ``time`` parameter, so no query rewriting is required.
"""

from __future__ import annotations

import time as _time
from typing import Any, Optional

from ..config import Config
from ..httpclient import HttpError, join_url, request_json
from ..models import MetricSample, MetricsSnapshot
from ..timeutil import parse_duration

# Metrics worth pulling as a time series for the deployment timeline.
SERIES_METRICS = ("cpu_pct", "memory_pct", "error_rate", "latency_p95", "restarts")


class PrometheusCollector:
    def __init__(self, config: Config):
        self.config = config
        self.prom = config.prometheus

    # -- raw API ----------------------------------------------------------

    def instant(self, query: str, at: Optional[float] = None) -> Optional[float]:
        payload = self._get("/api/v1/query", {"query": query, "time": at})
        return _first_scalar(payload)

    def range(self, query: str, start: float, end: float, step: float) -> list[tuple[float, float]]:
        payload = self._get(
            "/api/v1/query_range", {"query": query, "start": start, "end": end, "step": step}
        )
        result = (payload.get("data", {}) or {}).get("result", []) or []
        if not result:
            return []
        return [(float(ts), float(value)) for ts, value in result[0].get("values", []) if _is_number(value)]

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        payload = request_json(
            join_url(self.prom.url or "", path),
            params=params,
            timeout=self.prom.timeout_seconds,
            verify_tls=self.prom.verify_tls,
            bearer_token=self.prom.bearer_token,
            username=self.prom.username,
            password=self.prom.password,
        )
        if payload.get("status") == "error":
            raise HttpError(f"Prometheus error: {payload.get('error', 'unknown')}")
        return payload

    # -- collection -------------------------------------------------------

    def collect(self, cluster: str, service: str) -> MetricsSnapshot:
        if not self.prom.enabled:
            return MetricsSnapshot(available=False, error="Prometheus is not configured")

        variables = self.config.query_vars(cluster, service)
        snapshot = MetricsSnapshot()
        now = _time.time()
        window_seconds = self.config.window_minutes * 60
        baseline_offset = parse_duration(self.prom.baseline_offset, 86400.0)
        step = max(30.0, window_seconds / 30.0)

        for name, template in self.prom.queries.items():
            try:
                query = template.format(**variables)
            except KeyError as exc:
                snapshot.samples[name] = MetricSample(
                    name=name, query=template, error=f"unknown placeholder {exc} in query template"
                )
                continue

            sample = MetricSample(name=name, query=query, unit=_unit_for(name))
            try:
                sample.value = self.instant(query)
                if name in self.prom.baseline_metrics:
                    sample.baseline = self.instant(query, at=now - baseline_offset)
                if name in SERIES_METRICS:
                    sample.series = self.range(query, now - window_seconds, now, step)
            except HttpError as exc:
                sample.error = str(exc)
            snapshot.samples[name] = sample

        if snapshot.samples and all(s.error for s in snapshot.samples.values()):
            snapshot.available = False
            snapshot.error = next(iter(snapshot.samples.values())).error
        return snapshot


def _unit_for(name: str) -> str:
    if name.endswith("_pct") or name == "availability":
        return "%"
    if name.startswith("latency"):
        return "s"
    if name.endswith("_bytes"):
        return "B"
    if name.endswith("_rate"):
        return "/s"
    return ""


def _is_number(value: Any) -> bool:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return False
    return parsed == parsed  # filter NaN


def _first_scalar(payload: dict[str, Any]) -> Optional[float]:
    data = payload.get("data", {}) or {}
    result = data.get("result", []) or []
    if not result:
        return None
    if data.get("resultType") == "scalar":
        return float(result[1]) if _is_number(result[1]) else None
    value = result[0].get("value")
    if not value or len(value) < 2 or not _is_number(value[1]):
        return None
    return float(value[1])
