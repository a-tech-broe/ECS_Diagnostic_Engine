"""Collector interfaces plus no-op implementations for unconfigured backends."""

from __future__ import annotations

from typing import Optional, Protocol

from ..models import AlbSnapshot, LogSnapshot, MetricsSnapshot, ServiceSnapshot


class CollectorError(RuntimeError):
    """Raised when an upstream is unreachable or answers with something unusable."""


class EcsCollector(Protocol):
    def list_services(self, cluster: str) -> list[str]: ...

    def describe_services(self, cluster: str, services: list[str]) -> list[ServiceSnapshot]: ...

    def enrich_tasks(self, snapshot: ServiceSnapshot) -> ServiceSnapshot: ...


class AlbCollector(Protocol):
    def collect(self, snapshot: ServiceSnapshot, window_minutes: int) -> Optional[AlbSnapshot]: ...


class MetricCollector(Protocol):
    def collect(self, cluster: str, service: str) -> MetricsSnapshot: ...


class LogCollector(Protocol):
    def collect(self, cluster: str, service: str) -> LogSnapshot: ...


class NullAlbCollector:
    def collect(self, snapshot: ServiceSnapshot, window_minutes: int) -> Optional[AlbSnapshot]:
        return None


class NullMetricCollector:
    reason = "Prometheus is not configured"

    def collect(self, cluster: str, service: str) -> MetricsSnapshot:
        return MetricsSnapshot(available=False, error=self.reason)


class NullLogCollector:
    reason = "Splunk is not configured"

    def collect(self, cluster: str, service: str) -> LogSnapshot:
        return LogSnapshot(available=False, error=self.reason)
