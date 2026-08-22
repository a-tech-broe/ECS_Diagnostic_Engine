"""Core data model shared by collectors, rules, correlation and reporting.

Everything here is stdlib-only so the engine can be exercised without AWS,
Prometheus or Splunk reachable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _age_seconds(ts: Optional[datetime], now: Optional[datetime] = None) -> Optional[float]:
    if ts is None:
        return None
    return ((now or utcnow()) - ts).total_seconds()


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[self.value]


class Risk(str, Enum):
    LOW = "LOW"
    LOW_MEDIUM = "LOW/MEDIUM"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# --------------------------------------------------------------------------
# ECS
# --------------------------------------------------------------------------


@dataclass
class Container:
    name: str
    last_status: Optional[str] = None
    exit_code: Optional[int] = None
    reason: Optional[str] = None
    health_status: Optional[str] = None
    image: Optional[str] = None
    memory: Optional[int] = None          # MiB, from the task definition
    memory_reservation: Optional[int] = None
    cpu: Optional[int] = None

    @property
    def oom_killed(self) -> bool:
        """Exit code 137 is SIGKILL, which on ECS/Fargate is the OOM signature."""
        if self.exit_code == 137:
            return True
        text = " ".join(filter(None, [self.reason]))
        return "outofmemory" in text.lower().replace(" ", "")


@dataclass
class Task:
    task_arn: str
    last_status: Optional[str] = None
    desired_status: Optional[str] = None
    health_status: Optional[str] = None
    stopped_reason: Optional[str] = None
    stop_code: Optional[str] = None
    task_definition_arn: Optional[str] = None
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    availability_zone: Optional[str] = None
    containers: list[Container] = field(default_factory=list)

    @property
    def short_id(self) -> str:
        return self.task_arn.rsplit("/", 1)[-1]

    @property
    def oom_killed(self) -> bool:
        if self.stopped_reason and "outofmemory" in self.stopped_reason.lower().replace(" ", ""):
            return True
        return any(c.oom_killed for c in self.containers)

    @property
    def exit_codes(self) -> list[int]:
        return [c.exit_code for c in self.containers if c.exit_code is not None]

    def stopped_age_seconds(self, now: Optional[datetime] = None) -> Optional[float]:
        return _age_seconds(self.stopped_at, now)

    def lifetime_seconds(self) -> Optional[float]:
        if self.started_at and self.stopped_at:
            return (self.stopped_at - self.started_at).total_seconds()
        return None

    @property
    def reason_text(self) -> str:
        """Every failure string attached to the task, lowercased, for matching."""
        parts: list[str] = [self.stopped_reason or "", self.stop_code or ""]
        for c in self.containers:
            parts.append(c.reason or "")
        return " ".join(parts).lower()


@dataclass
class Deployment:
    id: str
    status: str                            # PRIMARY | ACTIVE | INACTIVE
    task_definition: Optional[str] = None
    desired_count: int = 0
    running_count: int = 0
    pending_count: int = 0
    failed_tasks: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    rollout_state: Optional[str] = None    # COMPLETED | FAILED | IN_PROGRESS
    rollout_state_reason: Optional[str] = None

    @property
    def is_primary(self) -> bool:
        return self.status == "PRIMARY"

    def age_seconds(self, now: Optional[datetime] = None) -> Optional[float]:
        return _age_seconds(self.created_at, now)

    def age_minutes(self, now: Optional[datetime] = None) -> Optional[float]:
        age = self.age_seconds(now)
        return None if age is None else age / 60.0

    @property
    def revision(self) -> Optional[str]:
        if not self.task_definition:
            return None
        return self.task_definition.rsplit("/", 1)[-1]


@dataclass
class ServiceEvent:
    created_at: Optional[datetime]
    message: str


@dataclass
class LoadBalancerRef:
    target_group_arn: Optional[str] = None
    load_balancer_name: Optional[str] = None
    container_name: Optional[str] = None
    container_port: Optional[int] = None


@dataclass
class ServiceSnapshot:
    """Everything DescribeServices / DescribeTasks tells us about one service."""

    cluster: str
    service_name: str
    status: str = "ACTIVE"
    desired_count: int = 0
    running_count: int = 0
    pending_count: int = 0
    launch_type: Optional[str] = None
    capacity_provider: Optional[str] = None
    health_check_grace_period_seconds: Optional[int] = None
    task_definition: Optional[str] = None
    platform_version: Optional[str] = None
    created_at: Optional[datetime] = None
    deployments: list[Deployment] = field(default_factory=list)
    events: list[ServiceEvent] = field(default_factory=list)
    running_tasks: list[Task] = field(default_factory=list)
    stopped_tasks: list[Task] = field(default_factory=list)
    load_balancers: list[LoadBalancerRef] = field(default_factory=list)
    # False until a collector has actually fetched task detail, so a report can
    # distinguish "no stopped tasks" from "we never looked".
    tasks_collected: bool = False

    @property
    def primary_deployment(self) -> Optional[Deployment]:
        for d in self.deployments:
            if d.is_primary:
                return d
        return self.deployments[0] if self.deployments else None

    @property
    def previous_deployment(self) -> Optional[Deployment]:
        """The most recently created non-PRIMARY deployment still hanging around."""
        others = [d for d in self.deployments if not d.is_primary]
        if not others:
            return None
        return sorted(others, key=lambda d: d.created_at or datetime.min.replace(tzinfo=timezone.utc))[-1]

    @property
    def is_converged(self) -> bool:
        return self.running_count == self.desired_count and self.pending_count == 0

    @property
    def missing_tasks(self) -> int:
        return max(0, self.desired_count - self.running_count)

    @property
    def availability_pct(self) -> float:
        if self.desired_count <= 0:
            return 100.0
        return 100.0 * self.running_count / self.desired_count

    def recent_stopped_tasks(self, within_seconds: float, now: Optional[datetime] = None) -> list[Task]:
        out = []
        for t in self.stopped_tasks:
            age = t.stopped_age_seconds(now)
            if age is None or age <= within_seconds:
                out.append(t)
        return out

    def recent_events(self, within_seconds: float, now: Optional[datetime] = None) -> list[ServiceEvent]:
        out = []
        for e in self.events:
            age = _age_seconds(e.created_at, now)
            if age is None or age <= within_seconds:
                out.append(e)
        return out


# --------------------------------------------------------------------------
# ALB
# --------------------------------------------------------------------------


@dataclass
class TargetGroupHealth:
    target_group_arn: str
    target_group_name: Optional[str] = None
    healthy: int = 0
    unhealthy: int = 0
    initial: int = 0
    draining: int = 0
    unused: int = 0
    unhealthy_reasons: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.healthy + self.unhealthy + self.initial + self.draining + self.unused


@dataclass
class AlbSnapshot:
    target_groups: list[TargetGroupHealth] = field(default_factory=list)
    request_count: Optional[float] = None
    http_4xx: Optional[float] = None
    http_5xx: Optional[float] = None
    target_5xx: Optional[float] = None
    target_connection_errors: Optional[float] = None
    target_response_time_p95: Optional[float] = None   # seconds

    @property
    def healthy_targets(self) -> int:
        return sum(tg.healthy for tg in self.target_groups)

    @property
    def unhealthy_targets(self) -> int:
        return sum(tg.unhealthy for tg in self.target_groups)

    @property
    def error_rate_5xx_pct(self) -> Optional[float]:
        total = self.request_count
        errors = self.http_5xx if self.http_5xx is not None else self.target_5xx
        if not total or errors is None:
            return None
        return 100.0 * errors / total

    @property
    def has_targets(self) -> bool:
        return bool(self.target_groups)


# --------------------------------------------------------------------------
# Metrics (Prometheus)
# --------------------------------------------------------------------------


@dataclass
class MetricSample:
    """One logical metric: its current value plus an optional pre-incident baseline."""

    name: str
    value: Optional[float] = None
    baseline: Optional[float] = None
    unit: str = ""
    query: Optional[str] = None
    error: Optional[str] = None
    series: list[tuple[float, float]] = field(default_factory=list)  # (epoch, value)

    @property
    def ok(self) -> bool:
        return self.error is None and self.value is not None

    @property
    def delta_pct(self) -> Optional[float]:
        if self.value is None or self.baseline is None:
            return None
        if self.baseline == 0:
            return None if self.value == 0 else float("inf")
        return 100.0 * (self.value - self.baseline) / self.baseline


@dataclass
class MetricsSnapshot:
    samples: dict[str, MetricSample] = field(default_factory=dict)
    available: bool = True
    error: Optional[str] = None

    def get(self, name: str) -> Optional[MetricSample]:
        s = self.samples.get(name)
        return s if (s and s.ok) else None

    def value(self, name: str, default: Optional[float] = None) -> Optional[float]:
        s = self.get(name)
        return default if s is None else s.value

    def baseline(self, name: str) -> Optional[float]:
        s = self.samples.get(name)
        return s.baseline if s else None

    def delta_pct(self, name: str) -> Optional[float]:
        s = self.get(name)
        return None if s is None else s.delta_pct


# --------------------------------------------------------------------------
# Logs (Splunk)
# --------------------------------------------------------------------------


@dataclass
class LogPattern:
    text: str
    count: int = 0


@dataclass
class LogSnapshot:
    level_counts: dict[str, int] = field(default_factory=dict)
    top_errors: list[LogPattern] = field(default_factory=list)
    top_exceptions: list[LogPattern] = field(default_factory=list)
    sample_messages: list[str] = field(default_factory=list)
    available: bool = True
    error: Optional[str] = None

    @property
    def error_count(self) -> int:
        return sum(v for k, v in self.level_counts.items() if k.upper() in ("ERROR", "FATAL", "CRITICAL"))

    @property
    def total_count(self) -> int:
        return sum(self.level_counts.values())

    def search(self, *needles: str) -> list[LogPattern]:
        """Return log patterns whose text mentions any of the given substrings."""
        found: list[LogPattern] = []
        lowered = [n.lower() for n in needles]
        for p in list(self.top_errors) + list(self.top_exceptions):
            text = p.text.lower()
            if any(n in text for n in lowered):
                found.append(p)
        for msg in self.sample_messages:
            if any(n in msg.lower() for n in lowered):
                found.append(LogPattern(text=msg, count=0))
        return found

    def mentions(self, *needles: str) -> bool:
        return bool(self.search(*needles))


# --------------------------------------------------------------------------
# Findings / recommendations
# --------------------------------------------------------------------------


@dataclass
class Evidence:
    source: str          # ECS | ALB | PROMETHEUS | SPLUNK | CORRELATION
    detail: str

    def __str__(self) -> str:
        return f"[{self.source}] {self.detail}"


@dataclass
class Recommendation:
    """A remediation *option*. The engine never runs any of these."""

    action: str
    why: str
    evidence: list[Evidence] = field(default_factory=list)
    risk: Risk = Risk.MEDIUM
    expected_effect: str = ""
    command: Optional[str] = None
    execution_status: str = "NOT PERFORMED"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)


@dataclass
class DeploymentCorrelation:
    correlated: bool = False
    confidence: Confidence = Confidence.LOW
    probability: str = "LOW"                       # LOW | MEDIUM | HIGH
    deployment_age_minutes: Optional[float] = None
    current_version: Optional[str] = None
    previous_version: Optional[str] = None
    observed_changes: list[tuple[str, str]] = field(default_factory=list)   # (label, "+38%")
    pre_deployment_changes: list[tuple[str, str]] = field(default_factory=list)  # degraded before the deploy
    timeline: list[tuple[str, str]] = field(default_factory=list)           # ("10:03", "CPU increases")
    log_signal: Optional[str] = None
    assessment: str = ""


@dataclass
class ServiceDiagnosis:
    service: ServiceSnapshot
    alb: Optional[AlbSnapshot] = None
    metrics: Optional[MetricsSnapshot] = None
    logs: Optional[LogSnapshot] = None
    correlation: Optional[DeploymentCorrelation] = None
    findings: list[Finding] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=utcnow)
    window_minutes: int = 15

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return sorted(self.findings, key=lambda f: f.severity.rank)[0].severity

    @property
    def healthy(self) -> bool:
        return all(f.severity.rank >= Severity.LOW.rank for f in self.findings)


@dataclass
class ClusterHealth:
    cluster: str
    services: list[ServiceSnapshot] = field(default_factory=list)
    generated_at: datetime = field(default_factory=utcnow)
    collection_errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses/enums/datetimes into JSON-safe values."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, float) and (obj != obj or obj in (float("inf"), float("-inf"))):
        return None
    return obj
