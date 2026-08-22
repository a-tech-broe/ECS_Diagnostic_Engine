"""Configuration: endpoints, PromQL/Splunk query templates and rule thresholds.

Metric names differ from shop to shop, so every query is a template that the
user can override in ``sre.yaml`` / ``sre.json``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Optional, get_type_hints

CONFIG_ENV_VAR = "SRE_ECS_CONFIG"
DEFAULT_CONFIG_NAMES = ("sre.yaml", "sre.yml", "sre.json", ".sre.yaml", ".sre.yml", ".sre.json")

# Placeholders available to every query template.
#   {service}   ECS service name
#   {cluster}   ECS cluster name
#   {window}    lookback window, e.g. "15m"
#   {baseline}  baseline offset, e.g. "1h"
DEFAULT_PROM_QUERIES: dict[str, str] = {
    "cpu_pct": (
        'avg(rate(container_cpu_usage_seconds_total{{container_label_com_amazonaws_ecs_service_name="{service}"}}[{window}])) * 100'
    ),
    "memory_pct": (
        'max(container_memory_working_set_bytes{{container_label_com_amazonaws_ecs_service_name="{service}"}} '
        '/ container_spec_memory_limit_bytes{{container_label_com_amazonaws_ecs_service_name="{service}"}}) * 100'
    ),
    "memory_bytes": (
        'max(container_memory_working_set_bytes{{container_label_com_amazonaws_ecs_service_name="{service}"}})'
    ),
    "restarts": (
        'sum(increase(container_start_time_seconds{{container_label_com_amazonaws_ecs_service_name="{service}"}}[{window}]))'
    ),
    "request_rate": 'sum(rate(http_requests_total{{service="{service}"}}[{window}]))',
    "error_rate": 'sum(rate(http_requests_total{{service="{service}",status=~"5.."}}[{window}]))',
    "latency_p50": (
        'histogram_quantile(0.50, sum(rate(http_request_duration_seconds_bucket{{service="{service}"}}[{window}])) by (le))'
    ),
    "latency_p95": (
        'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{{service="{service}"}}[{window}])) by (le))'
    ),
    "latency_p99": (
        'histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket{{service="{service}"}}[{window}])) by (le))'
    ),
    "availability": 'avg(up{{service="{service}"}}) * 100',
}

# Metrics for which a pre-incident baseline is worth fetching (via `offset`).
BASELINE_METRICS = ("cpu_pct", "memory_pct", "request_rate", "error_rate", "latency_p95")

DEFAULT_SPLUNK_QUERIES: dict[str, str] = {
    "levels": 'search index={index} service="{service}" earliest=-{window} | stats count by level | sort - count',
    "errors": (
        'search index={index} service="{service}" level=ERROR earliest=-{window} '
        "| stats count by error | sort - count | head 10"
    ),
    "exceptions": (
        'search index={index} service="{service}" earliest=-{window} '
        "| stats count by exception | sort - count | head 10"
    ),
    "samples": (
        'search index={index} service="{service}" (level=ERROR OR level=FATAL) earliest=-{window} '
        "| head 20 | table _time, level, message"
    ),
}


@dataclass
class PrometheusConfig:
    url: Optional[str] = None
    queries: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PROM_QUERIES))
    baseline_metrics: list[str] = field(default_factory=lambda: list(BASELINE_METRICS))
    baseline_offset: str = "24h"
    timeout_seconds: float = 15.0
    verify_tls: bool = True
    bearer_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return bool(self.url)


@dataclass
class SplunkConfig:
    url: Optional[str] = None
    index: str = "production"
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    queries: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SPLUNK_QUERIES))
    timeout_seconds: float = 60.0
    poll_interval_seconds: float = 1.0
    verify_tls: bool = True
    service_field: str = "service"

    @property
    def enabled(self) -> bool:
        return bool(self.url)


@dataclass
class AwsConfig:
    region: Optional[str] = None
    profile: Optional[str] = None
    cluster: Optional[str] = None
    # Pull ALB target health + CloudWatch request metrics for the service.
    include_alb: bool = True
    max_stopped_tasks: int = 50
    max_events: int = 30


@dataclass
class Thresholds:
    """Every number a rule fires on, in one place."""

    cpu_high_pct: float = 85.0
    cpu_critical_pct: float = 95.0
    memory_high_pct: float = 85.0
    memory_critical_pct: float = 95.0
    latency_p95_seconds: float = 1.0
    latency_increase_pct: float = 100.0
    error_rate_pct: float = 2.0
    error_rate_critical_pct: float = 10.0
    alb_5xx_pct: float = 2.0
    restart_count: float = 3.0
    stopped_task_count: int = 2
    oom_count: int = 1
    deployment_stuck_minutes: float = 10.0
    deployment_correlation_minutes: float = 30.0
    deployment_failed_tasks: int = 3
    crash_loop_lifetime_seconds: float = 120.0
    unhealthy_target_pct: float = 20.0
    availability_pct: float = 99.0
    metric_change_pct: float = 20.0     # minimum move to call out in correlation


@dataclass
class Config:
    aws: AwsConfig = field(default_factory=AwsConfig)
    prometheus: PrometheusConfig = field(default_factory=PrometheusConfig)
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    thresholds: Thresholds = field(default_factory=Thresholds)
    window_minutes: int = 15
    disabled_rules: list[str] = field(default_factory=list)
    source_path: Optional[str] = None

    @property
    def window(self) -> str:
        return f"{self.window_minutes}m"

    def query_vars(self, cluster: str, service: str) -> dict[str, str]:
        return {
            "service": service,
            "cluster": cluster,
            "window": self.window,
            "baseline": self.prometheus.baseline_offset,
            "index": self.splunk.index,
        }

    # -- loading ----------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        return _build(cls, data or {})

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        found = _resolve_path(path)
        if found is None:
            cfg = cls()
        else:
            cfg = cls.from_dict(_read_structured(found))
            cfg.source_path = str(found)
        cfg.apply_env()
        return cfg

    def apply_env(self) -> "Config":
        """Environment overrides — handy for CI and for keeping secrets out of files."""
        env = os.environ
        self.prometheus.url = env.get("PROMETHEUS_URL", self.prometheus.url)
        self.prometheus.bearer_token = env.get("PROMETHEUS_TOKEN", self.prometheus.bearer_token)
        self.splunk.url = env.get("SPLUNK_URL", self.splunk.url)
        self.splunk.token = env.get("SPLUNK_TOKEN", self.splunk.token)
        self.splunk.username = env.get("SPLUNK_USERNAME", self.splunk.username)
        self.splunk.password = env.get("SPLUNK_PASSWORD", self.splunk.password)
        self.splunk.index = env.get("SPLUNK_INDEX", self.splunk.index)
        self.aws.region = env.get("AWS_REGION", env.get("AWS_DEFAULT_REGION", self.aws.region))
        self.aws.profile = env.get("AWS_PROFILE", self.aws.profile)
        self.aws.cluster = env.get("ECS_CLUSTER", self.aws.cluster)
        return self


def _resolve_path(path: Optional[str]) -> Optional[Path]:
    if path:
        p = Path(path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"config file not found: {p}")
        return p
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        p = Path(env_path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"{CONFIG_ENV_VAR} points at a missing file: {p}")
        return p
    for directory in (Path.cwd(), Path.home() / ".config" / "sre-ecs", Path.home()):
        for name in DEFAULT_CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _read_structured(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                f"{path} is YAML but PyYAML is not installed. `pip install pyyaml` or use JSON."
            ) from exc
        return yaml.safe_load(text) or {}
    return json.loads(text or "{}")


def _build(cls: type, data: dict[str, Any]) -> Any:
    """Construct a (possibly nested) dataclass from a plain dict, ignoring unknown keys."""
    kwargs: dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}
    # `from __future__ import annotations` makes Field.type a string, so resolve
    # the real classes before testing for nested dataclasses.
    hints = get_type_hints(cls)
    unknown = [k for k in data if k not in known]
    if unknown:
        raise ValueError(f"unknown config key(s) for {cls.__name__}: {', '.join(sorted(unknown))}")
    for name, f in known.items():
        if name not in data:
            continue
        value = data[name]
        hint = hints.get(name)
        if is_dataclass(hint) and isinstance(value, dict):
            kwargs[name] = _build(hint, value)  # type: ignore[arg-type]
        elif name == "queries" and isinstance(value, dict):
            # Merge overrides over the defaults so partial overrides work.
            base = dict(DEFAULT_PROM_QUERIES if cls is PrometheusConfig else DEFAULT_SPLUNK_QUERIES)
            base.update(value)
            kwargs[name] = base
        else:
            kwargs[name] = value
    return cls(**kwargs)
