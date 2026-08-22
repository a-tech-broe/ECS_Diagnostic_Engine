"""Rule interface and the evaluation context handed to every rule."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from ..config import Config, Thresholds
from ..models import (
    AlbSnapshot,
    Confidence,
    DeploymentCorrelation,
    Evidence,
    Finding,
    LogSnapshot,
    MetricsSnapshot,
    Recommendation,
    ServiceSnapshot,
    Severity,
    utcnow,
)


@dataclass
class RuleContext:
    """Everything a rule may look at. Rules are pure: read this, return a Finding."""

    service: ServiceSnapshot
    config: Config
    alb: Optional[AlbSnapshot] = None
    metrics: Optional[MetricsSnapshot] = None
    logs: Optional[LogSnapshot] = None
    correlation: Optional[DeploymentCorrelation] = None
    now: datetime = field(default_factory=utcnow)

    @property
    def thresholds(self) -> Thresholds:
        return self.config.thresholds

    @property
    def window_minutes(self) -> int:
        return self.config.window_minutes

    @property
    def window_seconds(self) -> float:
        return self.config.window_minutes * 60

    def metric(self, name: str) -> Optional[float]:
        return self.metrics.value(name) if self.metrics else None

    def baseline(self, name: str) -> Optional[float]:
        return self.metrics.baseline(name) if self.metrics else None

    def delta_pct(self, name: str) -> Optional[float]:
        return self.metrics.delta_pct(name) if self.metrics else None

    def logs_mention(self, *needles: str) -> bool:
        return bool(self.logs and self.logs.available and self.logs.mentions(*needles))

    def log_hits(self, *needles: str) -> list[str]:
        if not (self.logs and self.logs.available):
            return []
        return [p.text for p in self.logs.search(*needles)]

    def recent_stopped(self):
        return self.service.recent_stopped_tasks(self.window_seconds, self.now)

    def event_matches(self, *needles: str) -> list[str]:
        lowered = [n.lower() for n in needles]
        hits = []
        for event in self.service.recent_events(self.window_seconds, self.now):
            message = event.message.lower()
            if any(n in message for n in lowered):
                hits.append(event.message)
        return hits


class Rule:
    """Base class for diagnosis rules.

    Subclasses set ``id``/``title`` and implement ``evaluate``. Returning None
    means "this rule has nothing to say", which is the common case.
    """

    id: str = ""
    title: str = ""
    description: str = ""
    # Ordering hint within a severity band: lower numbers are closer to a root
    # cause, so "image pull failed" outranks "the deployment is not converging".
    priority: int = 50

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------

    def finding(
        self,
        *,
        severity: Severity,
        confidence: Confidence,
        summary: str,
        evidence: list[Evidence],
        recommendations: Optional[list[Recommendation]] = None,
        title: Optional[str] = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=title or self.title,
            severity=severity,
            confidence=confidence,
            summary=summary,
            evidence=evidence,
            recommendations=recommendations or [],
        )


RuleFactory = Callable[[], Rule]
_REGISTRY: dict[str, RuleFactory] = {}


def register(rule_cls: type[Rule]) -> type[Rule]:
    """Class decorator that adds a rule to the global registry."""
    if not rule_cls.id:
        raise ValueError(f"{rule_cls.__name__} must define an id")
    if rule_cls.id in _REGISTRY:
        raise ValueError(f"duplicate rule id: {rule_cls.id}")
    _REGISTRY[rule_cls.id] = rule_cls
    return rule_cls


def all_rules(disabled: Optional[list[str]] = None) -> list[Rule]:
    disabled_set = set(disabled or [])
    return [factory() for rule_id, factory in _REGISTRY.items() if rule_id not in disabled_set]


def rule_ids() -> list[str]:
    return sorted(_REGISTRY)
