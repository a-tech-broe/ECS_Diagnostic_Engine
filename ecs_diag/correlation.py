"""Deployment correlation: did the incident start when the last deploy landed?

Answering that first is what makes the difference between "the service is sick"
and "roll back v1.42", so it runs before the rules and feeds evidence into them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .config import Thresholds
from .models import (
    Confidence,
    DeploymentCorrelation,
    LogSnapshot,
    MetricsSnapshot,
    ServiceSnapshot,
    utcnow,
)

# (metric key, human label, direction) - direction +1 means "an increase is bad".
CORRELATED_METRICS: list[tuple[str, str]] = [
    ("cpu_pct", "CPU"),
    ("memory_pct", "Memory"),
    ("error_rate", "5xx"),
    ("latency_p95", "p95 latency"),
    ("restarts", "restarts"),
]

# Log phrases that commonly point at a bad release rather than ambient load.
DEPLOY_SIGNAL_PHRASES = (
    "connection pool exhausted",
    "cannotpullcontainererror",
    "no such file",
    "classnotfound",
    "nomethoderror",
    "config",
    "migration",
    "schema",
    "unable to start",
    "panic",
)


def _fmt_delta(delta_pct: Optional[float], absolute: Optional[float] = None) -> str:
    if delta_pct is None:
        return f"+{absolute:.0f}" if absolute is not None else "n/a"
    sign = "+" if delta_pct >= 0 else ""
    return f"{sign}{delta_pct:.0f}%"


def _clock(ts: Optional[datetime]) -> str:
    if ts is None:
        return "--:--"
    return ts.astimezone(timezone.utc).strftime("%H:%M")


def _first_crossing(series: list[tuple[float, float]], threshold: float) -> Optional[datetime]:
    """First sample in the window that exceeds the threshold — when it started."""
    for ts, value in series:
        if value >= threshold:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
    return None


def correlate_deployment(
    service: ServiceSnapshot,
    metrics: Optional[MetricsSnapshot],
    logs: Optional[LogSnapshot],
    thresholds: Thresholds,
    now: Optional[datetime] = None,
) -> DeploymentCorrelation:
    now = now or utcnow()
    deployment = service.primary_deployment
    correlation = DeploymentCorrelation()
    if deployment is None:
        correlation.assessment = "No deployment information is available for this service."
        return correlation

    correlation.current_version = deployment.revision
    previous = service.previous_deployment
    correlation.previous_version = previous.revision if previous else None
    age_minutes = deployment.age_minutes(now)
    correlation.deployment_age_minutes = age_minutes

    timeline: list[tuple[datetime, str]] = []
    if deployment.created_at:
        version = deployment.revision or deployment.id
        timeline.append((deployment.created_at, f"Deployment {version}"))

    recent = age_minutes is not None and age_minutes <= thresholds.deployment_correlation_minutes
    signals = 0

    # 1. Metric movement since the baseline.
    if metrics:
        for key, label in CORRELATED_METRICS:
            sample = metrics.get(key)
            if sample is None:
                continue
            delta = sample.delta_pct
            if key == "restarts":
                if sample.value and sample.value >= thresholds.restart_count:
                    correlation.observed_changes.append((label, f"+{sample.value:.0f}"))
                    signals += 1
                    if sample.series:
                        crossing = _first_crossing(sample.series, 1.0)
                        if crossing:
                            timeline.append((crossing, "Containers begin restarting"))
                continue
            if delta is None or delta in (float("inf"), float("-inf")):
                continue
            if delta < thresholds.metric_change_pct:
                continue

            # When we have a series, check *when* the metric turned. A metric
            # that was already degrading before the deploy is not evidence the
            # deploy caused it — reporting it as such is how tools get rollbacks
            # ordered for the wrong reason.
            crossing = None
            if sample.series and sample.baseline:
                crossing = _first_crossing(sample.series, sample.baseline * 1.2)
            if crossing and deployment.created_at and crossing < deployment.created_at:
                correlation.pre_deployment_changes.append((label, _fmt_delta(delta)))
                timeline.append((crossing, f"{label} increases (before the deployment)"))
                continue

            correlation.observed_changes.append((label, _fmt_delta(delta)))
            signals += 1
            if crossing:
                timeline.append((crossing, f"{label} increases"))

    # 2. ECS-side failure signals attributable to the rollout.
    if deployment.failed_tasks >= thresholds.deployment_failed_tasks:
        correlation.observed_changes.append(("failed tasks", str(deployment.failed_tasks)))
        signals += 1
    if deployment.rollout_state == "FAILED":
        correlation.observed_changes.append(("rollout state", "FAILED"))
        signals += 1

    for task in service.recent_stopped_tasks(thresholds.deployment_correlation_minutes * 60, now):
        if task.stopped_at and deployment.created_at and task.stopped_at >= deployment.created_at:
            timeline.append((task.stopped_at, f"Task {task.short_id} stopped: {task.stopped_reason or 'unknown'}"))

    # 3. Application evidence.
    if logs and logs.available:
        for pattern in logs.top_errors + logs.top_exceptions:
            if any(phrase in pattern.text.lower() for phrase in DEPLOY_SIGNAL_PHRASES):
                correlation.log_signal = pattern.text
                signals += 1
                break
        if correlation.log_signal is None and logs.top_errors:
            correlation.log_signal = logs.top_errors[0].text

    # 4. Score it.
    if recent and signals >= 2:
        correlation.correlated = True
        correlation.probability = "HIGH"
        correlation.confidence = Confidence.HIGH
    elif recent and signals == 1:
        correlation.correlated = True
        correlation.probability = "MEDIUM"
        correlation.confidence = Confidence.MEDIUM
    elif recent:
        correlation.probability = "LOW"
        correlation.confidence = Confidence.MEDIUM
    else:
        correlation.probability = "LOW"
        correlation.confidence = Confidence.LOW

    correlation.timeline = [
        (_clock(ts), text) for ts, text in sorted(timeline, key=lambda item: item[0])
    ][:12]
    correlation.assessment = _assessment(correlation, age_minutes, recent, signals)
    if correlation.pre_deployment_changes:
        labels = ", ".join(label for label, _ in correlation.pre_deployment_changes)
        correlation.assessment += (
            f" Note: {labels} began degrading before this deployment landed, so that signal is not "
            "attributable to it."
        )
    return correlation


def _assessment(
    correlation: DeploymentCorrelation,
    age_minutes: Optional[float],
    recent: bool,
    signals: int,
) -> str:
    version = correlation.current_version or "the current revision"
    if not recent:
        if age_minutes is None:
            return "Deployment age is unknown, so no time correlation could be established."
        return (
            f"The last deployment ({version}) landed {age_minutes:.0f} minutes ago, outside the "
            "correlation window. The incident is unlikely to be deployment related."
        )
    if signals >= 2:
        return (
            f"The incident is strongly correlated with the most recent deployment ({version}, "
            f"{age_minutes:.0f} minutes ago). Multiple independent signals degraded after it landed."
        )
    if signals == 1:
        return (
            f"The most recent deployment ({version}) landed {age_minutes:.0f} minutes ago and one "
            "signal degraded after it. Treat the deployment as a candidate, not a conclusion."
        )
    return (
        f"A deployment ({version}) landed {age_minutes:.0f} minutes ago but no metric or log signal "
        "degraded after it."
    )
