"""Builders for constructing service snapshots in tests."""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from ecs_diag.config import Config
from ecs_diag.models import (
    AlbSnapshot,
    Container,
    Deployment,
    LogPattern,
    LogSnapshot,
    MetricSample,
    MetricsSnapshot,
    ServiceEvent,
    ServiceSnapshot,
    TargetGroupHealth,
    Task,
    utcnow,
)
from ecs_diag.rules.base import RuleContext

NOW = utcnow()


def ago(minutes: float):
    return NOW - timedelta(minutes=minutes)


def service(
    name: str = "payments-api",
    desired: int = 4,
    running: int = 4,
    pending: int = 0,
    deployment_age_minutes: float = 120.0,
    failed_tasks: int = 0,
    rollout_state: str = "COMPLETED",
    events: Optional[list[str]] = None,
    stopped: Optional[list[Task]] = None,
    running_tasks: Optional[list[Task]] = None,
) -> ServiceSnapshot:
    snapshot = ServiceSnapshot(
        cluster="prod",
        service_name=name,
        desired_count=desired,
        running_count=running,
        pending_count=pending,
        launch_type="FARGATE",
        task_definition=f"arn:aws:ecs:us-east-1:1:task-definition/{name}:42",
        deployments=[
            Deployment(
                id="ecs-svc/1",
                status="PRIMARY",
                task_definition=f"arn:aws:ecs:us-east-1:1:task-definition/{name}:42",
                desired_count=desired,
                running_count=running,
                pending_count=pending,
                failed_tasks=failed_tasks,
                rollout_state=rollout_state,
                created_at=ago(deployment_age_minutes),
            ),
            Deployment(
                id="ecs-svc/0",
                status="ACTIVE",
                task_definition=f"arn:aws:ecs:us-east-1:1:task-definition/{name}:41",
                created_at=ago(60 * 48),
            ),
        ],
        events=[ServiceEvent(created_at=ago(2), message=m) for m in (events or [])],
        stopped_tasks=stopped or [],
        running_tasks=running_tasks or [],
    )
    return snapshot


def stopped_task(
    task_id: str = "abc123",
    reason: str = "Essential container in task exited",
    exit_code: Optional[int] = 1,
    minutes_ago: float = 3.0,
    lifetime_minutes: float = 30.0,
    container_reason: Optional[str] = None,
    memory: Optional[int] = 1024,
    image: Optional[str] = None,
) -> Task:
    stopped_at = ago(minutes_ago)
    return Task(
        task_arn=f"arn:aws:ecs:us-east-1:1:task/prod/{task_id}",
        last_status="STOPPED",
        stopped_reason=reason,
        stopped_at=stopped_at,
        started_at=stopped_at - timedelta(minutes=lifetime_minutes),
        containers=[
            Container(
                name="app",
                last_status="STOPPED",
                exit_code=exit_code,
                reason=container_reason,
                memory=memory,
                image=image,
            )
        ],
    )


def metrics(**values) -> MetricsSnapshot:
    """metrics(cpu_pct=96, cpu_pct_baseline=50) -> a snapshot with that sample."""
    snapshot = MetricsSnapshot()
    baselines = {k[: -len("_baseline")]: v for k, v in values.items() if k.endswith("_baseline")}
    series = {k[: -len("_series")]: v for k, v in values.items() if k.endswith("_series")}
    for key, value in values.items():
        if key.endswith("_baseline") or key.endswith("_series"):
            continue
        snapshot.samples[key] = MetricSample(
            name=key, value=value, baseline=baselines.get(key), series=series.get(key, [])
        )
    return snapshot


def logs(errors: Optional[list[str]] = None, exceptions: Optional[list[str]] = None, **levels) -> LogSnapshot:
    return LogSnapshot(
        level_counts={k.upper(): v for k, v in levels.items()},
        top_errors=[LogPattern(text=t, count=10) for t in errors or []],
        top_exceptions=[LogPattern(text=t, count=5) for t in exceptions or []],
    )


def alb(healthy: int = 4, unhealthy: int = 0, reasons: Optional[list[str]] = None, **counters) -> AlbSnapshot:
    snapshot = AlbSnapshot(
        target_groups=[
            TargetGroupHealth(
                target_group_arn="arn:tg",
                target_group_name="tg",
                healthy=healthy,
                unhealthy=unhealthy,
                unhealthy_reasons=reasons or [],
            )
        ]
    )
    for key, value in counters.items():
        setattr(snapshot, key, value)
    return snapshot


def context(
    snapshot: Optional[ServiceSnapshot] = None,
    config: Optional[Config] = None,
    **kwargs,
) -> RuleContext:
    return RuleContext(
        service=snapshot or service(),
        config=config or Config(),
        now=NOW,
        **kwargs,
    )
