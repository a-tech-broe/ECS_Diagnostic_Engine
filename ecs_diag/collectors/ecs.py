"""ECS collection: DescribeServices, ListTasks/DescribeTasks, task definitions.

The parsers accept raw AWS API shapes so the same code serves both the live
boto3 client and the offline fixture loader.
"""

from __future__ import annotations

from typing import Any, Optional

from ..config import AwsConfig
from ..models import (
    Container,
    Deployment,
    LoadBalancerRef,
    ServiceEvent,
    ServiceSnapshot,
    Task,
)
from ..timeutil import parse_time
from .base import CollectorError


# --------------------------------------------------------------------------
# Parsers (raw AWS shapes -> models)
# --------------------------------------------------------------------------


def parse_deployment(raw: dict[str, Any]) -> Deployment:
    return Deployment(
        id=raw.get("id", "unknown"),
        status=raw.get("status", "UNKNOWN"),
        task_definition=raw.get("taskDefinition"),
        desired_count=int(raw.get("desiredCount", 0) or 0),
        running_count=int(raw.get("runningCount", 0) or 0),
        pending_count=int(raw.get("pendingCount", 0) or 0),
        failed_tasks=int(raw.get("failedTasks", 0) or 0),
        created_at=parse_time(raw.get("createdAt")),
        updated_at=parse_time(raw.get("updatedAt")),
        rollout_state=raw.get("rolloutState"),
        rollout_state_reason=raw.get("rolloutStateReason"),
    )


def parse_container(raw: dict[str, Any]) -> Container:
    memory = raw.get("memory")
    reservation = raw.get("memoryReservation")
    cpu = raw.get("cpu")
    return Container(
        name=raw.get("name", "unknown"),
        last_status=raw.get("lastStatus"),
        exit_code=raw.get("exitCode"),
        reason=raw.get("reason"),
        health_status=raw.get("healthStatus"),
        image=raw.get("image"),
        memory=int(memory) if memory not in (None, "") else None,
        memory_reservation=int(reservation) if reservation not in (None, "") else None,
        cpu=int(cpu) if cpu not in (None, "") else None,
    )


def parse_task(raw: dict[str, Any]) -> Task:
    return Task(
        task_arn=raw.get("taskArn", "unknown"),
        last_status=raw.get("lastStatus"),
        desired_status=raw.get("desiredStatus"),
        health_status=raw.get("healthStatus"),
        stopped_reason=raw.get("stoppedReason"),
        stop_code=raw.get("stopCode"),
        task_definition_arn=raw.get("taskDefinitionArn"),
        started_at=parse_time(raw.get("startedAt")),
        stopped_at=parse_time(raw.get("stoppedAt") or raw.get("stoppingAt")),
        availability_zone=raw.get("availabilityZone"),
        containers=[parse_container(c) for c in raw.get("containers", []) or []],
    )


def parse_service(raw: dict[str, Any], cluster: str) -> ServiceSnapshot:
    strategy = raw.get("capacityProviderStrategy") or []
    capacity_provider = strategy[0].get("capacityProvider") if strategy else None
    return ServiceSnapshot(
        cluster=cluster,
        service_name=raw.get("serviceName", "unknown"),
        status=raw.get("status", "UNKNOWN"),
        desired_count=int(raw.get("desiredCount", 0) or 0),
        running_count=int(raw.get("runningCount", 0) or 0),
        pending_count=int(raw.get("pendingCount", 0) or 0),
        launch_type=raw.get("launchType"),
        capacity_provider=capacity_provider,
        health_check_grace_period_seconds=raw.get("healthCheckGracePeriodSeconds"),
        task_definition=raw.get("taskDefinition"),
        platform_version=raw.get("platformVersion"),
        created_at=parse_time(raw.get("createdAt")),
        deployments=[parse_deployment(d) for d in raw.get("deployments", []) or []],
        events=[
            ServiceEvent(created_at=parse_time(e.get("createdAt")), message=e.get("message", ""))
            for e in raw.get("events", []) or []
        ],
        load_balancers=[
            LoadBalancerRef(
                target_group_arn=lb.get("targetGroupArn"),
                load_balancer_name=lb.get("loadBalancerName"),
                container_name=lb.get("containerName"),
                container_port=lb.get("containerPort"),
            )
            for lb in raw.get("loadBalancers", []) or []
        ],
    )


def apply_task_definition(snapshot: ServiceSnapshot, task_def: dict[str, Any]) -> None:
    """Copy per-container memory/cpu limits from a task definition onto tasks.

    DescribeTasks does not report the configured limits, but an OOM finding is
    far more useful when it can say *what* the limit was.
    """
    defs = {c.get("name"): c for c in task_def.get("containerDefinitions", []) or []}
    for task in list(snapshot.running_tasks) + list(snapshot.stopped_tasks):
        for container in task.containers:
            definition = defs.get(container.name)
            if not definition:
                continue
            if container.memory is None:
                container.memory = definition.get("memory")
            if container.memory_reservation is None:
                container.memory_reservation = definition.get("memoryReservation")
            if container.cpu is None:
                container.cpu = definition.get("cpu")


# --------------------------------------------------------------------------
# Live collector
# --------------------------------------------------------------------------


class Boto3EcsCollector:
    """Reads real ECS state. boto3 is imported lazily so the core stays dependency-free."""

    def __init__(self, config: AwsConfig, session: Any = None):
        self.config = config
        self._session = session
        self._client = None
        self._task_def_cache: dict[str, dict[str, Any]] = {}

    # -- plumbing ---------------------------------------------------------

    @property
    def session(self) -> Any:
        if self._session is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on environment
                raise CollectorError(
                    "boto3 is required for live AWS collection: pip install 'sre-ecs-diagnostics[aws]'"
                ) from exc
            self._session = boto3.Session(
                profile_name=self.config.profile or None,
                region_name=self.config.region or None,
            )
        return self._session

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = self.session.client("ecs")
        return self._client

    # -- collection -------------------------------------------------------

    def list_services(self, cluster: str) -> list[str]:
        arns: list[str] = []
        paginator = self.client.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster):
            arns.extend(page.get("serviceArns", []))
        return arns

    def describe_services(self, cluster: str, services: list[str]) -> list[ServiceSnapshot]:
        snapshots: list[ServiceSnapshot] = []
        # DescribeServices accepts at most 10 services per call.
        for batch in _chunks(services, 10):
            response = self.client.describe_services(cluster=cluster, services=batch)
            for failure in response.get("failures", []) or []:
                raise CollectorError(
                    f"ECS could not describe {failure.get('arn', '?')}: {failure.get('reason', 'unknown')}"
                )
            for raw in response.get("services", []) or []:
                snapshot = parse_service(raw, cluster)
                snapshot.events = snapshot.events[: self.config.max_events]
                snapshots.append(snapshot)
        return snapshots

    def enrich_tasks(self, snapshot: ServiceSnapshot) -> ServiceSnapshot:
        snapshot.running_tasks = self._tasks(snapshot, desired_status="RUNNING")
        snapshot.stopped_tasks = self._tasks(snapshot, desired_status="STOPPED")
        snapshot.stopped_tasks.sort(
            key=lambda t: t.stopped_at.timestamp() if t.stopped_at else 0.0, reverse=True
        )
        snapshot.stopped_tasks = snapshot.stopped_tasks[: self.config.max_stopped_tasks]
        if snapshot.task_definition:
            task_def = self._task_definition(snapshot.task_definition)
            if task_def:
                apply_task_definition(snapshot, task_def)
        snapshot.tasks_collected = True
        return snapshot

    def _tasks(self, snapshot: ServiceSnapshot, desired_status: str) -> list[Task]:
        arns: list[str] = []
        paginator = self.client.get_paginator("list_tasks")
        pages = paginator.paginate(
            cluster=snapshot.cluster,
            serviceName=snapshot.service_name,
            desiredStatus=desired_status,
        )
        for page in pages:
            arns.extend(page.get("taskArns", []))
            if len(arns) >= self.config.max_stopped_tasks and desired_status == "STOPPED":
                break
        tasks: list[Task] = []
        for batch in _chunks(arns, 100):   # DescribeTasks caps at 100 ARNs
            response = self.client.describe_tasks(cluster=snapshot.cluster, tasks=batch)
            tasks.extend(parse_task(t) for t in response.get("tasks", []) or [])
        return tasks

    def _task_definition(self, arn: str) -> Optional[dict[str, Any]]:
        if arn in self._task_def_cache:
            return self._task_def_cache[arn]
        try:
            response = self.client.describe_task_definition(taskDefinition=arn)
        except Exception:
            return None
        task_def = response.get("taskDefinition", {})
        self._task_def_cache[arn] = task_def
        return task_def


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
