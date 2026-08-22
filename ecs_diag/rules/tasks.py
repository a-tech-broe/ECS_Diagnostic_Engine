"""Task-level rules: why individual tasks are dying.

Each stopped task is classified once, so a single failure is reported by the
most specific rule that explains it rather than by all of them at once.
"""

from __future__ import annotations

from typing import Optional

from ..advisor import advise
from ..formatting import num, pct, plural
from ..models import Confidence, Evidence, Finding, Severity, Task
from ..timeutil import humanize_duration
from .base import Rule, RuleContext, register

# Substrings ECS puts in stoppedReason / container reason, mapped to a cause.
IMAGE_PULL_MARKERS = (
    "cannotpullcontainererror",
    "image manifest",
    "pull access denied",
    "repository does not exist",
    "no basic auth credentials",
    "imagepullbackoff",
    "manifest unknown",
)
NETWORK_MARKERS = (
    "resourceinitializationerror",
    "cannotcreatenetworkinterface",
    "unable to attach eni",
    "network interface provisioning",
    "failed to resolve",
    "dial tcp",
    "i/o timeout",
    "unable to pull secrets",
)
CAPACITY_MARKERS = (
    "no container instance met",
    "insufficient",
    "has no available ip",
    "capacity is unavailable",
    "resource:memory",
    "resource:cpu",
    "capacityproviderexception",
)


def classify_task(task: Task) -> str:
    """Return the most specific known cause for a stopped task."""
    if task.oom_killed:
        return "oom"
    text = task.reason_text
    if any(marker in text for marker in IMAGE_PULL_MARKERS):
        return "image_pull"
    if any(marker in text for marker in NETWORK_MARKERS):
        return "network"
    if any(marker in text for marker in CAPACITY_MARKERS):
        return "capacity"
    return "other"


def failed(task: Task) -> bool:
    """A task that stopped because something went wrong, not because ECS scaled in."""
    if task.oom_killed:
        return True
    if any(code not in (0, None) for code in task.exit_codes):
        return True
    text = task.reason_text
    if not text.strip():
        return False
    benign = ("scaling activity", "deployment", "user initiated", "service scheduler")
    return not any(phrase in text for phrase in benign)


def _task_evidence(tasks: list[Task], limit: int = 5) -> list[Evidence]:
    evidence: list[Evidence] = []
    for task in tasks[:limit]:
        reason = task.stopped_reason or "no stop reason recorded"
        codes = ", ".join(str(c) for c in task.exit_codes) or "none"
        evidence.append(
            Evidence("ECS", f"Task {task.short_id} stopped: {reason} (exit code: {codes})")
        )
    if len(tasks) > limit:
        evidence.append(Evidence("ECS", f"...and {len(tasks) - limit} more stopped tasks in the window"))
    return evidence


@register
class TaskFailureRule(Rule):
    id = "task_failure"
    title = "ECS tasks are failing"
    priority = 35
    description = "Tasks stopped in the window for a reason no more specific rule explains."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        candidates = [t for t in ctx.recent_stopped() if failed(t) and classify_task(t) == "other"]
        if len(candidates) < ctx.thresholds.stopped_task_count:
            return None

        service = ctx.service
        evidence = [
            Evidence(
                "ECS",
                f"{plural(len(candidates), 'task')} stopped in the last {ctx.window_minutes}m",
            ),
            Evidence(
                "ECS",
                f"Desired: {service.desired_count}, running: {service.running_count}, "
                f"pending: {service.pending_count}",
            ),
        ]
        evidence += _task_evidence(candidates)

        # A task that dies shortly after starting, repeatedly, is a crash loop.
        lifetimes = [t.lifetime_seconds() for t in candidates if t.lifetime_seconds() is not None]
        crash_loop = (
            len(lifetimes) >= 2
            and all(life <= ctx.thresholds.crash_loop_lifetime_seconds for life in lifetimes)
        )
        if crash_loop:
            evidence.append(
                Evidence(
                    "ECS",
                    "Tasks are exiting within "
                    f"{humanize_duration(max(lifetimes))} of starting — this is a crash loop",
                )
            )
        if ctx.logs and ctx.logs.available and ctx.logs.top_errors:
            top = ctx.logs.top_errors[0]
            evidence.append(Evidence("SPLUNK", f"Most frequent error: {top.text} ({top.count} occurrences)"))

        severity = Severity.CRITICAL if (crash_loop or service.running_count == 0) else Severity.HIGH
        confidence = Confidence.HIGH if len(candidates) >= 2 else Confidence.MEDIUM
        summary = (
            f"{plural(len(candidates), 'task')} stopped unexpectedly in the last "
            f"{ctx.window_minutes} minutes"
            + (" and tasks are restarting in a crash loop" if crash_loop else "")
        )
        return self.finding(
            severity=severity,
            confidence=confidence,
            summary=summary,
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
            title="Crash looping tasks" if crash_loop else self.title,
        )


@register
class OomRule(Rule):
    id = "oom"
    title = "Container memory exhaustion"
    priority = 10
    description = "Containers killed with exit code 137 / OutOfMemoryError."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        killed = [t for t in ctx.recent_stopped() if t.oom_killed]
        memory_pct = ctx.metric("memory_pct")
        memory_critical = (
            memory_pct is not None and memory_pct >= ctx.thresholds.memory_critical_pct
        )
        log_hits = ctx.log_hits("outofmemory", "out of memory", "oomkilled", "java.lang.OutOfMemoryError")

        if len(killed) < ctx.thresholds.oom_count and not (memory_critical and log_hits):
            return None

        evidence: list[Evidence] = []
        if killed:
            evidence.append(
                Evidence(
                    "ECS",
                    f"{plural(len(killed), 'container')} exited with code 137 "
                    f"in the last {ctx.window_minutes}m",
                )
            )
            for task in killed[:5]:
                limits = ", ".join(
                    f"{c.name}: {num(c.memory)} MB limit" for c in task.containers if c.memory
                )
                detail = f"Task {task.short_id}: {task.stopped_reason or 'OutOfMemoryError'}"
                evidence.append(Evidence("ECS", f"{detail}{f' ({limits})' if limits else ''}"))
        if memory_pct is not None:
            evidence.append(Evidence("PROMETHEUS", f"Memory utilisation {pct(memory_pct)}"))
        memory_bytes = ctx.metric("memory_bytes")
        if memory_bytes is not None:
            from ..formatting import bytes_human

            evidence.append(Evidence("PROMETHEUS", f"Working set {bytes_human(memory_bytes)}"))
        for hit in log_hits[:3]:
            evidence.append(Evidence("SPLUNK", f"Log evidence: {hit}"))

        # Three independent sources agreeing is the spec's HIGH-confidence case.
        agreeing = sum([bool(killed), bool(memory_critical), bool(log_hits)])
        confidence = (
            Confidence.HIGH if agreeing >= 2 else (Confidence.MEDIUM if killed else Confidence.LOW)
        )
        severity = Severity.CRITICAL if len(killed) >= 2 else Severity.HIGH
        return self.finding(
            severity=severity,
            confidence=confidence,
            summary=(
                f"{plural(len(killed), 'container')} were OOM killed"
                if killed
                else f"Memory utilisation is at {pct(memory_pct)} with OOM messages in the logs"
            ),
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


@register
class ImagePullFailureRule(Rule):
    id = "image_pull_failure"
    title = "Container image pull failure"
    priority = 10
    description = "Tasks cannot start because the container image cannot be pulled."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        tasks = [t for t in ctx.recent_stopped() if classify_task(t) == "image_pull"]
        events = ctx.event_matches(*IMAGE_PULL_MARKERS)
        if not tasks and not events:
            return None

        evidence: list[Evidence] = []
        if tasks:
            evidence.append(
                Evidence("ECS", f"{plural(len(tasks), 'task')} failed to pull their container image")
            )
            evidence += _task_evidence(tasks, limit=3)
        for message in events[:3]:
            evidence.append(Evidence("ECS", f"Service event: {message}"))
        if ctx.service.task_definition:
            evidence.append(Evidence("ECS", f"Task definition: {ctx.service.task_definition}"))
        images = {c.image for t in tasks for c in t.containers if c.image}
        for image in list(images)[:3]:
            evidence.append(Evidence("ECS", f"Image: {image}"))

        return self.finding(
            severity=Severity.CRITICAL if ctx.service.running_count == 0 else Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="Tasks cannot start because the container image cannot be pulled",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


@register
class NetworkFailureRule(Rule):
    id = "network_failure"
    title = "Task networking failure"
    priority = 15
    description = "ENI provisioning, DNS, or egress failures preventing tasks from starting."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        tasks = [t for t in ctx.recent_stopped() if classify_task(t) == "network"]
        events = ctx.event_matches(*NETWORK_MARKERS)
        if not tasks and not events:
            return None

        evidence: list[Evidence] = []
        if tasks:
            evidence.append(
                Evidence("ECS", f"{plural(len(tasks), 'task')} failed with a networking error")
            )
            evidence += _task_evidence(tasks, limit=3)
        for message in events[:3]:
            evidence.append(Evidence("ECS", f"Service event: {message}"))
        if ctx.service.launch_type:
            evidence.append(Evidence("ECS", f"Launch type: {ctx.service.launch_type}"))

        return self.finding(
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM if not tasks else Confidence.HIGH,
            summary="Tasks are failing on network or resource initialisation",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


@register
class CapacityFailureRule(Rule):
    id = "capacity_failure"
    title = "Capacity or placement failure"
    priority = 15
    description = "ECS cannot place tasks because the cluster has no room for them."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        tasks = [t for t in ctx.recent_stopped() if classify_task(t) == "capacity"]
        events = ctx.event_matches(*CAPACITY_MARKERS, "unable to place a task")
        service = ctx.service
        stuck_pending = service.pending_count > 0 and service.missing_tasks > 0
        if not tasks and not events and not stuck_pending:
            return None
        # Pending alone is normal mid-deploy; only report it with a placement complaint.
        if not tasks and not events:
            return None

        evidence: list[Evidence] = [
            Evidence(
                "ECS",
                f"Desired: {service.desired_count}, running: {service.running_count}, "
                f"pending: {service.pending_count}",
            )
        ]
        for message in events[:4]:
            evidence.append(Evidence("ECS", f"Service event: {message}"))
        evidence += _task_evidence(tasks, limit=3)
        if service.capacity_provider:
            evidence.append(Evidence("ECS", f"Capacity provider: {service.capacity_provider}"))
        if service.launch_type:
            evidence.append(Evidence("ECS", f"Launch type: {service.launch_type}"))

        return self.finding(
            severity=Severity.HIGH if service.missing_tasks else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            summary=(
                f"ECS cannot place {plural(service.missing_tasks, 'task')} — the cluster or "
                "capacity provider has no room"
            ),
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )
