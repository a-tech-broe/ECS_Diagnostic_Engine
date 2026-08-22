"""Deployment rules: is the rollout itself the problem?"""

from __future__ import annotations

from typing import Optional

from ..advisor import advise
from ..formatting import num, plural
from ..models import Confidence, Evidence, Finding, Severity
from .base import Rule, RuleContext, register


@register
class DeploymentFailureRule(Rule):
    id = "deployment_failure"
    title = "ECS deployment failure"
    priority = 30
    description = "The primary deployment is not converging on its desired count."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        service = ctx.service
        deployment = service.primary_deployment
        if deployment is None:
            return None

        age_minutes = deployment.age_minutes(ctx.now)
        thresholds = ctx.thresholds
        rollout_failed = deployment.rollout_state == "FAILED"
        many_failed_tasks = deployment.failed_tasks >= thresholds.deployment_failed_tasks
        stalled = (
            age_minutes is not None
            and age_minutes >= thresholds.deployment_stuck_minutes
            and deployment.running_count < deployment.desired_count
        )
        if not (rollout_failed or many_failed_tasks or stalled):
            return None

        evidence = [
            Evidence("ECS", f"Desired tasks: {deployment.desired_count}"),
            Evidence("ECS", f"Running tasks: {deployment.running_count}"),
            Evidence("ECS", f"Failed tasks: {deployment.failed_tasks}"),
            Evidence(
                "ECS",
                f"Deployment age: {num(age_minutes, 0)} minutes"
                if age_minutes is not None
                else "Deployment age: unknown",
            ),
        ]
        if deployment.revision:
            evidence.append(Evidence("ECS", f"Task definition: {deployment.revision}"))
        previous = service.previous_deployment
        if previous and previous.revision:
            evidence.append(
                Evidence("ECS", f"Previous revision still active: {previous.revision}")
            )
        if deployment.rollout_state:
            reason = f" — {deployment.rollout_state_reason}" if deployment.rollout_state_reason else ""
            evidence.append(Evidence("ECS", f"Rollout state: {deployment.rollout_state}{reason}"))

        # The stopped tasks from this rollout usually carry the real cause.
        causes: dict[str, int] = {}
        for task in ctx.recent_stopped():
            reason = task.stopped_reason or "unknown"
            causes[reason] = causes.get(reason, 0) + 1
        for reason, count in sorted(causes.items(), key=lambda item: -item[1])[:3]:
            evidence.append(Evidence("ECS", f"Recent stop reason ({count}x): {reason}"))
        if ctx.logs and ctx.logs.available and ctx.logs.top_errors:
            top = ctx.logs.top_errors[0]
            evidence.append(Evidence("SPLUNK", f"Top application error: {top.text} ({top.count})"))

        severity = Severity.CRITICAL if service.running_count == 0 else Severity.HIGH
        summary_bits = []
        if rollout_failed:
            summary_bits.append("the rollout is marked FAILED")
        if many_failed_tasks:
            summary_bits.append(f"{plural(deployment.failed_tasks, 'task')} failed during the rollout")
        if stalled:
            summary_bits.append(
                f"it has not converged after {num(age_minutes, 0)} minutes "
                f"({deployment.running_count}/{deployment.desired_count} running)"
            )
        return self.finding(
            severity=severity,
            confidence=Confidence.HIGH,
            summary="Deployment " + (deployment.revision or deployment.id) + ": " + "; ".join(summary_bits),
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )
