"""Resource rules: CPU and memory pressure from Prometheus."""

from __future__ import annotations

from typing import Optional

from ..advisor import advise
from ..formatting import bytes_human, delta, pct
from ..models import Confidence, Evidence, Finding, Severity
from .base import Rule, RuleContext, register


@register
class CpuHighRule(Rule):
    id = "cpu_high"
    title = "CPU saturation"
    priority = 60
    description = "Container CPU utilisation above the configured threshold."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        cpu = ctx.metric("cpu_pct")
        if cpu is None or cpu < ctx.thresholds.cpu_high_pct:
            return None

        evidence = [Evidence("PROMETHEUS", f"CPU utilisation {pct(cpu)}")]
        baseline = ctx.baseline("cpu_pct")
        change = ctx.delta_pct("cpu_pct")
        if baseline is not None:
            evidence.append(
                Evidence("PROMETHEUS", f"Baseline CPU {pct(baseline)} ({delta(change)} vs baseline)")
            )

        # CPU up without traffic up means each request costs more than it used to.
        request_change = ctx.delta_pct("request_rate")
        traffic_flat = request_change is not None and request_change < ctx.thresholds.metric_change_pct
        if request_change is not None:
            evidence.append(Evidence("PROMETHEUS", f"Request rate {delta(request_change)} vs baseline"))
        if traffic_flat and change is not None and change >= ctx.thresholds.metric_change_pct:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    "CPU rose while request rate stayed flat — work per request increased",
                )
            )
        if ctx.correlation and ctx.correlation.correlated:
            evidence.append(
                Evidence("CORRELATION", f"A deployment landed {ctx.correlation.deployment_age_minutes:.0f}m ago")
            )

        severity = Severity.HIGH if cpu >= ctx.thresholds.cpu_critical_pct else Severity.MEDIUM
        return self.finding(
            severity=severity,
            confidence=Confidence.HIGH if baseline is not None else Confidence.MEDIUM,
            summary=f"CPU utilisation is {pct(cpu)} (threshold {pct(ctx.thresholds.cpu_high_pct)})",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


@register
class MemoryHighRule(Rule):
    id = "memory_high"
    title = "Memory pressure"
    priority = 60
    description = "Container memory utilisation above the configured threshold."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        memory = ctx.metric("memory_pct")
        if memory is None or memory < ctx.thresholds.memory_high_pct:
            return None
        # An actual OOM is reported by the oom rule; don't double-report the same fact.
        if any(task.oom_killed for task in ctx.recent_stopped()):
            return None

        evidence = [Evidence("PROMETHEUS", f"Memory utilisation {pct(memory)}")]
        baseline = ctx.baseline("memory_pct")
        if baseline is not None:
            evidence.append(
                Evidence(
                    "PROMETHEUS",
                    f"Baseline memory {pct(baseline)} ({delta(ctx.delta_pct('memory_pct'))} vs baseline)",
                )
            )
        working_set = ctx.metric("memory_bytes")
        if working_set is not None:
            evidence.append(Evidence("PROMETHEUS", f"Working set {bytes_human(working_set)}"))

        limits = {
            f"{c.name}: {c.memory} MB"
            for task in ctx.service.running_tasks
            for c in task.containers
            if c.memory
        }
        for limit in list(limits)[:3]:
            evidence.append(Evidence("ECS", f"Configured limit {limit}"))

        critical = memory >= ctx.thresholds.memory_critical_pct
        if critical:
            evidence.append(
                Evidence("CORRELATION", "Utilisation is in the range where OOM kills become likely")
            )
        return self.finding(
            severity=Severity.HIGH if critical else Severity.MEDIUM,
            confidence=Confidence.HIGH if baseline is not None else Confidence.MEDIUM,
            summary=f"Memory utilisation is {pct(memory)} (threshold {pct(ctx.thresholds.memory_high_pct)})",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )
