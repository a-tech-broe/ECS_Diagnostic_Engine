"""Dependency rules driven mainly by application evidence from Splunk."""

from __future__ import annotations

from typing import Optional

from ..advisor import advise
from ..formatting import num, pct, seconds
from ..models import Confidence, Evidence, Finding, Severity
from .base import Rule, RuleContext, register

POOL_MARKERS = (
    "connection pool exhausted",
    "pool exhausted",
    "timeout acquiring connection",
    "unable to acquire connection",
    "too many connections",
    "connection limit exceeded",
    "hikaricp",
    "no available connections",
)

DEPENDENCY_MARKERS = (
    "connection refused",
    "connection reset",
    "read timed out",
    "timeout",
    "timed out",
    "upstream",
    "circuit breaker",
    "503 from",
    "gateway timeout",
    "unavailableexception",
    "socketexception",
    "dns",
)


@register
class ConnectionExhaustionRule(Rule):
    id = "connection_exhaustion"
    title = "Connection pool exhaustion"
    priority = 20
    description = "The application cannot obtain connections from its pool."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        hits = ctx.log_hits(*POOL_MARKERS)
        if not hits:
            return None

        evidence = [Evidence("SPLUNK", f"Log evidence: {hit}") for hit in hits[:5]]
        latency = ctx.metric("latency_p95")
        cpu = ctx.metric("cpu_pct")
        if latency is not None:
            evidence.append(Evidence("PROMETHEUS", f"p95 latency {seconds(latency)}"))
        if cpu is not None:
            evidence.append(Evidence("PROMETHEUS", f"CPU utilisation {pct(cpu)}"))
        if cpu is not None and latency is not None and cpu < ctx.thresholds.cpu_high_pct:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    "Requests are slow while CPU is idle, which is the signature of waiting on a pool",
                )
            )
        evidence.append(
            Evidence("ECS", f"Running tasks: {ctx.service.running_count} (each holds its own pool)")
        )
        if ctx.correlation and ctx.correlation.correlated:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    f"Pool errors appeared after deployment {ctx.correlation.current_version}",
                )
            )

        return self.finding(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="The application is reporting connection pool exhaustion",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


@register
class DependencyFailureRule(Rule):
    id = "dependency_failure"
    title = "Downstream dependency failure"
    priority = 25
    description = "The service is failing on calls to something it depends on."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        hits = ctx.log_hits(*DEPENDENCY_MARKERS)
        if not hits:
            return None
        # Pool exhaustion is the more specific explanation; let that rule own it.
        if ctx.log_hits(*POOL_MARKERS) and len(hits) <= len(ctx.log_hits(*POOL_MARKERS)):
            return None

        evidence = [Evidence("SPLUNK", f"Log evidence: {hit}") for hit in hits[:5]]
        if ctx.logs and ctx.logs.available and ctx.logs.top_exceptions:
            top = ctx.logs.top_exceptions[0]
            evidence.append(Evidence("SPLUNK", f"Top exception: {top.text} ({top.count} occurrences)"))

        cpu = ctx.metric("cpu_pct")
        latency = ctx.metric("latency_p95")
        if latency is not None:
            evidence.append(Evidence("PROMETHEUS", f"p95 latency {seconds(latency)}"))
        if cpu is not None:
            evidence.append(Evidence("PROMETHEUS", f"CPU utilisation {pct(cpu)}"))

        # A dependency problem typically leaves ECS and the ALB looking fine.
        platform_healthy = ctx.service.is_converged and not (ctx.alb and ctx.alb.unhealthy_targets)
        if platform_healthy:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    "ECS and the ALB are healthy while the application reports downstream errors — "
                    "the fault is outside this service",
                )
            )
        errors = ctx.metric("error_rate")
        if errors is not None:
            evidence.append(Evidence("PROMETHEUS", f"5xx rate {num(errors, 2)} req/s"))

        return self.finding(
            severity=Severity.HIGH if not platform_healthy else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            summary="The application is reporting failures calling a downstream dependency",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )
