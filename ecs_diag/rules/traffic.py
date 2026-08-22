"""Traffic-path rules: latency, error rate, and ALB target health."""

from __future__ import annotations

from typing import Optional

from ..advisor import advise
from ..formatting import delta, num, pct, seconds
from ..models import Confidence, Evidence, Finding, Severity
from .base import Rule, RuleContext, register


@register
class LatencyHighRule(Rule):
    id = "latency_high"
    title = "Application latency degradation"
    priority = 55
    description = "p95 latency above threshold, or far above its own baseline."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        p95 = ctx.metric("latency_p95")
        source = "PROMETHEUS"
        if p95 is None and ctx.alb and ctx.alb.target_response_time_p95 is not None:
            p95 = ctx.alb.target_response_time_p95
            source = "ALB"
        if p95 is None:
            return None

        change = ctx.delta_pct("latency_p95")
        over_absolute = p95 >= ctx.thresholds.latency_p95_seconds
        over_relative = change is not None and change >= ctx.thresholds.latency_increase_pct
        if not (over_absolute or over_relative):
            return None

        evidence = [Evidence(source, f"p95 latency {seconds(p95)}")]
        for key, label in (("latency_p50", "p50"), ("latency_p99", "p99")):
            value = ctx.metric(key)
            if value is not None:
                evidence.append(Evidence("PROMETHEUS", f"{label} latency {seconds(value)}"))
        baseline = ctx.baseline("latency_p95")
        if baseline is not None:
            evidence.append(
                Evidence("PROMETHEUS", f"Baseline p95 {seconds(baseline)} ({delta(change)} vs baseline)")
            )

        # Latency up while CPU is calm points downstream rather than at this service.
        cpu = ctx.metric("cpu_pct")
        cpu_calm = cpu is not None and cpu < ctx.thresholds.cpu_high_pct
        if cpu is not None:
            evidence.append(Evidence("PROMETHEUS", f"CPU utilisation {pct(cpu)}"))

        dependency_hits = ctx.log_hits(
            "timeout", "timed out", "connection pool", "deadlock", "slow query", "circuit breaker"
        )
        for hit in dependency_hits[:3]:
            evidence.append(Evidence("SPLUNK", f"Log evidence: {hit}"))

        assessment = ""
        if cpu_calm and dependency_hits:
            assessment = " Latency is elevated while CPU is normal and the logs show dependency timeouts, which points downstream."
            evidence.append(
                Evidence("CORRELATION", "High latency + normal CPU + dependency timeouts = downstream cause")
            )
        elif not cpu_calm and cpu is not None:
            assessment = " CPU is also saturated, so the service itself may be the bottleneck."

        severity = Severity.HIGH if p95 >= ctx.thresholds.latency_p95_seconds * 2 else Severity.MEDIUM
        return self.finding(
            severity=severity,
            confidence=Confidence.HIGH if (baseline is not None or dependency_hits) else Confidence.MEDIUM,
            summary=(
                f"p95 latency is {seconds(p95)}"
                + (f" ({delta(change)} vs baseline)" if change is not None else "")
                + "."
                + assessment
            ),
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


def _error_rate_pct(ctx: RuleContext) -> tuple[Optional[float], str]:
    """Error percentage from Prometheus if possible, else from ALB counters."""
    errors = ctx.metric("error_rate")
    requests = ctx.metric("request_rate")
    if errors is not None and requests:
        return 100.0 * errors / requests, "PROMETHEUS"
    if ctx.alb is not None:
        alb_pct = ctx.alb.error_rate_5xx_pct
        if alb_pct is not None:
            return alb_pct, "ALB"
    return None, ""


@register
class ErrorRateHighRule(Rule):
    id = "error_rate_high"
    title = "Elevated error rate"
    priority = 50
    description = "5xx responses above the configured share of traffic."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        rate, source = _error_rate_pct(ctx)
        if rate is None or rate < ctx.thresholds.error_rate_pct:
            return None

        evidence = [Evidence(source, f"5xx error rate {pct(rate)} of requests")]
        errors = ctx.metric("error_rate")
        requests = ctx.metric("request_rate")
        if errors is not None:
            evidence.append(Evidence("PROMETHEUS", f"5xx rate {num(errors, 2)} req/s"))
        if requests is not None:
            evidence.append(Evidence("PROMETHEUS", f"Request rate {num(requests, 2)} req/s"))
        change = ctx.delta_pct("error_rate")
        if change is not None:
            evidence.append(Evidence("PROMETHEUS", f"Error rate {delta(change)} vs baseline"))
        if ctx.alb:
            if ctx.alb.http_5xx is not None:
                evidence.append(Evidence("ALB", f"ELB 5xx count {num(ctx.alb.http_5xx)}"))
            if ctx.alb.target_5xx is not None:
                evidence.append(Evidence("ALB", f"Target 5xx count {num(ctx.alb.target_5xx)}"))
            if ctx.alb.target_connection_errors:
                evidence.append(
                    Evidence("ALB", f"Target connection errors {num(ctx.alb.target_connection_errors)}")
                )
        if ctx.logs and ctx.logs.available:
            for pattern in ctx.logs.top_errors[:3]:
                evidence.append(Evidence("SPLUNK", f"{pattern.text} ({pattern.count} occurrences)"))

        # ECS healthy + ALB healthy + rising 5xx = the application, not the platform.
        if ctx.service.is_converged and ctx.alb and ctx.alb.has_targets and not ctx.alb.unhealthy_targets:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    "ECS is converged and all ALB targets are healthy, so this is an application "
                    "or dependency fault rather than a platform one",
                )
            )
        if ctx.correlation and ctx.correlation.correlated:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    f"Errors rose after deployment {ctx.correlation.current_version} "
                    f"({num(ctx.correlation.deployment_age_minutes, 0)}m ago)",
                )
            )

        severity = (
            Severity.CRITICAL if rate >= ctx.thresholds.error_rate_critical_pct else Severity.HIGH
        )
        return self.finding(
            severity=severity,
            confidence=Confidence.HIGH,
            summary=f"{pct(rate)} of requests are returning 5xx (threshold {pct(ctx.thresholds.error_rate_pct)})",
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )


@register
class AlbUnhealthyRule(Rule):
    id = "alb_unhealthy"
    title = "Unhealthy load balancer targets"
    priority = 40
    description = "Targets failing ALB health checks."

    def evaluate(self, ctx: RuleContext) -> Optional[Finding]:
        alb = ctx.alb
        if alb is None or not alb.has_targets:
            return None
        total = alb.healthy_targets + alb.unhealthy_targets
        if not alb.unhealthy_targets or total == 0:
            return None
        unhealthy_pct = 100.0 * alb.unhealthy_targets / total
        if unhealthy_pct < ctx.thresholds.unhealthy_target_pct:
            return None

        evidence = [
            Evidence("ALB", f"Healthy targets: {alb.healthy_targets}"),
            Evidence("ALB", f"Unhealthy targets: {alb.unhealthy_targets} ({pct(unhealthy_pct)} of targets)"),
        ]
        for tg in alb.target_groups:
            for reason in tg.unhealthy_reasons[:3]:
                evidence.append(Evidence("ALB", f"{tg.target_group_name or 'target group'}: {reason}"))
        if alb.target_response_time_p95 is not None:
            evidence.append(Evidence("ALB", f"Target response time p95 {seconds(alb.target_response_time_p95)}"))
        if ctx.service.health_check_grace_period_seconds is not None:
            evidence.append(
                Evidence(
                    "ECS",
                    f"Health check grace period: {ctx.service.health_check_grace_period_seconds}s",
                )
            )

        # ECS thinks the tasks are fine but the ALB disagrees: look at the app or the check.
        if ctx.service.is_converged:
            evidence.append(
                Evidence(
                    "CORRELATION",
                    "ECS reports the service as converged while the ALB reports unhealthy targets — "
                    "suspect the application's health endpoint or the health check configuration",
                )
            )

        severity = Severity.CRITICAL if alb.healthy_targets == 0 else Severity.HIGH
        return self.finding(
            severity=severity,
            confidence=Confidence.HIGH,
            summary=(
                f"{alb.unhealthy_targets} of {total} ALB targets are failing health checks"
                + (" — no healthy targets remain" if alb.healthy_targets == 0 else "")
            ),
            evidence=evidence,
            recommendations=advise(self.id, ctx, evidence),
        )
