"""Each rule: it fires on its signature, and stays quiet otherwise."""

from __future__ import annotations

import unittest

from ecs_diag.models import Confidence, Severity
from ecs_diag.rules import all_rules
from ecs_diag.rules.dependencies import ConnectionExhaustionRule, DependencyFailureRule
from ecs_diag.rules.deployment import DeploymentFailureRule
from ecs_diag.rules.resources import CpuHighRule, MemoryHighRule
from ecs_diag.rules.tasks import (
    CapacityFailureRule,
    ImagePullFailureRule,
    NetworkFailureRule,
    OomRule,
    TaskFailureRule,
    classify_task,
)
from ecs_diag.rules.traffic import AlbUnhealthyRule, ErrorRateHighRule, LatencyHighRule
from tests.helpers import alb, context, logs, metrics, service, stopped_task


class TaskRuleTests(unittest.TestCase):
    def test_task_failure_fires_on_repeated_stops(self):
        snapshot = service(
            running=2,
            stopped=[
                stopped_task("t1", exit_code=1, minutes_ago=2),
                stopped_task("t2", exit_code=1, minutes_ago=4),
            ],
        )
        finding = TaskFailureRule().evaluate(context(snapshot))
        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_id, "task_failure")
        self.assertTrue(finding.recommendations)

    def test_task_failure_ignores_a_single_stop(self):
        snapshot = service(stopped=[stopped_task("t1", exit_code=1)])
        self.assertIsNone(TaskFailureRule().evaluate(context(snapshot)))

    def test_task_failure_ignores_scale_in(self):
        snapshot = service(
            stopped=[
                stopped_task("t1", reason="Scaling activity initiated by deployment", exit_code=0),
                stopped_task("t2", reason="Scaling activity initiated by deployment", exit_code=0),
            ]
        )
        self.assertIsNone(TaskFailureRule().evaluate(context(snapshot)))

    def test_task_failure_escalates_a_crash_loop(self):
        snapshot = service(
            stopped=[
                stopped_task("t1", exit_code=1, lifetime_minutes=0.5, minutes_ago=2),
                stopped_task("t2", exit_code=1, lifetime_minutes=0.7, minutes_ago=5),
            ]
        )
        finding = TaskFailureRule().evaluate(context(snapshot))
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertIn("crash loop", finding.summary)

    def test_task_failure_leaves_specific_causes_to_their_own_rules(self):
        snapshot = service(
            stopped=[
                stopped_task("t1", reason="CannotPullContainerError: image not found", exit_code=None),
                stopped_task("t2", reason="CannotPullContainerError: image not found", exit_code=None),
            ]
        )
        self.assertIsNone(TaskFailureRule().evaluate(context(snapshot)))
        self.assertIsNotNone(ImagePullFailureRule().evaluate(context(snapshot)))

    def test_classify_task(self):
        self.assertEqual(classify_task(stopped_task(exit_code=137)), "oom")
        self.assertEqual(
            classify_task(stopped_task(reason="CannotPullContainerError: nope", exit_code=None)),
            "image_pull",
        )
        self.assertEqual(
            classify_task(stopped_task(reason="ResourceInitializationError: eni", exit_code=None)),
            "network",
        )
        self.assertEqual(
            classify_task(stopped_task(reason="no container instance met all of its requirements", exit_code=None)),
            "capacity",
        )
        self.assertEqual(classify_task(stopped_task(reason="something else", exit_code=2)), "other")


class OomRuleTests(unittest.TestCase):
    def test_fires_on_exit_137(self):
        snapshot = service(running=2, stopped=[stopped_task("t1", exit_code=137)])
        finding = OomRule().evaluate(context(snapshot))
        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_id, "oom")

    def test_confidence_is_high_when_sources_agree(self):
        snapshot = service(
            running=2,
            stopped=[stopped_task("t1", exit_code=137), stopped_task("t2", exit_code=137)],
        )
        ctx = context(
            snapshot,
            metrics=metrics(memory_pct=96.0, memory_pct_baseline=70.0),
            logs=logs(errors=["java.lang.OutOfMemoryError: Java heap space"]),
        )
        finding = OomRule().evaluate(ctx)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        sources = {e.source for e in finding.evidence}
        self.assertEqual(sources, {"ECS", "PROMETHEUS", "SPLUNK"})

    def test_quiet_when_nothing_was_oom_killed(self):
        snapshot = service(stopped=[stopped_task("t1", exit_code=1)])
        self.assertIsNone(OomRule().evaluate(context(snapshot)))

    def test_memory_high_defers_to_oom(self):
        snapshot = service(stopped=[stopped_task("t1", exit_code=137)])
        ctx = context(snapshot, metrics=metrics(memory_pct=97.0))
        self.assertIsNone(MemoryHighRule().evaluate(ctx))
        self.assertIsNotNone(OomRule().evaluate(ctx))


class StartupRuleTests(unittest.TestCase):
    def test_image_pull_failure_from_service_events(self):
        snapshot = service(
            running=0,
            events=["failed to launch a task with (error CannotPullContainerError: image not found)"],
        )
        finding = ImagePullFailureRule().evaluate(context(snapshot))
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_network_failure(self):
        snapshot = service(
            stopped=[stopped_task("t1", reason="ResourceInitializationError: unable to attach ENI", exit_code=None)]
        )
        self.assertIsNotNone(NetworkFailureRule().evaluate(context(snapshot)))

    def test_capacity_failure(self):
        snapshot = service(
            running=1,
            pending=2,
            events=["service was unable to place a task because no container instance met all of its requirements"],
        )
        finding = CapacityFailureRule().evaluate(context(snapshot))
        self.assertIsNotNone(finding)
        self.assertIn("place", finding.summary)

    def test_capacity_quiet_while_a_deploy_is_merely_pending(self):
        snapshot = service(running=3, pending=1, desired=4)
        self.assertIsNone(CapacityFailureRule().evaluate(context(snapshot)))


class DeploymentRuleTests(unittest.TestCase):
    def test_fires_on_failed_tasks(self):
        snapshot = service(running=2, desired=6, failed_tasks=11, deployment_age_minutes=14, rollout_state="IN_PROGRESS")
        finding = DeploymentFailureRule().evaluate(context(snapshot))
        self.assertIsNotNone(finding)
        self.assertIn("11", finding.summary)

    def test_fires_on_a_stalled_rollout(self):
        snapshot = service(running=2, desired=4, deployment_age_minutes=45, rollout_state="IN_PROGRESS")
        self.assertIsNotNone(DeploymentFailureRule().evaluate(context(snapshot)))

    def test_quiet_on_a_healthy_recent_deploy(self):
        snapshot = service(deployment_age_minutes=3, rollout_state="IN_PROGRESS")
        self.assertIsNone(DeploymentFailureRule().evaluate(context(snapshot)))


class ResourceRuleTests(unittest.TestCase):
    def test_cpu_high(self):
        ctx = context(metrics=metrics(cpu_pct=96.0, cpu_pct_baseline=48.0, request_rate=10.0, request_rate_baseline=10.0))
        finding = CpuHighRule().evaluate(ctx)
        self.assertEqual(finding.severity, Severity.HIGH)
        details = " ".join(e.detail for e in finding.evidence)
        self.assertIn("request rate stayed flat", details)

    def test_cpu_quiet_below_threshold(self):
        self.assertIsNone(CpuHighRule().evaluate(context(metrics=metrics(cpu_pct=60.0))))

    def test_memory_high_severity_bands(self):
        warning = MemoryHighRule().evaluate(context(metrics=metrics(memory_pct=91.0)))
        self.assertEqual(warning.severity, Severity.MEDIUM)     # above 85%, below the 95% critical band
        critical = MemoryHighRule().evaluate(context(metrics=metrics(memory_pct=97.0)))
        self.assertEqual(critical.severity, Severity.HIGH)
        details = " ".join(e.detail for e in critical.evidence)
        self.assertIn("OOM kills become likely", details)

    def test_rules_are_quiet_without_metrics(self):
        ctx = context()
        self.assertIsNone(CpuHighRule().evaluate(ctx))
        self.assertIsNone(MemoryHighRule().evaluate(ctx))


class TrafficRuleTests(unittest.TestCase):
    def test_latency_high_on_relative_increase(self):
        ctx = context(
            metrics=metrics(latency_p95=0.9, latency_p95_baseline=0.31, cpu_pct=40.0),
            logs=logs(errors=["Database timeout exceeded"]),
        )
        finding = LatencyHighRule().evaluate(ctx)
        self.assertIsNotNone(finding)
        self.assertIn("downstream", finding.summary)

    def test_latency_quiet_when_fast_and_stable(self):
        ctx = context(metrics=metrics(latency_p95=0.2, latency_p95_baseline=0.19))
        self.assertIsNone(LatencyHighRule().evaluate(ctx))

    def test_latency_falls_back_to_alb(self):
        ctx = context(alb=alb(target_response_time_p95=4.0))
        finding = LatencyHighRule().evaluate(ctx)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.evidence[0].source, "ALB")

    def test_error_rate_from_prometheus(self):
        ctx = context(metrics=metrics(error_rate=3.0, request_rate=40.0))
        finding = ErrorRateHighRule().evaluate(ctx)
        self.assertIsNotNone(finding)
        self.assertIn("7.5%", finding.summary)

    def test_error_rate_quiet_below_threshold(self):
        ctx = context(metrics=metrics(error_rate=0.2, request_rate=40.0))
        self.assertIsNone(ErrorRateHighRule().evaluate(ctx))

    def test_error_rate_severity_bands(self):
        low = ErrorRateHighRule().evaluate(context(metrics=metrics(error_rate=1.2, request_rate=40.0)))
        self.assertEqual(low.severity, Severity.HIGH)
        high = ErrorRateHighRule().evaluate(context(metrics=metrics(error_rate=8.0, request_rate=40.0)))
        self.assertEqual(high.severity, Severity.CRITICAL)

    def test_error_rate_from_alb_when_prometheus_is_absent(self):
        ctx = context(alb=alb(request_count=1000.0, http_5xx=68.0))
        finding = ErrorRateHighRule().evaluate(ctx)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.evidence[0].source, "ALB")

    def test_error_rate_notes_healthy_platform(self):
        ctx = context(
            service(),
            alb=alb(healthy=4, unhealthy=0, request_count=1000.0, http_5xx=100.0),
            metrics=metrics(error_rate=3.0, request_rate=40.0),
        )
        details = " ".join(e.detail for e in ErrorRateHighRule().evaluate(ctx).evidence)
        self.assertIn("application", details)

    def test_alb_unhealthy(self):
        ctx = context(alb=alb(healthy=0, unhealthy=3, reasons=["Health checks failed with these codes: [503]"]))
        finding = AlbUnhealthyRule().evaluate(ctx)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertIn("no healthy targets", finding.summary)

    def test_alb_quiet_when_all_targets_pass(self):
        self.assertIsNone(AlbUnhealthyRule().evaluate(context(alb=alb(healthy=4))))


class DependencyRuleTests(unittest.TestCase):
    def test_connection_exhaustion(self):
        ctx = context(logs=logs(errors=["Connection pool exhausted: timeout acquiring connection"]))
        finding = ConnectionExhaustionRule().evaluate(ctx)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.confidence, Confidence.HIGH)

    def test_dependency_failure(self):
        ctx = context(logs=logs(errors=["upstream ledger-service connection refused"]))
        self.assertIsNotNone(DependencyFailureRule().evaluate(ctx))

    def test_dependency_defers_to_pool_exhaustion(self):
        ctx = context(logs=logs(errors=["Connection pool exhausted: timeout acquiring connection"]))
        self.assertIsNone(DependencyFailureRule().evaluate(ctx))

    def test_quiet_without_logs(self):
        ctx = context()
        self.assertIsNone(ConnectionExhaustionRule().evaluate(ctx))
        self.assertIsNone(DependencyFailureRule().evaluate(ctx))


class RegistryTests(unittest.TestCase):
    def test_every_rule_has_identity_and_advice(self):
        from ecs_diag.advisor import CATALOG

        for rule in all_rules():
            self.assertTrue(rule.id, f"{type(rule).__name__} has no id")
            self.assertTrue(rule.title, f"{rule.id} has no title")
            self.assertIn(rule.id, CATALOG, f"{rule.id} has no remediation options")
            self.assertTrue(CATALOG[rule.id], f"{rule.id} has an empty catalog")

    def test_a_healthy_service_fires_nothing(self):
        ctx = context(
            service(),
            alb=alb(healthy=4, request_count=1000.0, http_5xx=1.0),
            metrics=metrics(cpu_pct=30.0, memory_pct=50.0, latency_p95=0.2, error_rate=0.01, request_rate=40.0),
            logs=logs(info=1000),
        )
        fired = [rule.id for rule in all_rules() if rule.evaluate(ctx) is not None]
        self.assertEqual(fired, [])


if __name__ == "__main__":
    unittest.main()
