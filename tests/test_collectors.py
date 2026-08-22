"""Collector parsing: AWS shapes, Prometheus responses, Splunk job results, fixtures."""

from __future__ import annotations

import unittest
from datetime import timezone

from ecs_diag.collectors.alb import arn_suffix, parse_target_health
from ecs_diag.collectors.ecs import apply_task_definition, parse_service, parse_task
from ecs_diag.collectors.fixtures import FixtureStore, FixtureEcsCollector, FixtureMetricCollector
from ecs_diag.collectors.prometheus import _first_scalar, _unit_for
from ecs_diag.collectors.splunk import SplunkCollector, _int, _truthy
from ecs_diag.timeutil import parse_duration, parse_time

FIXTURES = "examples/incident-cluster"


class EcsParsingTests(unittest.TestCase):
    def test_parse_service(self):
        snapshot = parse_service(
            {
                "serviceName": "payments-api",
                "status": "ACTIVE",
                "desiredCount": 4,
                "runningCount": 2,
                "pendingCount": 1,
                "launchType": "FARGATE",
                "capacityProviderStrategy": [{"capacityProvider": "FARGATE_SPOT"}],
                "healthCheckGracePeriodSeconds": 60,
                "taskDefinition": "arn:aws:ecs:us-east-1:1:task-definition/payments-api:142",
                "deployments": [
                    {"id": "d1", "status": "PRIMARY", "createdAt": "-6m", "failedTasks": 3,
                     "taskDefinition": "arn:aws:ecs:us-east-1:1:task-definition/payments-api:142"},
                    {"id": "d0", "status": "ACTIVE", "createdAt": "-2d",
                     "taskDefinition": "arn:aws:ecs:us-east-1:1:task-definition/payments-api:141"},
                ],
                "events": [{"createdAt": "-1m", "message": "started 2 tasks"}],
                "loadBalancers": [{"targetGroupArn": "arn:tg", "containerName": "payments", "containerPort": 8080}],
            },
            "prod",
        )
        self.assertEqual(snapshot.service_name, "payments-api")
        self.assertEqual(snapshot.capacity_provider, "FARGATE_SPOT")
        self.assertEqual(snapshot.missing_tasks, 2)
        self.assertFalse(snapshot.is_converged)
        self.assertAlmostEqual(snapshot.availability_pct, 50.0)
        self.assertEqual(snapshot.primary_deployment.revision, "payments-api:142")
        self.assertEqual(snapshot.previous_deployment.revision, "payments-api:141")
        self.assertEqual(snapshot.load_balancers[0].container_port, 8080)
        self.assertEqual(snapshot.primary_deployment.created_at.tzinfo, timezone.utc)

    def test_parse_task_detects_oom_from_either_signal(self):
        by_exit_code = parse_task({"taskArn": "arn/a", "containers": [{"name": "app", "exitCode": 137}]})
        by_reason = parse_task(
            {"taskArn": "arn/b", "stoppedReason": "OutOfMemoryError: killed", "containers": [{"name": "app"}]}
        )
        neither = parse_task({"taskArn": "arn/c", "containers": [{"name": "app", "exitCode": 1}]})
        self.assertTrue(by_exit_code.oom_killed)
        self.assertTrue(by_reason.oom_killed)
        self.assertFalse(neither.oom_killed)
        self.assertEqual(by_exit_code.short_id, "a")

    def test_task_lifetime(self):
        task = parse_task({"taskArn": "arn/a", "startedAt": "-10m", "stoppedAt": "-9m"})
        self.assertAlmostEqual(task.lifetime_seconds(), 60.0, delta=2.0)

    def test_apply_task_definition_fills_memory_limits(self):
        snapshot = parse_service({"serviceName": "s", "deployments": []}, "prod")
        snapshot.stopped_tasks = [parse_task({"taskArn": "arn/a", "containers": [{"name": "app", "exitCode": 137}]})]
        apply_task_definition(snapshot, {"containerDefinitions": [{"name": "app", "memory": 1024, "cpu": 512}]})
        self.assertEqual(snapshot.stopped_tasks[0].containers[0].memory, 1024)
        self.assertEqual(snapshot.stopped_tasks[0].containers[0].cpu, 512)


class AlbParsingTests(unittest.TestCase):
    def test_arn_suffix(self):
        self.assertEqual(
            arn_suffix("arn:aws:elasticloadbalancing:us-east-1:1:targetgroup/payments/1a2b"),
            "targetgroup/payments/1a2b",
        )
        self.assertEqual(
            arn_suffix("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/prod-alb/9f8e"),
            "app/prod-alb/9f8e",
        )
        self.assertIsNone(arn_suffix(None))

    def test_target_health_counts_and_reasons(self):
        health = parse_target_health(
            "arn:tg",
            "payments",
            [
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "unhealthy", "Description": "Health checks failed with [503]"}},
                {"TargetHealth": {"State": "draining"}},
            ],
        )
        self.assertEqual((health.healthy, health.unhealthy, health.draining), (1, 1, 1))
        self.assertEqual(health.total, 3)
        self.assertEqual(health.unhealthy_reasons, ["Health checks failed with [503]"])


class PrometheusParsingTests(unittest.TestCase):
    def test_vector_scalar_and_empty_results(self):
        self.assertEqual(_first_scalar({"data": {"resultType": "vector", "result": [{"value": [1, "96.4"]}]}}), 96.4)
        self.assertEqual(_first_scalar({"data": {"resultType": "scalar", "result": [1, "3"]}}), 3.0)
        self.assertIsNone(_first_scalar({"data": {"result": []}}))
        self.assertIsNone(_first_scalar({"data": {"resultType": "vector", "result": [{"value": [1, "NaN"]}]}}))

    def test_units(self):
        self.assertEqual(_unit_for("cpu_pct"), "%")
        self.assertEqual(_unit_for("latency_p95"), "s")
        self.assertEqual(_unit_for("memory_bytes"), "B")


class SplunkParsingTests(unittest.TestCase):
    def test_row_handlers(self):
        from ecs_diag.models import LogSnapshot

        snapshot = LogSnapshot()
        SplunkCollector._apply_levels(snapshot, [{"level": "error", "count": "12"}, {"level": "INFO", "count": "900"}])
        SplunkCollector._apply_errors(snapshot, [{"error": "pool exhausted", "count": "5"}])
        SplunkCollector._apply_exceptions(snapshot, [{"exception": "PSQLException", "count": "3"}])
        SplunkCollector._apply_samples(snapshot, [{"message": "connection timed out"}])
        self.assertEqual(snapshot.level_counts, {"ERROR": 12, "INFO": 900})
        self.assertEqual(snapshot.error_count, 12)
        self.assertEqual(snapshot.total_count, 912)
        self.assertTrue(snapshot.mentions("pool exhausted"))
        self.assertTrue(snapshot.mentions("psqlexception"))
        self.assertFalse(snapshot.mentions("disk full"))

    def test_helpers(self):
        self.assertTrue(_truthy("1"))
        self.assertFalse(_truthy("0"))
        self.assertEqual(_int("12.0"), 12)
        self.assertEqual(_int(None), 0)


class FixtureTests(unittest.TestCase):
    def test_keyed_documents_resolve_per_service(self):
        store = FixtureStore(FIXTURES)
        metrics = FixtureMetricCollector(store).collect("prod", "checkout-api")
        self.assertAlmostEqual(metrics.value("memory_pct"), 96.2)
        self.assertAlmostEqual(metrics.delta_pct("memory_pct"), 30.0, delta=0.1)

    def test_relative_timestamps_stay_fresh(self):
        store = FixtureStore(FIXTURES)
        snapshot = FixtureEcsCollector(store).describe_services("prod", ["payments-api"])[0]
        age = snapshot.primary_deployment.age_minutes()
        self.assertTrue(5.9 <= age <= 7.0, f"deployment age drifted: {age}")

    def test_missing_service_is_reported(self):
        from ecs_diag.collectors.base import CollectorError

        store = FixtureStore(FIXTURES)
        with self.assertRaises(CollectorError):
            FixtureEcsCollector(store).describe_services("prod", ["ghost-api"])

    def test_missing_path_is_reported(self):
        from ecs_diag.collectors.base import CollectorError

        with self.assertRaises(CollectorError):
            FixtureStore("/no/such/fixtures")


class TimeUtilTests(unittest.TestCase):
    def test_parse_time_formats(self):
        self.assertIsNotNone(parse_time("-6m"))
        self.assertIsNotNone(parse_time("2026-08-22T10:00:00Z"))
        self.assertIsNotNone(parse_time(1700000000))
        self.assertIsNone(parse_time(None))
        self.assertIsNone(parse_time("not a time"))

    def test_parse_duration(self):
        self.assertEqual(parse_duration("15m"), 900)
        self.assertEqual(parse_duration("1h30m"), 5400)
        self.assertEqual(parse_duration("nonsense", 60), 60)


if __name__ == "__main__":
    unittest.main()
