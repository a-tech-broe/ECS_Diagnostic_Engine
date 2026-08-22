"""Deployment correlation: it should credit a deploy only for what followed it."""

from __future__ import annotations

import unittest

from ecs_diag.config import Thresholds
from ecs_diag.correlation import correlate_deployment
from ecs_diag.models import Confidence
from tests.helpers import NOW, ago, logs, metrics, service, stopped_task


def series(*points):
    """(minutes_ago, value) -> (epoch, value)."""
    return [(ago(minutes).timestamp(), value) for minutes, value in points]


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.thresholds = Thresholds()

    def test_recent_deploy_with_multiple_signals_is_high(self):
        snapshot = service(deployment_age_minutes=6)
        result = correlate_deployment(
            snapshot,
            metrics(
                cpu_pct=62.0,
                cpu_pct_baseline=45.0,
                latency_p95=3.4,
                latency_p95_baseline=0.31,
                error_rate=3.1,
                error_rate_baseline=0.02,
            ),
            logs(errors=["Connection pool exhausted"]),
            self.thresholds,
            now=NOW,
        )
        self.assertTrue(result.correlated)
        self.assertEqual(result.probability, "HIGH")
        self.assertEqual(result.confidence, Confidence.HIGH)
        self.assertEqual(result.current_version, "payments-api:42")
        self.assertEqual(result.previous_version, "payments-api:41")
        labels = dict(result.observed_changes)
        self.assertIn("CPU", labels)
        self.assertIn("p95 latency", labels)
        self.assertEqual(result.log_signal, "Connection pool exhausted")

    def test_old_deploy_is_not_correlated(self):
        snapshot = service(deployment_age_minutes=240)
        result = correlate_deployment(
            snapshot,
            metrics(cpu_pct=95.0, cpu_pct_baseline=40.0, latency_p95=4.0, latency_p95_baseline=0.3),
            None,
            self.thresholds,
            now=NOW,
        )
        self.assertFalse(result.correlated)
        self.assertEqual(result.probability, "LOW")
        self.assertIn("outside the correlation window", result.assessment)

    def test_metric_that_degraded_before_the_deploy_is_not_credited_to_it(self):
        snapshot = service(deployment_age_minutes=6)
        result = correlate_deployment(
            snapshot,
            metrics(
                error_rate=3.0,
                error_rate_baseline=0.02,
                error_rate_series=series((14, 0.02), (10, 1.5), (2, 3.0)),  # rose 10m ago, deploy was 6m ago
            ),
            None,
            self.thresholds,
            now=NOW,
        )
        self.assertEqual([label for label, _ in result.pre_deployment_changes], ["5xx"])
        self.assertEqual(result.observed_changes, [])
        self.assertIn("began degrading before this deployment", result.assessment)

    def test_metric_that_degraded_after_the_deploy_is_credited(self):
        snapshot = service(deployment_age_minutes=6)
        result = correlate_deployment(
            snapshot,
            metrics(
                error_rate=3.0,
                error_rate_baseline=0.02,
                error_rate_series=series((14, 0.02), (8, 0.02), (4, 1.9), (1, 3.0)),
            ),
            None,
            self.thresholds,
            now=NOW,
        )
        self.assertEqual([label for label, _ in result.observed_changes], ["5xx"])
        self.assertEqual(result.pre_deployment_changes, [])
        self.assertTrue(any("5xx increases" in text for _, text in result.timeline))

    def test_failed_tasks_count_as_a_signal(self):
        snapshot = service(deployment_age_minutes=8, failed_tasks=11, rollout_state="IN_PROGRESS", running=2)
        result = correlate_deployment(snapshot, None, None, self.thresholds, now=NOW)
        self.assertTrue(result.correlated)
        self.assertIn(("failed tasks", "11"), result.observed_changes)

    def test_timeline_is_ordered_and_includes_stopped_tasks(self):
        snapshot = service(
            deployment_age_minutes=10,
            failed_tasks=5,
            stopped=[stopped_task("aa11", minutes_ago=4), stopped_task("bb22", minutes_ago=7)],
        )
        result = correlate_deployment(snapshot, None, None, self.thresholds, now=NOW)
        stamps = [stamp for stamp, _ in result.timeline]
        self.assertEqual(stamps, sorted(stamps))
        self.assertTrue(any("aa11" in text for _, text in result.timeline))

    def test_no_deployment_information(self):
        snapshot = service()
        snapshot.deployments = []
        result = correlate_deployment(snapshot, None, None, self.thresholds, now=NOW)
        self.assertFalse(result.correlated)
        self.assertIn("No deployment information", result.assessment)


if __name__ == "__main__":
    unittest.main()
