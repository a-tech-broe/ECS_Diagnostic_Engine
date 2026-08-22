"""Engine wiring, degradation behaviour, and the fixture-backed end-to-end path."""

from __future__ import annotations

import unittest
from pathlib import Path

from ecs_diag.collectors.base import CollectorError
from ecs_diag.config import Config
from ecs_diag.engine import Engine, build_engine
from ecs_diag.models import Severity

FIXTURES = str(Path(__file__).resolve().parent.parent / "examples" / "incident-cluster")


class ExplodingCollector:
    def __init__(self, message="upstream is down"):
        self.message = message

    def collect(self, *args, **kwargs):
        raise CollectorError(self.message)


class FixtureEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = build_engine(Config(), fixtures=FIXTURES)

    def test_health_lists_every_service_worst_first(self):
        report = self.engine.health("prod")
        names = [s.service_name for s in report.services]
        self.assertEqual(len(names), 5)
        self.assertEqual(names[0], "orders-api")          # 2/6 running is the worst availability
        self.assertIn("search-api", names)

    def test_diagnose_payments_api_finds_the_pool_exhaustion(self):
        diagnosis = self.engine.diagnose("prod", "payments-api")
        ids = [f.rule_id for f in diagnosis.findings]
        self.assertEqual(ids[0], "connection_exhaustion")
        self.assertIn("latency_high", ids)
        self.assertIn("error_rate_high", ids)
        self.assertTrue(diagnosis.correlation.correlated)
        self.assertEqual(diagnosis.correlation.probability, "HIGH")

    def test_diagnose_checkout_api_finds_the_oom(self):
        diagnosis = self.engine.diagnose("prod", "checkout-api")
        self.assertEqual(diagnosis.findings[0].rule_id, "oom")
        self.assertEqual(diagnosis.findings[0].severity, Severity.CRITICAL)

    def test_diagnose_orders_api_leads_with_the_root_cause(self):
        diagnosis = self.engine.diagnose("prod", "orders-api")
        self.assertEqual(diagnosis.findings[0].rule_id, "image_pull_failure")
        self.assertIn("deployment_failure", [f.rule_id for f in diagnosis.findings])

    def test_diagnose_inventory_api_separates_ecs_health_from_alb_health(self):
        diagnosis = self.engine.diagnose("prod", "inventory-api")
        self.assertTrue(diagnosis.service.is_converged)
        self.assertEqual(diagnosis.findings[0].rule_id, "alb_unhealthy")

    def test_healthy_service_produces_no_findings(self):
        diagnosis = self.engine.diagnose("prod", "search-api")
        self.assertEqual(diagnosis.findings, [])
        self.assertEqual(diagnosis.worst_severity, Severity.INFO)

    def test_every_recommendation_is_marked_not_performed(self):
        for name in ("payments-api", "checkout-api", "orders-api", "inventory-api"):
            diagnosis = self.engine.diagnose("prod", name)
            for finding in diagnosis.findings:
                self.assertTrue(finding.recommendations, f"{name}/{finding.rule_id} gave no options")
                for recommendation in finding.recommendations:
                    self.assertEqual(recommendation.execution_status, "NOT PERFORMED")

    def test_unknown_service_is_reported_clearly(self):
        with self.assertRaises(CollectorError) as raised:
            self.engine.diagnose("prod", "nope-api")
        self.assertIn("nope-api", str(raised.exception))


class DegradedSourceTests(unittest.TestCase):
    def test_a_failing_source_degrades_the_report_instead_of_aborting_it(self):
        base = build_engine(Config(), fixtures=FIXTURES)
        engine = Engine(
            Config(),
            base.ecs,
            alb_collector=ExplodingCollector("ALB timeout"),
            metric_collector=ExplodingCollector("Prometheus refused the connection"),
            log_collector=base.logs,
        )
        diagnosis = engine.diagnose("prod", "checkout-api")
        self.assertIn("ALB: ALB timeout", diagnosis.collection_errors)
        self.assertTrue(any("Prometheus" in e for e in diagnosis.collection_errors))
        # ECS and Splunk evidence still support the OOM finding.
        self.assertEqual(diagnosis.findings[0].rule_id, "oom")

    def test_unconfigured_backends_report_themselves(self):
        base = build_engine(Config(), fixtures=FIXTURES)
        engine = Engine(Config(), base.ecs)      # null ALB/metrics/logs
        diagnosis = engine.diagnose("prod", "checkout-api")
        self.assertIsNone(diagnosis.alb)
        self.assertFalse(diagnosis.metrics.available)
        self.assertIn("Prometheus is not configured", diagnosis.metrics.error)
        self.assertEqual(diagnosis.findings[0].rule_id, "oom")   # ECS alone is still enough

    def test_a_broken_rule_does_not_take_down_the_report(self):
        from ecs_diag.rules.base import Rule, _REGISTRY

        class BoomRule(Rule):
            id = "boom_test_rule"
            title = "Boom"

            def evaluate(self, ctx):
                raise ValueError("kaboom")

        _REGISTRY[BoomRule.id] = BoomRule
        try:
            engine = build_engine(Config(), fixtures=FIXTURES)
            diagnosis = engine.diagnose("prod", "search-api")
            broken = [f for f in diagnosis.findings if f.rule_id == "boom_test_rule"]
            self.assertEqual(len(broken), 1)
            self.assertIn("kaboom", broken[0].summary)
            self.assertEqual(broken[0].severity, Severity.INFO)
        finally:
            _REGISTRY.pop(BoomRule.id, None)

    def test_disabled_rules_are_skipped(self):
        config = Config()
        config.disabled_rules = ["oom"]
        engine = build_engine(config, fixtures=FIXTURES)
        ids = [f.rule_id for f in engine.diagnose("prod", "checkout-api").findings]
        self.assertNotIn("oom", ids)


class SafetyTests(unittest.TestCase):
    """The engine must not contain a code path that changes AWS."""

    MUTATING = (
        "update_service", "register_task_definition", "delete_service", "create_service",
        "stop_task", "run_task", "start_task", "update_cluster", "delete_cluster",
        "put_scaling_policy", "set_desired_capacity", "deregister_task_definition",
        "modify_target_group", "deregister_targets", "register_targets",
    )

    def test_no_mutating_api_call_exists_in_the_package(self):
        import re

        package = Path(__file__).resolve().parent.parent / "ecs_diag"
        pattern = re.compile(r"\.(" + "|".join(self.MUTATING) + r")\s*\(")
        offenders = []
        for path in package.rglob("*.py"):
            for number, line in enumerate(path.read_text().splitlines(), start=1):
                if pattern.search(line):
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(offenders, [], "the engine must never call a mutating AWS API")


if __name__ == "__main__":
    unittest.main()
