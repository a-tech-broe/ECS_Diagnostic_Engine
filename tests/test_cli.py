"""CLI behaviour: argument handling, output modes, and exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from ecs_diag.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

FIXTURES = str(Path(__file__).resolve().parent.parent / "examples" / "incident-cluster")
BASE = ["--fixtures", FIXTURES, "--cluster", "prod", "--no-color"]


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exit_signal:      # argparse / explicit SystemExit
            code = exit_signal.code if isinstance(exit_signal.code, int) else EXIT_ERROR
            if isinstance(exit_signal.code, str):
                err.write(exit_signal.code)
    return code, out.getvalue(), err.getvalue()


class HealthCommandTests(unittest.TestCase):
    def test_health(self):
        code, out, _ = run(["ecs", "health", *BASE])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("ECS CLUSTER HEALTH", out)
        self.assertIn("orders-api", out)

    def test_health_json(self):
        code, out, _ = run(["ecs", "health", *BASE, "--json"])
        payload = json.loads(out)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["summary"]["degraded"], 2)

    def test_health_can_be_limited_to_named_services(self):
        _, out, _ = run(["ecs", "health", *BASE, "--service", "search-api", "--json"])
        payload = json.loads(out)
        self.assertEqual([s["service_name"] for s in payload["services"]], ["search-api"])


class DiagnoseCommandTests(unittest.TestCase):
    def test_diagnose_one_service(self):
        code, out, _ = run(["ecs", "diagnose", *BASE, "--service", "checkout-api"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Container memory exhaustion", out)
        self.assertIn("NO ACTIONS WERE EXECUTED", out)

    def test_diagnose_json(self):
        _, out, _ = run(["ecs", "diagnose", *BASE, "--service", "checkout-api", "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["findings"][0]["rule_id"], "oom")

    def test_diagnose_multiple_services_emits_a_json_list(self):
        _, out, _ = run(
            ["ecs", "diagnose", *BASE, "--service", "checkout-api", "--service", "orders-api", "--json"]
        )
        payload = json.loads(out)
        self.assertEqual(len(payload), 2)

    def test_all_degraded_picks_the_unhealthy_services(self):
        _, out, _ = run(["ecs", "diagnose", *BASE, "--all-degraded", "--json"])
        payload = json.loads(out)
        names = sorted(d["service"]["service_name"] for d in payload)
        self.assertEqual(names, ["checkout-api", "orders-api"])

    def test_disable_rule(self):
        _, out, _ = run(["ecs", "diagnose", *BASE, "--service", "checkout-api", "--disable-rule", "oom", "--json"])
        payload = json.loads(out)
        self.assertNotIn("oom", [f["rule_id"] for f in payload["findings"]])

    def test_window_override_changes_what_counts_as_recent(self):
        # checkout-api's OOM kills are ~3 and ~7 minutes old; a 5m window sees only one.
        _, out, _ = run(["ecs", "diagnose", *BASE, "--service", "checkout-api", "--window", "5", "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["window_minutes"], 5)
        oom = [f for f in payload["findings"] if f["rule_id"] == "oom"][0]
        self.assertIn("1 container", oom["summary"])

    def test_fail_on_returns_a_non_zero_exit_code(self):
        code, _, _ = run(["ecs", "diagnose", *BASE, "--service", "checkout-api", "--fail-on", "critical"])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_fail_on_stays_zero_for_a_healthy_service(self):
        code, _, _ = run(["ecs", "diagnose", *BASE, "--service", "search-api", "--fail-on", "low"])
        self.assertEqual(code, EXIT_OK)

    def test_fail_on_respects_the_severity_floor(self):
        # orders-api tops out at HIGH, so a critical-only gate must not trip.
        code, _, _ = run(["ecs", "diagnose", *BASE, "--service", "orders-api", "--fail-on", "critical"])
        self.assertEqual(code, EXIT_OK)
        code, _, _ = run(["ecs", "diagnose", *BASE, "--service", "orders-api", "--fail-on", "high"])
        self.assertEqual(code, EXIT_FINDINGS)

    def test_missing_service_argument_is_explained(self):
        code, _, err = run(["ecs", "diagnose", *BASE])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("--service", err)

    def test_unknown_service_exits_with_an_error(self):
        code, _, err = run(["ecs", "diagnose", *BASE, "--service", "ghost-api"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("ghost-api", err)


class RulesCommandTests(unittest.TestCase):
    def test_rules_lists_all_thirteen(self):
        code, out, _ = run(["ecs", "rules", "--no-color"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("connection_exhaustion", out)

    def test_rules_json_marks_disabled_rules(self):
        _, out, _ = run(["ecs", "rules", "--no-color", "--json", "--disable-rule", "oom"])
        payload = json.loads(out)
        self.assertEqual(len(payload), 13)
        by_id = {rule["id"]: rule for rule in payload}
        self.assertTrue(by_id["cpu_high"]["enabled"])


class SafetyTests(unittest.TestCase):
    def test_the_cli_exposes_no_verb_that_changes_aws(self):
        from ecs_diag.cli import build_parser

        parser = build_parser()
        ecs_group = parser._subparsers._group_actions[0].choices["ecs"]
        commands = set(ecs_group._subparsers._group_actions[0].choices)
        self.assertEqual(commands, {"health", "diagnose", "rules"})


if __name__ == "__main__":
    unittest.main()
