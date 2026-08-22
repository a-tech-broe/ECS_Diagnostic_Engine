"""Report rendering: alignment, colour control, JSON, and the never-remediate contract."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from ecs_diag.config import Config
from ecs_diag.engine import build_engine
from ecs_diag.report import (
    Renderer,
    _display_width,
    _wrap,
    diagnosis_json,
    health_json,
    render_diagnosis,
    render_health,
)

FIXTURES = str(Path(__file__).resolve().parent.parent / "examples" / "incident-cluster")


class PrimitiveTests(unittest.TestCase):
    def test_display_width_counts_emoji_as_two_columns(self):
        self.assertEqual(_display_width("abc"), 3)
        self.assertEqual(_display_width("🔴 HIGH"), 7)
        self.assertEqual(_display_width("\033[1mbold\033[0m"), 4)

    def test_wrap_keeps_short_lines_verbatim(self):
        self.assertEqual(_wrap("  CPU      +38%", 40), ["  CPU      +38%"])

    def test_wrap_preserves_indent_on_continuation(self):
        lines = _wrap("  " + "word " * 20, 30)
        self.assertTrue(all(line.startswith("  ") for line in lines))
        self.assertTrue(all(_display_width(line) <= 30 for line in lines))

    def test_box_borders_line_up(self):
        renderer = Renderer(color=False, width=50)
        lines = renderer.box("TITLE", ["🔴 HIGH PROBABILITY", "  CPU   +38%", "x" * 200])
        self.assertTrue(all(_display_width(line) == 50 for line in lines), lines)
        self.assertTrue(lines[0].startswith("┌") and lines[-1].startswith("└"))

    def test_table_columns_line_up(self):
        renderer = Renderer(color=False, width=60)
        rows = [["a", "1"], ["much-longer-name", "22222"]]
        lines = renderer.table(["NAME", "COUNT"], rows)
        self.assertEqual(lines[1].split("  ")[0], "─" * len("much-longer-name"))

    def test_colour_can_be_switched_off(self):
        self.assertEqual(Renderer(color=False).paint("x", "red"), "x")
        self.assertIn("\033[31m", Renderer(color=True).paint("x", "red"))


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = build_engine(Config(), fixtures=FIXTURES)
        cls.renderer = Renderer(color=False)

    def test_health_marks_uncollected_task_detail_rather_than_claiming_zero(self):
        report = self.engine.health("prod")
        text = render_health(report, self.renderer)
        healthy_row = [line for line in text.splitlines() if line.startswith("search-api")][0]
        self.assertTrue(healthy_row.rstrip().endswith("-"), healthy_row)
        degraded_row = [line for line in text.splitlines() if line.startswith("checkout-api")][0]
        self.assertTrue(degraded_row.rstrip().endswith("2"), degraded_row)

    def test_health_report(self):
        text = render_health(self.engine.health("prod"), self.renderer)
        self.assertIn("ECS CLUSTER HEALTH — prod", text)
        self.assertIn("payments-api", text)
        self.assertIn("DEGRADED", text)
        self.assertNotIn("\033[", text)

    def test_diagnosis_report_contains_every_section(self):
        text = render_diagnosis(self.engine.diagnose("prod", "payments-api"), self.renderer)
        for section in (
            "ECS SRE DIAGNOSTIC REPORT",
            "SERVICE",
            "LOAD BALANCER",
            "PROMETHEUS",
            "SPLUNK",
            "DEPLOYMENT CORRELATION",
            "DIAGNOSIS",
            "REMEDIATION OPTION #1",
        ):
            self.assertIn(section, text)

    def test_every_remediation_option_states_the_full_contract(self):
        text = render_diagnosis(self.engine.diagnose("prod", "checkout-api"), self.renderer)
        options = text.count("REMEDIATION OPTION #")
        self.assertGreater(options, 0)
        for field in ("Action:", "Why:", "Risk:", "Expected effect:"):
            self.assertGreaterEqual(text.count(field), options)
        self.assertEqual(text.count("EXECUTION: NOT PERFORMED"), options)
        self.assertIn("NO ACTIONS WERE EXECUTED", text)

    def test_healthy_service_reads_as_healthy(self):
        text = render_diagnosis(self.engine.diagnose("prod", "search-api"), self.renderer)
        self.assertIn("VERDICT: HEALTHY", text)
        self.assertIn("No rule fired", text)
        self.assertNotIn("REMEDIATION OPTION", text)

    def test_brief_mode_drops_the_option_boxes(self):
        diagnosis = self.engine.diagnose("prod", "checkout-api")
        text = render_diagnosis(diagnosis, self.renderer, brief=True)
        self.assertNotIn("REMEDIATION OPTION #", text)
        self.assertIn("Remediation options (none executed):", text)

    def test_max_options_truncates_and_says_so(self):
        diagnosis = self.engine.diagnose("prod", "checkout-api")
        text = render_diagnosis(diagnosis, self.renderer, max_options=1)
        self.assertNotIn("REMEDIATION OPTION #2", text)
        self.assertIn("suppressed by --max-options", text)

    def test_report_never_exceeds_the_configured_width(self):
        renderer = Renderer(color=False, width=100)
        text = render_diagnosis(self.engine.diagnose("prod", "payments-api"), renderer)
        too_wide = [line for line in text.splitlines() if _display_width(line) > 100]
        self.assertEqual(too_wide, [])


class JsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = build_engine(Config(), fixtures=FIXTURES)

    def test_diagnosis_json_round_trips(self):
        payload = json.loads(diagnosis_json(self.engine.diagnose("prod", "payments-api")))
        self.assertEqual(payload["service"]["service_name"], "payments-api")
        self.assertEqual(payload["verdict"]["execution_policy"], "recommend-only")
        self.assertEqual(payload["verdict"]["executed_actions"], 0)
        self.assertTrue(payload["findings"])
        self.assertEqual(payload["findings"][0]["rule_id"], "connection_exhaustion")
        self.assertEqual(payload["correlation"]["probability"], "HIGH")
        for finding in payload["findings"]:
            for recommendation in finding["recommendations"]:
                self.assertEqual(recommendation["execution_status"], "NOT PERFORMED")

    def test_health_json(self):
        payload = json.loads(health_json(self.engine.health("prod")))
        self.assertEqual(payload["summary"]["services"], 5)
        self.assertEqual(payload["summary"]["degraded"], 2)

    def test_enums_and_datetimes_are_serialisable(self):
        text = diagnosis_json(self.engine.diagnose("prod", "checkout-api"))
        payload = json.loads(text)
        self.assertEqual(payload["findings"][0]["severity"], "CRITICAL")
        self.assertTrue(payload["generated_at"].endswith("+00:00"))


if __name__ == "__main__":
    unittest.main()
