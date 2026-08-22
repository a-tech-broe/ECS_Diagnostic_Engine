"""Config loading, overrides, and query templating."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ecs_diag.config import DEFAULT_PROM_QUERIES, Config, PrometheusConfig, Thresholds


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        config = Config()
        self.assertEqual(config.window, "15m")
        self.assertFalse(config.prometheus.enabled)
        self.assertFalse(config.splunk.enabled)
        self.assertEqual(config.thresholds.cpu_high_pct, 85.0)

    def test_nested_sections_become_dataclasses(self):
        config = Config.from_dict(
            {
                "window_minutes": 30,
                "thresholds": {"cpu_high_pct": 70.0},
                "prometheus": {"url": "http://prom:9090"},
            }
        )
        self.assertIsInstance(config.thresholds, Thresholds)
        self.assertIsInstance(config.prometheus, PrometheusConfig)
        self.assertEqual(config.thresholds.cpu_high_pct, 70.0)
        self.assertTrue(config.prometheus.enabled)
        self.assertEqual(config.window, "30m")

    def test_query_overrides_merge_over_defaults(self):
        config = Config.from_dict({"prometheus": {"queries": {"cpu_pct": "my_cpu{{service=\"{service}\"}}"}}})
        self.assertEqual(len(config.prometheus.queries), len(DEFAULT_PROM_QUERIES))
        rendered = config.prometheus.queries["cpu_pct"].format(**config.query_vars("prod", "payments-api"))
        self.assertEqual(rendered, 'my_cpu{service="payments-api"}')
        self.assertEqual(config.prometheus.queries["latency_p95"], DEFAULT_PROM_QUERIES["latency_p95"])

    def test_default_queries_all_render(self):
        import re

        leftover = re.compile(r"\{[A-Za-z_]+\}")     # an unsubstituted {placeholder}
        config = Config()
        variables = config.query_vars("prod", "payments-api")
        for name, template in config.prometheus.queries.items():
            rendered = template.format(**variables)
            self.assertIn("payments-api", rendered, f"{name} dropped the service name")
            self.assertIsNone(leftover.search(rendered), f"{name} left a placeholder: {rendered}")
        for name, template in config.splunk.queries.items():
            rendered = template.format(**variables)
            self.assertIn("payments-api", rendered, f"{name} dropped the service name")

    def test_unknown_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            Config.from_dict({"promethius": {"url": "typo"}})

    def test_load_from_json_file_and_env_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sre.json"
            path.write_text(json.dumps({"window_minutes": 45, "splunk": {"index": "staging"}}))
            os.environ["SPLUNK_URL"] = "https://splunk.internal:8089"
            try:
                config = Config.load(str(path))
            finally:
                del os.environ["SPLUNK_URL"]
        self.assertEqual(config.window_minutes, 45)
        self.assertEqual(config.splunk.index, "staging")
        self.assertEqual(config.splunk.url, "https://splunk.internal:8089")
        self.assertTrue(config.source_path.endswith("sre.json"))

    def test_missing_file_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            Config.load("/nonexistent/sre.yaml")


if __name__ == "__main__":
    unittest.main()
