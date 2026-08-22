"""Splunk collection through the search-jobs REST API.

Flow: POST /services/search/jobs -> poll the job -> GET its results.
"""

from __future__ import annotations

import time as _time
from typing import Any, Optional

from ..config import Config
from ..httpclient import HttpError, join_url, request_json
from ..models import LogPattern, LogSnapshot


class SplunkCollector:
    def __init__(self, config: Config):
        self.config = config
        self.splunk = config.splunk

    # -- raw API ----------------------------------------------------------

    def run_search(self, search: str) -> list[dict[str, Any]]:
        """Create a search job, wait for it to finish, and return its result rows."""
        if not search.strip().startswith(("search ", "|")):
            search = f"search {search}"
        created = self._call(
            "/services/search/jobs",
            method="POST",
            data={"search": search, "output_mode": "json", "exec_mode": "normal"},
        )
        sid = created.get("sid")
        if not sid:
            raise HttpError(f"Splunk did not return a search id for: {search[:120]}")

        deadline = _time.monotonic() + self.splunk.timeout_seconds
        while True:
            status = self._call(f"/services/search/jobs/{sid}", params={"output_mode": "json"})
            entries = status.get("entry", []) or []
            content = entries[0].get("content", {}) if entries else {}
            if _truthy(content.get("isDone")):
                if _truthy(content.get("isFailed")):
                    messages = content.get("messages") or []
                    detail = messages[0].get("text") if messages else "search failed"
                    raise HttpError(f"Splunk search failed: {detail}")
                break
            if _time.monotonic() > deadline:
                raise HttpError(f"Splunk search {sid} did not finish within {self.splunk.timeout_seconds}s")
            _time.sleep(self.splunk.poll_interval_seconds)

        results = self._call(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": 100},
        )
        return results.get("results", []) or []

    def _call(
        self,
        path: str,
        *,
        method: str = "GET",
        params: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return request_json(
            join_url(self.splunk.url or "", path),
            method=method,
            params=params,
            data=data,
            timeout=self.splunk.timeout_seconds,
            verify_tls=self.splunk.verify_tls,
            bearer_token=self.splunk.token,
            username=self.splunk.username if not self.splunk.token else None,
            password=self.splunk.password if not self.splunk.token else None,
        )

    # -- collection -------------------------------------------------------

    def collect(self, cluster: str, service: str) -> LogSnapshot:
        if not self.splunk.enabled:
            return LogSnapshot(available=False, error="Splunk is not configured")

        variables = self.config.query_vars(cluster, service)
        snapshot = LogSnapshot()
        errors: list[str] = []

        for key, handler in (
            ("levels", self._apply_levels),
            ("errors", self._apply_errors),
            ("exceptions", self._apply_exceptions),
            ("samples", self._apply_samples),
        ):
            template = self.splunk.queries.get(key)
            if not template:
                continue
            try:
                rows = self.run_search(template.format(**variables))
            except (HttpError, KeyError) as exc:
                errors.append(f"{key}: {exc}")
                continue
            handler(snapshot, rows)

        if errors and not (snapshot.level_counts or snapshot.top_errors or snapshot.top_exceptions):
            snapshot.available = False
            snapshot.error = "; ".join(errors)
        elif errors:
            snapshot.error = "; ".join(errors)
        return snapshot

    @staticmethod
    def _apply_levels(snapshot: LogSnapshot, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            level = row.get("level") or row.get("severity") or "UNKNOWN"
            snapshot.level_counts[str(level).upper()] = _int(row.get("count"))

    @staticmethod
    def _apply_errors(snapshot: LogSnapshot, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            text = row.get("error") or row.get("message")
            if text:
                snapshot.top_errors.append(LogPattern(text=str(text), count=_int(row.get("count"))))

    @staticmethod
    def _apply_exceptions(snapshot: LogSnapshot, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            text = row.get("exception")
            if text:
                snapshot.top_exceptions.append(LogPattern(text=str(text), count=_int(row.get("count"))))

    @staticmethod
    def _apply_samples(snapshot: LogSnapshot, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            message = row.get("message") or row.get("_raw")
            if message:
                snapshot.sample_messages.append(str(message)[:300])


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def _int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
