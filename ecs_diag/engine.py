"""The diagnostic engine: collect -> correlate -> diagnose -> recommend.

It never remediates. There is no code path in this package that mutates AWS,
and the CLI never passes credentials to anything that could.
"""

from __future__ import annotations

from typing import Optional

from .collectors.base import (
    CollectorError,
    NullAlbCollector,
    NullLogCollector,
    NullMetricCollector,
)
from .config import Config
from .correlation import correlate_deployment
from .models import (
    ClusterHealth,
    Confidence,
    Finding,
    ServiceDiagnosis,
    ServiceSnapshot,
    Severity,
    utcnow,
)
from .rules import RuleContext, all_rules


class Engine:
    def __init__(
        self,
        config: Config,
        ecs_collector,
        alb_collector=None,
        metric_collector=None,
        log_collector=None,
    ):
        self.config = config
        self.ecs = ecs_collector
        self.alb = alb_collector or NullAlbCollector()
        self.metrics = metric_collector or NullMetricCollector()
        self.logs = log_collector or NullLogCollector()

    # -- health -----------------------------------------------------------

    def health(self, cluster: str, services: Optional[list[str]] = None, with_tasks: bool = True) -> ClusterHealth:
        """Cluster-wide desired/running/pending posture. Cheap: no metrics or logs."""
        report = ClusterHealth(cluster=cluster)
        names = services if services else self.ecs.list_services(cluster)
        if not names:
            return report
        snapshots = self.ecs.describe_services(cluster, names)
        for snapshot in snapshots:
            if with_tasks and not snapshot.is_converged:
                # Only pay for task detail on services that already look unhappy.
                try:
                    self.ecs.enrich_tasks(snapshot)
                except CollectorError as exc:
                    report.collection_errors.append(f"{snapshot.service_name}: {exc}")
            report.services.append(snapshot)
        report.services.sort(key=lambda s: (s.availability_pct, s.service_name))
        return report

    # -- diagnose ---------------------------------------------------------

    def diagnose(self, cluster: str, service: str) -> ServiceDiagnosis:
        snapshots = self.ecs.describe_services(cluster, [service])
        if not snapshots:
            raise CollectorError(f"service '{service}' was not found in cluster '{cluster}'")
        return self.diagnose_snapshot(snapshots[0])

    def diagnose_snapshot(self, snapshot: ServiceSnapshot) -> ServiceDiagnosis:
        diagnosis = ServiceDiagnosis(
            service=snapshot, generated_at=utcnow(), window_minutes=self.config.window_minutes
        )

        # 1. Collect. A failing source degrades the report; it never aborts it.
        try:
            self.ecs.enrich_tasks(snapshot)
        except CollectorError as exc:
            diagnosis.collection_errors.append(f"ECS tasks: {exc}")

        try:
            diagnosis.alb = self.alb.collect(snapshot, self.config.window_minutes)
        except CollectorError as exc:
            diagnosis.collection_errors.append(f"ALB: {exc}")
        except Exception as exc:  # third-party client errors vary too much to enumerate
            diagnosis.collection_errors.append(f"ALB: {exc}")

        try:
            diagnosis.metrics = self.metrics.collect(snapshot.cluster, snapshot.service_name)
        except Exception as exc:
            diagnosis.collection_errors.append(f"Prometheus: {exc}")
        if diagnosis.metrics and diagnosis.metrics.error and not diagnosis.metrics.available:
            diagnosis.collection_errors.append(f"Prometheus: {diagnosis.metrics.error}")

        try:
            diagnosis.logs = self.logs.collect(snapshot.cluster, snapshot.service_name)
        except Exception as exc:
            diagnosis.collection_errors.append(f"Splunk: {exc}")
        if diagnosis.logs and diagnosis.logs.error and not diagnosis.logs.available:
            diagnosis.collection_errors.append(f"Splunk: {diagnosis.logs.error}")

        # 2. Correlate the deployment first so rules can cite it.
        diagnosis.correlation = correlate_deployment(
            snapshot, diagnosis.metrics, diagnosis.logs, self.config.thresholds, diagnosis.generated_at
        )

        # 3. Diagnose.
        ctx = RuleContext(
            service=snapshot,
            config=self.config,
            alb=diagnosis.alb,
            metrics=diagnosis.metrics,
            logs=diagnosis.logs,
            correlation=diagnosis.correlation,
            now=diagnosis.generated_at,
        )
        diagnosis.findings = self.run_rules(ctx)
        return diagnosis

    def run_rules(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        priorities: dict[str, int] = {}
        for rule in all_rules(self.config.disabled_rules):
            priorities[rule.id] = rule.priority
            try:
                finding = rule.evaluate(ctx)
            except Exception as exc:  # a broken rule must not take the report down
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=f"Rule '{rule.id}' failed to evaluate",
                        severity=Severity.INFO,
                        confidence=Confidence.LOW,
                        summary=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue
            if finding is not None:
                findings.append(finding)
        findings.sort(
            key=lambda f: (f.severity.rank, priorities.get(f.rule_id, 50), f.confidence.rank, f.rule_id)
        )
        return findings


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


def build_engine(config: Config, fixtures: Optional[str] = None, session=None) -> Engine:
    """Assemble an engine from config: fixture-backed when offline, live otherwise."""
    if fixtures:
        from .collectors.fixtures import (
            FixtureAlbCollector,
            FixtureEcsCollector,
            FixtureLogCollector,
            FixtureMetricCollector,
            FixtureStore,
        )

        store = FixtureStore(fixtures)
        return Engine(
            config,
            FixtureEcsCollector(store),
            FixtureAlbCollector(store),
            FixtureMetricCollector(store),
            FixtureLogCollector(store),
        )

    from .collectors.alb import Boto3AlbCollector
    from .collectors.ecs import Boto3EcsCollector

    ecs = Boto3EcsCollector(config.aws, session=session)
    alb = Boto3AlbCollector(config.aws, session=session) if config.aws.include_alb else NullAlbCollector()

    metrics = NullMetricCollector()
    if config.prometheus.enabled:
        from .collectors.prometheus import PrometheusCollector

        metrics = PrometheusCollector(config)

    logs = NullLogCollector()
    if config.splunk.enabled:
        from .collectors.splunk import SplunkCollector

        logs = SplunkCollector(config)

    return Engine(config, ecs, alb, metrics, logs)
