"""ALB collection: target-group health from elbv2 plus request metrics from CloudWatch."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Optional

from ..config import AwsConfig
from ..models import AlbSnapshot, ServiceSnapshot, TargetGroupHealth, utcnow
from .base import CollectorError

# (CloudWatch metric name, statistic, field on AlbSnapshot)
_METRIC_SPECS: list[tuple[str, str, str]] = [
    ("RequestCount", "Sum", "request_count"),
    ("HTTPCode_Target_4XX_Count", "Sum", "http_4xx"),
    ("HTTPCode_ELB_5XX_Count", "Sum", "http_5xx"),
    ("HTTPCode_Target_5XX_Count", "Sum", "target_5xx"),
    ("TargetConnectionErrorCount", "Sum", "target_connection_errors"),
    ("TargetResponseTime", "p95", "target_response_time_p95"),
]


def arn_suffix(arn: Optional[str]) -> Optional[str]:
    """CloudWatch dimensions use the ARN tail, e.g. ``targetgroup/payments/1a2b``."""
    if not arn:
        return None
    for marker in ("targetgroup/", "loadbalancer/"):
        idx = arn.find(marker)
        if idx != -1:
            suffix = arn[idx:]
            return suffix[len("loadbalancer/") :] if marker == "loadbalancer/" else suffix
    return None


def parse_target_health(arn: str, name: Optional[str], descriptions: list[dict[str, Any]]) -> TargetGroupHealth:
    health = TargetGroupHealth(target_group_arn=arn, target_group_name=name)
    counters = {
        "healthy": "healthy",
        "unhealthy": "unhealthy",
        "initial": "initial",
        "draining": "draining",
        "unused": "unused",
        "unavailable": "unused",
    }
    for description in descriptions:
        state = (description.get("TargetHealth", {}) or {}).get("State", "").lower()
        attr = counters.get(state)
        if attr:
            setattr(health, attr, getattr(health, attr) + 1)
        if state == "unhealthy":
            target_health = description.get("TargetHealth", {}) or {}
            reason = target_health.get("Description") or target_health.get("Reason")
            if reason and reason not in health.unhealthy_reasons:
                health.unhealthy_reasons.append(reason)
    return health


class Boto3AlbCollector:
    """Target health + CloudWatch request metrics for a service's load balancers."""

    def __init__(self, config: AwsConfig, session: Any = None):
        self.config = config
        self._session = session
        self._elbv2 = None
        self._cloudwatch = None

    @property
    def session(self) -> Any:
        if self._session is None:
            try:
                import boto3  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on environment
                raise CollectorError("boto3 is required for ALB collection") from exc
            self._session = boto3.Session(
                profile_name=self.config.profile or None,
                region_name=self.config.region or None,
            )
        return self._session

    @property
    def elbv2(self) -> Any:
        if self._elbv2 is None:
            self._elbv2 = self.session.client("elbv2")
        return self._elbv2

    @property
    def cloudwatch(self) -> Any:
        if self._cloudwatch is None:
            self._cloudwatch = self.session.client("cloudwatch")
        return self._cloudwatch

    def collect(self, snapshot: ServiceSnapshot, window_minutes: int) -> Optional[AlbSnapshot]:
        target_group_arns = [lb.target_group_arn for lb in snapshot.load_balancers if lb.target_group_arn]
        if not target_group_arns:
            return None

        alb = AlbSnapshot()
        load_balancer_arns: list[str] = []
        described = self.elbv2.describe_target_groups(TargetGroupArns=target_group_arns)
        names = {
            tg["TargetGroupArn"]: tg.get("TargetGroupName") for tg in described.get("TargetGroups", []) or []
        }
        for tg in described.get("TargetGroups", []) or []:
            load_balancer_arns.extend(tg.get("LoadBalancerArns", []) or [])

        for arn in target_group_arns:
            health = self.elbv2.describe_target_health(TargetGroupArn=arn)
            alb.target_groups.append(
                parse_target_health(arn, names.get(arn), health.get("TargetHealthDescriptions", []) or [])
            )

        if load_balancer_arns:
            self._add_cloudwatch(alb, target_group_arns[0], load_balancer_arns[0], window_minutes)
        return alb

    def _add_cloudwatch(
        self, alb: AlbSnapshot, target_group_arn: str, load_balancer_arn: str, window_minutes: int
    ) -> None:
        tg_dimension = arn_suffix(target_group_arn)
        lb_dimension = arn_suffix(load_balancer_arn)
        if not tg_dimension or not lb_dimension:
            return

        end = utcnow()
        start = end - timedelta(minutes=window_minutes)
        period = max(60, int(window_minutes * 60))
        dimensions = [
            {"Name": "TargetGroup", "Value": tg_dimension},
            {"Name": "LoadBalancer", "Value": lb_dimension},
        ]
        queries = []
        for index, (metric_name, stat, _) in enumerate(_METRIC_SPECS):
            queries.append(
                {
                    "Id": f"m{index}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/ApplicationELB",
                            "MetricName": metric_name,
                            "Dimensions": dimensions,
                        },
                        "Period": period,
                        "Stat": stat,
                    },
                    "ReturnData": True,
                }
            )
        try:
            response = self.cloudwatch.get_metric_data(
                MetricDataQueries=queries, StartTime=start, EndTime=end
            )
        except Exception as exc:
            raise CollectorError(f"CloudWatch ALB metrics unavailable: {exc}") from exc

        by_id = {result["Id"]: result for result in response.get("MetricDataResults", []) or []}
        for index, (_, _, attr) in enumerate(_METRIC_SPECS):
            values = (by_id.get(f"m{index}", {}) or {}).get("Values", []) or []
            if values:
                setattr(alb, attr, float(values[0]))
