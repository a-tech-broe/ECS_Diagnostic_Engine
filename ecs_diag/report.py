"""Rendering: the SRE report (text) and its machine-readable JSON twin."""

from __future__ import annotations

import json
import unicodedata
from typing import Iterable, Optional

from .formatting import bytes_human, delta, num, pct, seconds
from .models import (
    ClusterHealth,
    Finding,
    Recommendation,
    ServiceDiagnosis,
    ServiceSnapshot,
    Severity,
    to_jsonable,
)
from .timeutil import humanize_duration

WIDTH = 74

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_MARK = {
    Severity.CRITICAL: "[!!]",
    Severity.HIGH: "[!]",
    Severity.MEDIUM: "[~]",
    Severity.LOW: "[.]",
    Severity.INFO: "[i]",
}


class Renderer:
    def __init__(self, color: bool = True, width: int = WIDTH):
        self.color = color
        self.width = width

    # -- primitives -------------------------------------------------------

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        prefix = "".join(_ANSI[s] for s in styles if s in _ANSI)
        return f"{prefix}{text}{_ANSI['reset']}" if prefix else text

    def rule(self, char: str = "─") -> str:
        return char * self.width

    def heading(self, text: str) -> list[str]:
        return [self.paint(text, "bold"), self.rule()]

    def field(self, label: str, value: str, pad: int = 26) -> str:
        return f"{label + ':':<{pad}}{value}"

    def box(self, title: str, lines: Iterable[str], style: Optional[str] = None) -> list[str]:
        """A drawn box, used for the remediation options and the correlation verdict."""
        inner = self.width - 2
        content = inner - 2
        out = ["┌" + "─" * inner + "┐"]
        if title:
            fitted = _fit(title, content)
            out.append("│ " + self.paint(fitted, "bold") + " " * max(0, content - _display_width(fitted)) + " │")
            out.append("├" + "─" * inner + "┤")
        for line in lines:
            for wrapped in _wrap(line, content):
                out.append("│ " + wrapped + " " * max(0, content - _display_width(wrapped)) + " │")
        out.append("└" + "─" * inner + "┘")
        if style and self.color:
            return [self.paint(line, style) for line in out]
        return out

    def table(self, headers: list[str], rows: list[list[str]], gutter: str = "  ") -> list[str]:
        if not rows:
            return []
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], _display_width(cell))
        def line(cells: list[str]) -> str:
            parts = []
            for i, cell in enumerate(cells):
                pad = widths[i] - _display_width(cell)
                parts.append(cell + " " * max(0, pad))
            return gutter.join(parts).rstrip()
        out = [self.paint(line(headers), "bold"), line(["─" * w for w in widths])]
        out.extend(line(row) for row in rows)
        return out


def _display_width(text: str) -> int:
    """Rendered column count: emoji and CJK glyphs occupy two terminal cells."""
    width = 0
    for char in _strip(text):
        code = ord(char)
        if (
            0x1F300 <= code <= 0x1FAFF          # emoji & pictographs
            or 0x2600 <= code <= 0x27BF         # misc symbols / dingbats
            or unicodedata.east_asian_width(char) in ("W", "F")
        ):
            width += 2
        elif unicodedata.combining(char):
            width += 0
        else:
            width += 1
    return width


def _strip(text: str) -> str:
    """Length without ANSI escapes, so coloured cells still align."""
    result, i = [], 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
            continue
        result.append(text[i])
        i += 1
    return "".join(result)


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    if _display_width(text) <= width:
        return [text]          # keep short lines verbatim, indentation included
    # Wrap the content to the space left after the indent, then re-apply it, so
    # a hanging indent never pushes a line past the requested width.
    indent = " " * (len(text) - len(text.lstrip(" ")))
    width = max(1, width - len(indent))
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word if len(word) <= width else word[:width]
    if current:
        lines.append(current)
    if indent:
        lines = [indent + line for line in lines]
    return lines or [""]


def _bullet(renderer: Renderer, text: str, marker: str = "•", indent: int = 2) -> list[str]:
    prefix = " " * indent + f"{marker} "
    wrapped = _wrap(text, renderer.width - len(prefix))
    return [prefix + wrapped[0]] + [" " * len(prefix) + line for line in wrapped[1:]]


# --------------------------------------------------------------------------
# Cluster health
# --------------------------------------------------------------------------


def render_health(report: ClusterHealth, renderer: Optional[Renderer] = None) -> str:
    r = renderer or Renderer()
    out: list[str] = []
    out += r.heading(f"ECS CLUSTER HEALTH — {report.cluster}")
    out.append(r.paint(report.generated_at.strftime("Generated %Y-%m-%d %H:%M:%S UTC"), "dim"))
    out.append("")

    if not report.services:
        out.append("No services found in this cluster.")
        return "\n".join(out)

    rows = []
    for service in report.services:
        state = _service_state(service)
        rows.append(
            [
                r.paint(service.service_name, "bold"),
                r.paint(state[0], state[1]),
                str(service.desired_count),
                str(service.running_count),
                str(service.pending_count),
                _deployment_cell(service),
                _stopped_cell(service),
            ]
        )
    out += r.table(
        ["SERVICE", "STATE", "DESIRED", "RUNNING", "PENDING", "DEPLOYMENT", "RECENT STOPS"], rows
    )
    out.append("")

    degraded = [s for s in report.services if not s.is_converged]
    if degraded:
        out.append(r.paint(f"{len(degraded)} service(s) not at desired count:", "yellow"))
        for service in degraded:
            out += _bullet(
                r,
                f"{service.service_name}: {service.running_count}/{service.desired_count} running "
                f"— diagnose with `sre ecs diagnose --cluster {report.cluster} --service {service.service_name}`",
            )
    else:
        out.append(r.paint("All services are at their desired count.", "green"))

    if report.collection_errors:
        out.append("")
        out.append(r.paint("Collection warnings:", "yellow"))
        for error in report.collection_errors:
            out += _bullet(r, error, marker="!")
    return "\n".join(out)


def _service_state(service: ServiceSnapshot) -> tuple[str, str]:
    if service.status != "ACTIVE":
        return service.status, "red"
    if service.running_count == 0 and service.desired_count > 0:
        return "DOWN", "red"
    if not service.is_converged:
        return "DEGRADED", "yellow"
    return "OK", "green"


def _deployment_cell(service: ServiceSnapshot) -> str:
    deployment = service.primary_deployment
    if deployment is None:
        return "-"
    age = deployment.age_seconds()
    state = deployment.rollout_state or deployment.status
    revision = deployment.revision or deployment.id
    return f"{revision} {state.lower()} {humanize_duration(age)} ago" if age is not None else f"{revision} {state.lower()}"


def _stopped_cell(service: ServiceSnapshot) -> str:
    if not service.tasks_collected:
        return "-"      # health() only fetches task detail for degraded services
    return str(len(service.recent_stopped_tasks(15 * 60)))


# --------------------------------------------------------------------------
# Service diagnosis
# --------------------------------------------------------------------------


def render_diagnosis(
    diagnosis: ServiceDiagnosis,
    renderer: Optional[Renderer] = None,
    brief: bool = False,
    max_options: int = 0,
) -> str:
    r = renderer or Renderer()
    service = diagnosis.service
    out: list[str] = []

    out += r.heading(f"ECS SRE DIAGNOSTIC REPORT — {service.service_name}")
    out.append(
        r.paint(
            f"Cluster: {service.cluster}    Window: {diagnosis.window_minutes}m    "
            + diagnosis.generated_at.strftime("Generated %Y-%m-%d %H:%M:%S UTC"),
            "dim",
        )
    )
    out.append("")

    verdict, color = _verdict(diagnosis)
    out.append(r.paint(verdict, "bold", color))
    out.append("")

    out += _section_service(r, diagnosis)
    out += _section_tasks(r, diagnosis)
    out += _section_alb(r, diagnosis)
    out += _section_metrics(r, diagnosis)
    out += _section_logs(r, diagnosis)
    out += _section_correlation(r, diagnosis)
    out += _section_findings(r, diagnosis, brief=brief, max_options=max_options)

    if diagnosis.collection_errors:
        out.append(r.paint("COLLECTION WARNINGS", "bold"))
        out.append(r.rule())
        for error in diagnosis.collection_errors:
            out += _bullet(r, error, marker="!")
        out.append("")

    out.append(r.rule("═"))
    out.append(r.paint("NO ACTIONS WERE EXECUTED. THIS TOOL ONLY RECOMMENDS.", "bold", "green"))
    out.append(r.rule("═"))
    return "\n".join(out)


def _verdict(diagnosis: ServiceDiagnosis) -> tuple[str, str]:
    if not diagnosis.findings:
        return "VERDICT: HEALTHY — no rule fired in this window.", "green"
    worst = diagnosis.worst_severity
    top = diagnosis.findings[0]
    label = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "DEGRADED",
        Severity.MEDIUM: "WARNING",
        Severity.LOW: "MINOR",
        Severity.INFO: "INFO",
    }[worst]
    return (
        f"VERDICT: {label} — {len(diagnosis.findings)} finding(s). Most likely: {top.title} "
        f"(confidence {top.confidence.value}).",
        _SEVERITY_COLOR[worst],
    )


def _section_service(r: Renderer, diagnosis: ServiceDiagnosis) -> list[str]:
    service = diagnosis.service
    out = [r.paint("SERVICE", "bold"), r.rule()]
    out.append(r.field("Status", service.status))
    out.append(r.field("Desired", str(service.desired_count)))
    out.append(r.field("Running", str(service.running_count)))
    out.append(r.field("Pending", str(service.pending_count)))
    out.append(r.field("Availability", pct(service.availability_pct)))
    if service.launch_type:
        out.append(r.field("Launch type", service.launch_type))
    if service.capacity_provider:
        out.append(r.field("Capacity provider", service.capacity_provider))
    if service.health_check_grace_period_seconds is not None:
        out.append(r.field("Health check grace", f"{service.health_check_grace_period_seconds}s"))
    if service.task_definition:
        out.append(r.field("Task definition", service.task_definition.rsplit("/", 1)[-1]))

    deployment = service.primary_deployment
    if deployment:
        age = deployment.age_seconds(diagnosis.generated_at)
        out.append(
            r.field(
                "Deployment",
                f"{deployment.revision or deployment.id} "
                f"({deployment.rollout_state or deployment.status}, {humanize_duration(age)} ago)",
            )
        )
        out.append(
            r.field(
                "Deployment tasks",
                f"desired {deployment.desired_count}, running {deployment.running_count}, "
                f"pending {deployment.pending_count}, failed {deployment.failed_tasks}",
            )
        )
    previous = service.previous_deployment
    if previous:
        out.append(r.field("Previous revision", previous.revision or previous.id))

    events = service.recent_events(diagnosis.window_minutes * 60, diagnosis.generated_at)[:5]
    if events:
        out.append("")
        out.append("Recent service events:")
        for event in events:
            stamp = event.created_at.strftime("%H:%M") if event.created_at else "--:--"
            out += _bullet(r, f"{stamp}  {event.message}")
    out.append("")
    return out


def _section_tasks(r: Renderer, diagnosis: ServiceDiagnosis) -> list[str]:
    service = diagnosis.service
    stopped = service.recent_stopped_tasks(diagnosis.window_minutes * 60, diagnosis.generated_at)
    if not stopped:
        return []
    out = [r.paint(f"STOPPED TASKS (last {diagnosis.window_minutes}m)", "bold"), r.rule()]
    rows = []
    for task in stopped[:10]:
        codes = ", ".join(str(c) for c in task.exit_codes) or "-"
        rows.append(
            [
                task.short_id,
                _fit(task.stopped_reason or "-", 40),
                codes,
                humanize_duration(task.stopped_age_seconds(diagnosis.generated_at)) + " ago",
            ]
        )
    out += r.table(["TASK", "REASON", "EXIT", "WHEN"], rows)

    detailed = [t for t in stopped if any(c.exit_code is not None or c.reason for c in t.containers)]
    if detailed:
        out.append("")
        out.append("Containers:")
        for task in detailed[:5]:
            for container in task.containers:
                if container.exit_code is None and not container.reason:
                    continue
                bits = [f"{task.short_id}/{container.name}"]
                if container.exit_code is not None:
                    bits.append(f"exit {container.exit_code}")
                if container.memory:
                    bits.append(f"{container.memory} MB limit")
                if container.reason:
                    bits.append(container.reason)
                out += _bullet(r, "  ".join(bits))
    out.append("")
    return out


def _section_alb(r: Renderer, diagnosis: ServiceDiagnosis) -> list[str]:
    alb = diagnosis.alb
    if alb is None:
        return []
    out = [r.paint("LOAD BALANCER", "bold"), r.rule()]
    if alb.has_targets:
        out.append(r.field("Healthy targets", str(alb.healthy_targets)))
        out.append(r.field("Unhealthy targets", str(alb.unhealthy_targets)))
        for tg in alb.target_groups:
            for reason in tg.unhealthy_reasons[:2]:
                out += _bullet(r, f"{tg.target_group_name or 'target group'}: {reason}")
    if alb.request_count is not None:
        out.append(r.field("Requests", num(alb.request_count)))
    if alb.http_4xx is not None:
        out.append(r.field("HTTP 4xx", num(alb.http_4xx)))
    if alb.http_5xx is not None:
        out.append(r.field("HTTP 5xx (ELB)", num(alb.http_5xx)))
    if alb.target_5xx is not None:
        out.append(r.field("HTTP 5xx (target)", num(alb.target_5xx)))
    if alb.target_connection_errors is not None:
        out.append(r.field("Connection errors", num(alb.target_connection_errors)))
    if alb.target_response_time_p95 is not None:
        out.append(r.field("Target response p95", seconds(alb.target_response_time_p95)))
    if alb.error_rate_5xx_pct is not None:
        out.append(r.field("5xx share of traffic", pct(alb.error_rate_5xx_pct)))
    out.append("")
    return out


_METRIC_LABELS = [
    ("cpu_pct", "CPU", pct),
    ("memory_pct", "Memory", pct),
    ("memory_bytes", "Working set", bytes_human),
    ("request_rate", "Request rate", lambda v: f"{num(v, 2)}/s"),
    ("error_rate", "5xx rate", lambda v: f"{num(v, 2)}/s"),
    ("latency_p50", "p50 latency", seconds),
    ("latency_p95", "p95 latency", seconds),
    ("latency_p99", "p99 latency", seconds),
    ("restarts", "Restarts", lambda v: num(v, 0)),
    ("availability", "Availability", pct),
]


def _section_metrics(r: Renderer, diagnosis: ServiceDiagnosis) -> list[str]:
    metrics = diagnosis.metrics
    if metrics is None:
        return []
    out = [r.paint("PROMETHEUS", "bold"), r.rule()]
    if not metrics.available:
        out.append(r.paint(metrics.error or "no metrics available", "dim"))
        out.append("")
        return out

    rows = []
    for key, label, formatter in _METRIC_LABELS:
        sample = metrics.samples.get(key)
        if sample is None:
            continue
        if sample.error:
            rows.append([label, "error", "-", _fit(sample.error, 40)])
            continue
        if sample.value is None:
            continue
        change = sample.delta_pct
        change_cell = delta(change) if change is not None else "-"
        if change is not None and abs(change) >= 20:
            change_cell = r.paint(change_cell, "yellow" if change > 0 else "cyan")
        rows.append(
            [
                label,
                formatter(sample.value),
                formatter(sample.baseline) if sample.baseline is not None else "-",
                change_cell,
            ]
        )
    extras = [k for k in metrics.samples if k not in {m[0] for m in _METRIC_LABELS}]
    for key in extras:
        sample = metrics.samples[key]
        if sample.value is not None:
            rows.append([key, num(sample.value), "-", delta(sample.delta_pct) if sample.delta_pct else "-"])
    out += r.table(["METRIC", "CURRENT", "BASELINE", "CHANGE"], rows)
    if metrics.error:
        out.append(r.paint(f"partial: {metrics.error}", "dim"))
    out.append("")
    return out


def _section_logs(r: Renderer, diagnosis: ServiceDiagnosis) -> list[str]:
    logs = diagnosis.logs
    if logs is None:
        return []
    out = [r.paint("SPLUNK", "bold"), r.rule()]
    if not logs.available:
        out.append(r.paint(logs.error or "no log evidence available", "dim"))
        out.append("")
        return out

    if logs.level_counts:
        ordered = sorted(logs.level_counts.items(), key=lambda item: -item[1])
        out += r.table(["LEVEL", "COUNT"], [[level, num(count)] for level, count in ordered])
        out.append("")
    if logs.top_errors:
        out.append("Top errors:")
        for pattern in logs.top_errors[:5]:
            out += _bullet(r, f"{pattern.text}  ({num(pattern.count)})")
    if logs.top_exceptions:
        out.append("Top exceptions:")
        for pattern in logs.top_exceptions[:5]:
            out += _bullet(r, f"{pattern.text}  ({num(pattern.count)})")
    if logs.error:
        out.append(r.paint(f"partial: {logs.error}", "dim"))
    out.append("")
    return out


def _section_correlation(r: Renderer, diagnosis: ServiceDiagnosis) -> list[str]:
    correlation = diagnosis.correlation
    if correlation is None:
        return []
    out = [r.paint("DEPLOYMENT CORRELATION", "bold"), r.rule()]

    marker = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(correlation.probability, "")
    headline = f"{marker} {correlation.probability} PROBABILITY DEPLOYMENT RELATED".strip()
    lines = [
        headline,
        "",
        f"Current version:   {correlation.current_version or 'unknown'}",
        f"Previous version:  {correlation.previous_version or 'unknown'}",
        f"Deployment age:    {num(correlation.deployment_age_minutes, 0)} minutes"
        if correlation.deployment_age_minutes is not None
        else "Deployment age:    unknown",
    ]
    if correlation.observed_changes:
        lines.append("")
        lines.append("Observed after deployment:")
        for label, change in correlation.observed_changes:
            lines.append(f"  {label:<16}{change}")
    if correlation.pre_deployment_changes:
        lines.append("")
        lines.append("Already degrading before the deployment:")
        for label, change in correlation.pre_deployment_changes:
            lines.append(f"  {label:<16}{change}")
    if correlation.log_signal:
        lines.append("")
        lines.append(f'Splunk: "{correlation.log_signal}"')
    lines.append("")
    lines.append(f"Assessment: {correlation.assessment}")
    lines.append(f"Confidence: {correlation.confidence.value}")

    color = {"HIGH": "red", "MEDIUM": "yellow"}.get(correlation.probability)
    out += r.box("", lines, style=color)

    if correlation.timeline:
        out.append("")
        out.append("Timeline:")
        for stamp, text in correlation.timeline:
            out += _bullet(r, f"{stamp}  {text}", marker=" ")
    out.append("")
    return out


def _section_findings(
    r: Renderer, diagnosis: ServiceDiagnosis, brief: bool = False, max_options: int = 0
) -> list[str]:
    out = [r.paint("DIAGNOSIS", "bold"), r.rule()]
    if not diagnosis.findings:
        out.append("No rule fired. The service looks healthy across every collected source.")
        out.append("")
        return out

    for index, finding in enumerate(diagnosis.findings, start=1):
        out += _render_finding(r, index, finding, brief=brief, max_options=max_options)
    return out


def _render_finding(
    r: Renderer, index: int, finding: Finding, brief: bool = False, max_options: int = 0
) -> list[str]:
    color = _SEVERITY_COLOR[finding.severity]
    mark = _SEVERITY_MARK[finding.severity]
    out = [
        r.paint(
            f"{mark} FINDING #{index}: {finding.title}  "
            f"[{finding.severity.value} / confidence {finding.confidence.value}]",
            "bold",
            color,
        ),
        f"    rule: {finding.rule_id}",
        "",
    ]
    out += _wrap_indented(finding.summary, indent=4)
    if finding.evidence:
        out.append("")
        out.append("    Evidence:")
        evidence = finding.evidence[:4] if brief else finding.evidence
        for item in evidence:
            out += _bullet(r, f"[{item.source}] {item.detail}", indent=6)
        if brief and len(finding.evidence) > len(evidence):
            out += _bullet(r, f"({len(finding.evidence) - len(evidence)} more evidence items)", indent=6)

    if finding.recommendations:
        out.append("")
        if brief:
            out.append("    Remediation options (none executed):")
            for option_index, recommendation in enumerate(finding.recommendations, start=1):
                out += _bullet(
                    r,
                    f"{option_index}. {recommendation.action}  [risk {recommendation.risk.value}]",
                    marker=" ",
                    indent=4,
                )
        else:
            shown = (
                finding.recommendations[:max_options] if max_options > 0 else finding.recommendations
            )
            for option_index, recommendation in enumerate(shown, start=1):
                out += _render_recommendation(r, option_index, recommendation)
            hidden = len(finding.recommendations) - len(shown)
            if hidden > 0:
                out += _bullet(
                    r, f"({hidden} further option(s) suppressed by --max-options)", marker=" ", indent=4
                )
    out.append("")
    return out


def _render_recommendation(r: Renderer, index: int, recommendation: Recommendation) -> list[str]:
    lines = [
        f"Action: {recommendation.action}",
        "",
        "Why:",
        f"  {recommendation.why}",
        "",
        f"Risk: {recommendation.risk.value}",
        "",
        "Expected effect:",
        f"  {recommendation.expected_effect}",
    ]
    if recommendation.command:
        lines += ["", "Command:", f"  {recommendation.command}"]
    lines += ["", f"EXECUTION: {recommendation.execution_status}"]
    return r.box(f"REMEDIATION OPTION #{index}", lines)


def _wrap_indented(text: str, indent: int = 4, width: int = WIDTH) -> list[str]:
    return [" " * indent + line for line in _wrap(text, width - indent)]


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def diagnosis_json(diagnosis: ServiceDiagnosis, indent: int = 2) -> str:
    payload = to_jsonable(diagnosis)
    payload["verdict"] = {
        "severity": diagnosis.worst_severity.value,
        "finding_count": len(diagnosis.findings),
        "executed_actions": 0,
        "execution_policy": "recommend-only",
    }
    return json.dumps(payload, indent=indent, sort_keys=False)


def health_json(report: ClusterHealth, indent: int = 2) -> str:
    payload = to_jsonable(report)
    payload["summary"] = {
        "services": len(report.services),
        "degraded": len([s for s in report.services if not s.is_converged]),
    }
    return json.dumps(payload, indent=indent, sort_keys=False)
