"""``sre`` command line: ``sre ecs health`` and ``sre ecs diagnose``.

Collect, correlate, diagnose, recommend. The CLI has no verb that changes AWS.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import __version__
from .collectors.base import CollectorError
from .config import Config
from .engine import Engine, build_engine
from .models import Severity
from .report import Renderer, diagnosis_json, health_json, render_diagnosis, render_health
from .rules import all_rules, rule_ids

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_ERROR = 3


class CliError(RuntimeError):
    """A usage problem worth reporting through the normal error path."""

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sre",
        description="ECS SRE diagnostic and recommendation engine (never remediates).",
        epilog="This tool only reads. It never restarts tasks, scales services, or changes infrastructure.",
    )
    parser.add_argument("--version", action="version", version=f"sre-ecs-diagnostics {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", help="path to sre.yaml / sre.json")
    common.add_argument("--cluster", help="ECS cluster name (or set ECS_CLUSTER)")
    common.add_argument("--region", help="AWS region")
    common.add_argument("--profile", help="AWS profile")
    common.add_argument("--window", type=int, metavar="MINUTES", help="lookback window in minutes (default 15)")
    common.add_argument("--fixtures", metavar="DIR", help="run offline against a fixture directory")
    common.add_argument("--json", action="store_true", help="emit JSON instead of the text report")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    common.add_argument("--width", type=int, default=74, help="report width (default 74)")
    common.add_argument("--debug", action="store_true", help="show full tracebacks")
    common.add_argument(
        "--disable-rule", action="append", default=[], metavar="RULE_ID", help="skip a rule (repeatable)"
    )

    subparsers = parser.add_subparsers(dest="group", required=True)
    ecs = subparsers.add_parser("ecs", help="ECS commands").add_subparsers(dest="command", required=True)

    health = ecs.add_parser("health", parents=[common], help="cluster-wide service health")
    health.add_argument("--service", action="append", default=[], help="limit to these services (repeatable)")
    health.set_defaults(func=cmd_health)

    diagnose = ecs.add_parser(
        "diagnose", parents=[common], help="full diagnosis of one service (or every degraded service)"
    )
    diagnose.add_argument("--service", action="append", default=[], help="service to diagnose (repeatable)")
    diagnose.add_argument(
        "--all-degraded",
        action="store_true",
        help="diagnose every service that is not at its desired count",
    )
    diagnose.add_argument(
        "--brief", action="store_true", help="one-line remediation options instead of full option boxes"
    )
    diagnose.add_argument(
        "--max-options",
        type=int,
        default=0,
        metavar="N",
        help="show at most N remediation options per finding (0 = all)",
    )
    diagnose.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="exit non-zero when a finding at or above this severity is reported",
    )
    diagnose.set_defaults(func=cmd_diagnose)

    rules = ecs.add_parser("rules", parents=[common], help="list the diagnosis rules")
    rules.set_defaults(func=cmd_rules)
    return parser


def _load_config(args: argparse.Namespace) -> Config:
    config = Config.load(args.config)
    if args.window:
        config.window_minutes = args.window
    if args.region:
        config.aws.region = args.region
    if args.profile:
        config.aws.profile = args.profile
    if getattr(args, "disable_rule", None):
        config.disabled_rules = list({*config.disabled_rules, *args.disable_rule})
    return config


def _renderer(args: argparse.Namespace) -> Renderer:
    color = not args.no_color and sys.stdout.isatty()
    return Renderer(color=color, width=args.width)


def _cluster(args: argparse.Namespace, config: Config) -> str:
    cluster = args.cluster or config.aws.cluster
    if not cluster:
        if args.fixtures:
            return "fixture"
        raise CliError("no cluster given: pass --cluster, set ECS_CLUSTER, or set aws.cluster in config")
    return cluster


def _engine(args: argparse.Namespace, config: Config) -> Engine:
    return build_engine(config, fixtures=args.fixtures)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_health(args: argparse.Namespace) -> int:
    config = _load_config(args)
    cluster = _cluster(args, config)
    report = _engine(args, config).health(cluster, services=args.service or None)
    print(health_json(report) if args.json else render_health(report, _renderer(args)))
    return EXIT_OK


def cmd_diagnose(args: argparse.Namespace) -> int:
    config = _load_config(args)
    cluster = _cluster(args, config)
    engine = _engine(args, config)

    services = list(args.service)
    if args.all_degraded:
        health = engine.health(cluster, with_tasks=False)
        services += [s.service_name for s in health.services if not s.is_converged]
        services = list(dict.fromkeys(services))
        if not services:
            print("Every service in the cluster is at its desired count. Nothing to diagnose.")
            return EXIT_OK
    if not services:
        raise CliError("no service given: pass --service NAME (repeatable) or --all-degraded")

    renderer = _renderer(args)
    diagnoses = [engine.diagnose(cluster, name) for name in services]

    if args.json:
        if len(diagnoses) == 1:
            print(diagnosis_json(diagnoses[0]))
        else:
            import json

            from .models import to_jsonable

            print(json.dumps([to_jsonable(d) for d in diagnoses], indent=2))
    else:
        for index, diagnosis in enumerate(diagnoses):
            if index:
                print("\n")
            print(render_diagnosis(diagnosis, renderer, brief=args.brief, max_options=args.max_options))

    if args.fail_on:
        limit = Severity[args.fail_on.upper()]
        breached = any(
            finding.severity.rank <= limit.rank for d in diagnoses for finding in d.findings
        )
        if breached:
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    config = _load_config(args)
    rules = {rule.id: rule for rule in all_rules()}
    if args.json:
        import json

        print(
            json.dumps(
                [
                    {
                        "id": rule_id,
                        "title": rules[rule_id].title,
                        "description": rules[rule_id].description,
                        "enabled": rule_id not in config.disabled_rules,
                    }
                    for rule_id in rule_ids()
                ],
                indent=2,
            )
        )
        return EXIT_OK

    renderer = _renderer(args)
    print(renderer.paint("DIAGNOSIS RULES", "bold"))
    print(renderer.rule())
    rows = [
        [
            rule_id,
            "off" if rule_id in config.disabled_rules else "on",
            rules[rule_id].title,
        ]
        for rule_id in rule_ids()
    ]
    print("\n".join(renderer.table(["RULE", "STATE", "TITLE"], rows)))
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CollectorError, FileNotFoundError, ValueError, RuntimeError) as exc:
        if getattr(args, "debug", False):
            raise
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # e.g. piping into `head`
        return EXIT_OK
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
