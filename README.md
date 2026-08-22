# ECS SRE Diagnostic & Recommendation Engine

**Collect → correlate → diagnose → recommend. Never remediate.**

An SRE CLI that reads ECS, the ALB, Prometheus, and Splunk, correlates what it finds against the
service's deployment history, and prints a diagnosis with ranked remediation *options*.

It never restarts a task, scales a service, rolls back a deployment, or changes infrastructure.
That is the point: engineers get actionable analysis without granting a tool write access to
production. Every recommendation is printed with `EXECUTION: NOT PERFORMED`, and a test in the
suite fails the build if a mutating AWS call ever appears in the package.

```
$ sre ecs diagnose --cluster prod --service payments-api

VERDICT: DEGRADED — 4 finding(s). Most likely: Connection pool exhaustion (confidence HIGH).
```

---

## Quickstart

No AWS account needed — the repo ships a fixture cluster with five services and four different
incidents, so the whole engine runs offline:

```bash
python3 -m ecs_diag ecs health   --fixtures examples/incident-cluster --cluster prod
python3 -m ecs_diag ecs diagnose --fixtures examples/incident-cluster --cluster prod --service payments-api
python3 -m ecs_diag ecs diagnose --fixtures examples/incident-cluster --cluster prod --all-degraded --brief
```

Install it as the `sre` command:

```bash
pip install -e ".[aws]"        # boto3 is only needed for live AWS collection
sre ecs health --cluster prod
```

The engine, the rules, the reports, and the Prometheus/Splunk clients are **stdlib-only**.
`boto3` is an extra needed only to talk to real AWS; `pyyaml` is an extra needed only if you want
YAML config instead of JSON.

### The fixture cluster

| Service | What it demonstrates |
|---|---|
| `payments-api` | Latency + 5xx spike minutes after a deploy, with pool exhaustion in the logs |
| `checkout-api` | OOM kills (exit 137) plus a deployment that never converged |
| `orders-api` | `CannotPullContainerError` — a failed rollout with the image as the root cause |
| `inventory-api` | ECS converged and healthy while every ALB target fails its health check |
| `search-api` | Healthy — the report must stay quiet |

---

## Commands

```
sre ecs health     [--cluster NAME] [--service NAME ...]
sre ecs diagnose   [--cluster NAME] (--service NAME ... | --all-degraded)
sre ecs rules
```

Shared options: `--config PATH`, `--region`, `--profile`, `--window MINUTES`, `--fixtures DIR`,
`--json`, `--no-color`, `--width N`, `--disable-rule ID`, `--debug`.

`diagnose` adds:

| Option | Effect |
|---|---|
| `--all-degraded` | Diagnose every service not at its desired count |
| `--brief` | One-line remediation options instead of full option boxes |
| `--max-options N` | Show at most N options per finding |
| `--fail-on LEVEL` | Exit `2` when a finding at or above `critical\|high\|medium\|low` is reported |

Exit codes: `0` success, `2` `--fail-on` threshold breached, `3` error. `--fail-on` is what makes
this usable as a deployment gate in CI — it reports, CI decides.

---

## Architecture

```
                         ┌──────────────────────┐
                         │       SRE CLI        │
                         │  sre ecs health      │
                         │  sre ecs diagnose    │
                         └──────────┬───────────┘
                                    ▼
                     ┌──────────────────────────┐
                     │  ECS Diagnostic Engine   │
                     └────────────┬─────────────┘
             ┌────────────────────┼─────────────────────┐
             ▼                    ▼                     ▼
      ┌────────────┐       ┌────────────┐       ┌────────────┐
      │  AWS ECS   │       │ Prometheus │       │   Splunk   │
      │  + ALB     │       │            │       │            │
      └─────┬──────┘       └─────┬──────┘       └─────┬──────┘
            │                    │                    │
       services              CPU / memory          errors
       tasks                 request rate          exceptions
       deployments           latency               patterns
       events                restarts              recent errors
       target health         availability
            │                    │                    │
            └────────────────────┼────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Correlation Engine      │  ← did the deploy cause this?
                    └────────────┬────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Diagnosis Engine        │  ← 13 rules over the evidence
                    └────────────┬────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Remediation Advisor     │
                    │ NEVER EXECUTES ACTIONS  │
                    └────────────┬────────────┘
                                 ▼
                         ┌───────────────┐
                         │  SRE REPORT   │
                         └───────────────┘
```

Grafana is deliberately not a collector: Prometheus is the metrics source and Grafana stays the
visualisation layer.

### Layout

```
ecs_diag/
  cli.py            argparse CLI — three read-only verbs, no mutating verb exists
  engine.py         collect → correlate → diagnose orchestration
  models.py         the data model (snapshots, findings, recommendations)
  config.py         config file + env overrides, query templates, thresholds
  correlation.py    deployment correlation and the incident timeline
  advisor.py        the remediation catalog (58 options across 13 rules)
  report.py         text report + JSON
  collectors/
    ecs.py          DescribeServices / ListTasks / DescribeTasks (boto3)
    alb.py          elbv2 target health + CloudWatch ALB metrics
    prometheus.py   /api/v1/query and /api/v1/query_range
    splunk.py       /services/search/jobs create → poll → results
    fixtures.py     the same interfaces, backed by JSON on disk
  rules/            13 rules in five modules, self-registering
```

Each collector is an interface with a live implementation and a fixture implementation, so the
whole engine is exercisable without touching a cloud account. A source that fails degrades the
report (a `COLLECTION WARNINGS` section) rather than aborting it — a diagnosis from ECS alone is
still worth printing when Splunk is down.

---

## What it checks

### 1. ECS service health
Desired / running / pending counts, deployment status and age, failed tasks, task definition,
service status, launch type, capacity provider, health check grace period, and service events.
Deployment `failedTasks`, `rolloutState`, and per-deployment counts are read straight off the
deployment object.

### 2. ECS task health
For every unhealthy service: running and stopped tasks, exit codes, stop reasons, container exit
reasons, container health, OOM signatures, essential container failures, image pull failures,
startup failures, and network errors. Especially important on Fargate, where the task is the only
place the failure is recorded.

```
STOPPED TASKS (last 15m)
TASK    REASON                                EXIT  WHEN
──────  ────────────────────────────────────  ────  ───────
abc123  Essential container in task exited    137   3m ago
def456  OutOfMemoryError: Container killed    137   7m ago
```

### 3. ALB health
Healthy and unhealthy targets, unhealthy reasons, target response time, 4xx, 5xx, target
connection errors, and request count — then the correlation that matters:

- ECS healthy **+** ALB unhealthy → application, container, or health-check configuration problem
- ECS healthy **+** ALB healthy **+** rising 5xx → application or dependency problem

Both are stated explicitly in the finding's evidence, so the reader does not have to infer them.

### 4. Prometheus
CPU, memory working set, restart count, request rate, error rate, and p50/p95/p99 latency.
Every query is a **template you can override** because metric names differ between shops.
Baselines use the same query evaluated at `now − baseline_offset` (default 24h) through the
instant query's `time` parameter, so no query rewriting is involved.

### 5. Splunk
Level counts, top errors, top exceptions, and sample messages via the search-jobs REST API
(create → poll → results). This answers "what is the application actually complaining about?"

### 6. Deployment correlation
```
┌────────────────────────────────────────────────────────────────────────┐
│ 🔴 HIGH PROBABILITY DEPLOYMENT RELATED                                 │
│                                                                        │
│ Current version:   payments-api:142                                    │
│ Previous version:  payments-api:141                                    │
│ Deployment age:    6 minutes                                           │
│                                                                        │
│ Observed after deployment:                                             │
│   CPU             +38%                                                 │
│   p95 latency     +997%                                                │
│   5xx             +15700%                                              │
│                                                                        │
│ Splunk: "Connection pool exhausted: timeout acquiring connection"      │
│                                                                        │
│ Assessment: The incident is strongly correlated with the most recent   │
│ deployment (payments-api:142, 6 minutes ago). Multiple independent     │
│ signals degraded after it landed.                                      │
│ Confidence: HIGH                                                       │
└────────────────────────────────────────────────────────────────────────┘

Timeline:
    16:08  Deployment payments-api:142
    16:09  CPU increases
    16:09  p95 latency increases
    16:10  5xx increases
```

One detail worth calling out: when a metric has a time series, the engine checks **when** it
turned. A metric that was already degrading *before* the deploy landed is reported separately
under "Already degrading before the deployment" and does **not** count toward the correlation
score. Crediting a deploy for a regression that predates it is how a tool gets a rollback ordered
for the wrong reason.

### 7. Diagnosis rules

| Rule | Fires on | Priority |
|---|---|---|
| `oom` | Exit 137 / OutOfMemoryError, corroborated by memory % and logs | root cause |
| `image_pull_failure` | `CannotPullContainerError`, manifest/auth failures | root cause |
| `network_failure` | `ResourceInitializationError`, ENI attach, DNS/egress | root cause |
| `capacity_failure` | Placement failures, no instance met requirements, no free IPs | root cause |
| `connection_exhaustion` | Pool exhausted / timeout acquiring connection | root cause |
| `dependency_failure` | Downstream timeouts, refused connections, circuit breakers | root cause |
| `deployment_failure` | Rollout FAILED, failed tasks, or a stalled rollout | symptom |
| `task_failure` | Repeated stops nothing more specific explains; crash loops | symptom |
| `alb_unhealthy` | Targets failing health checks | symptom |
| `error_rate_high` | 5xx above a share of traffic (Prometheus, else ALB) | symptom |
| `latency_high` | p95 over threshold, or far above its own baseline | symptom |
| `cpu_high` / `memory_high` | Utilisation above threshold | symptom |

Findings are ordered by severity, then by how close the rule sits to a root cause. A failed image
pull outranks "the deployment is not converging" — the second is caused by the first, and the
report should lead with the thing an engineer can act on.

Rules also defer to each other rather than double-reporting: `memory_high` stays quiet when `oom`
already fired, `dependency_failure` stays quiet when `connection_exhaustion` explains the same
logs, and `task_failure` ignores stops that a specific rule already owns.

---

## The design principle

Every recommendation carries **action, why, evidence, risk, expected effect, command, and
execution status**:

```
┌────────────────────────────────────────────────────────────────────────┐
│ REMEDIATION OPTION #5                                                  │
├────────────────────────────────────────────────────────────────────────┤
│ Action: Increase task memory if the higher usage is justified          │
│                                                                        │
│ Why:                                                                   │
│   If usage is legitimate and stable, the allocation is too small.      │
│                                                                        │
│ Risk: LOW/MEDIUM                                                       │
│                                                                        │
│ Expected effect:                                                       │
│   Reduces memory-related task termination.                             │
│                                                                        │
│ Command:                                                               │
│   aws ecs register-task-definition --cli-input-json file://taskdef.json│
│                                                                        │
│ EXECUTION: NOT PERFORMED                                               │
└────────────────────────────────────────────────────────────────────────┘
```

The command is printed so a human can read it, understand it, and decide. The tool does not run it.

---

## Configuration

Config is discovered at `./sre.yaml`, `./sre.json`, `~/.config/sre-ecs/`, or `$HOME`, or given with
`--config`. See [`sre.example.yaml`](sre.example.yaml) for a fully commented file covering
endpoints, query templates, and every threshold.

Secrets are better passed by environment: `PROMETHEUS_URL`, `PROMETHEUS_TOKEN`, `SPLUNK_URL`,
`SPLUNK_TOKEN`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`, `SPLUNK_INDEX`, `AWS_REGION`, `AWS_PROFILE`,
`ECS_CLUSTER`. Unconfigured backends are not an error — the report says which sources were
unavailable and diagnoses from what it has.

### Required IAM (read-only)

```
ecs:ListServices, ecs:DescribeServices, ecs:ListTasks, ecs:DescribeTasks,
ecs:DescribeTaskDefinition, ecs:ListContainerInstances,
elasticloadbalancing:DescribeTargetGroups, elasticloadbalancing:DescribeTargetHealth,
cloudwatch:GetMetricData
```

No write permission is needed, and none should be granted.

---

## Tests

```bash
python3 -m unittest discover -s tests -t .      # 113 tests, no network, no AWS
```

Coverage includes every rule's fire/quiet behaviour, the correlation scorer (including the
pre-deployment guard), degraded-source handling, report alignment, JSON serialisation, CLI exit
codes, and two safety tests: one asserting no mutating AWS API call exists anywhere in the
package, and one asserting the CLI exposes no verb beyond `health`, `diagnose`, and `rules`.
