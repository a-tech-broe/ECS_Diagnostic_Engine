"""The remediation advisor.

Every entry here is an *option* presented to a human. Nothing in this module —
or anywhere else in the engine — executes an action against AWS. The command
strings exist so an engineer can copy, read, and decide.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from .models import Evidence, Recommendation, Risk

if TYPE_CHECKING:  # avoids an import cycle: rules import the advisor at runtime
    from .rules.base import RuleContext

EXECUTION_STATUS = "NOT PERFORMED"


@dataclass(frozen=True)
class Advice:
    """A remediation option template. ``command`` may use {service}, {cluster}, {task_def}, {window}."""

    action: str
    why: str
    expected_effect: str
    risk: Risk = Risk.MEDIUM
    command: Optional[str] = None


def _vars(ctx: "RuleContext") -> dict[str, str]:
    service = ctx.service
    task_def = service.task_definition or "TASK_DEFINITION"
    return {
        "cluster": service.cluster,
        "service": service.service_name,
        "task_def": task_def,
        "family": task_def.rsplit("/", 1)[-1].split(":")[0],
        "window": f"{ctx.window_minutes}m",
        "region": ctx.config.aws.region or "$AWS_REGION",
    }


def advise(rule_id: str, ctx: "RuleContext", evidence: list[Evidence]) -> list[Recommendation]:
    """Render the catalog for a rule into recommendations carrying this finding's evidence."""
    variables = _vars(ctx)
    recommendations: list[Recommendation] = []
    for advice in CATALOG.get(rule_id, []):
        recommendations.append(
            Recommendation(
                action=advice.action.format(**variables),
                why=advice.why.format(**variables),
                evidence=list(evidence),
                risk=advice.risk,
                expected_effect=advice.expected_effect.format(**variables),
                command=advice.command.format(**variables) if advice.command else None,
                execution_status=EXECUTION_STATUS,
            )
        )
    return recommendations


_DESCRIBE_SERVICE = "aws ecs describe-services --cluster {cluster} --services {service}"
_DESCRIBE_TASKDEF = "aws ecs describe-task-definition --task-definition {task_def}"
_LIST_STOPPED = (
    "aws ecs list-tasks --cluster {cluster} --service-name {service} --desired-status STOPPED"
)

CATALOG: dict[str, list[Advice]] = {
    # ---------------------------------------------------------------- tasks
    "task_failure": [
        Advice(
            action="Read the stop reasons on the recently stopped tasks",
            why="The stop reason and container exit code name the failure directly.",
            expected_effect="Turns 'tasks are dying' into a specific cause.",
            risk=Risk.LOW,
            command=_LIST_STOPPED,
        ),
        Advice(
            action="Check application logs for the failed tasks around their stop time",
            why="The container usually logs the fatal error before ECS records the exit.",
            expected_effect="Identifies the code path or dependency that failed.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Compare the failing task definition against the last known-good revision",
            why="A changed image, env var, or secret is the most common cause of new task failures.",
            expected_effect="Confirms or rules out a configuration regression.",
            risk=Risk.LOW,
            command=_DESCRIBE_TASKDEF,
        ),
        Advice(
            action="Consider rolling back to the previous task definition revision",
            why="If the failures began with the current revision, rollback restores service fastest.",
            expected_effect="Tasks stabilise on the last known-good revision.",
            risk=Risk.MEDIUM,
            command="aws ecs update-service --cluster {cluster} --service {service} --task-definition {family}:<PREVIOUS>",
        ),
    ],
    "oom": [
        Advice(
            action="Review the container memory allocation in the task definition",
            why="Containers are being killed with exit code 137, the OOM signature.",
            expected_effect="Establishes whether the limit is simply too low for the workload.",
            risk=Risk.LOW,
            command=_DESCRIBE_TASKDEF,
        ),
        Advice(
            action="Compare current memory usage against the task definition limit",
            why="Sustained usage near the limit means the workload has outgrown its allocation.",
            expected_effect="Quantifies the gap between demand and the configured limit.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Investigate recent memory growth for a leak",
            why="A steadily climbing working set that never drops indicates a leak, not a sizing problem.",
            expected_effect="Distinguishes a leak from under-provisioning; a leak is not fixed by more memory.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check whether the OOM kills started with the most recent deployment",
            why="A new release that raises memory demand is a common OOM trigger.",
            expected_effect="Points at rollback if the regression arrived with the release.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Increase task memory if the higher usage is justified",
            why="If usage is legitimate and stable, the allocation is simply too small.",
            expected_effect="Reduces memory-related task termination.",
            risk=Risk.LOW_MEDIUM,
            command="aws ecs register-task-definition --cli-input-json file://taskdef.json  # review memory first",
        ),
    ],
    "image_pull_failure": [
        Advice(
            action="Verify the image and tag exist in ECR",
            why="ECS reports CannotPullContainerError when the referenced image cannot be resolved.",
            expected_effect="Confirms whether the image reference itself is wrong.",
            risk=Risk.LOW,
            command="aws ecr describe-images --repository-name <REPO> --image-ids imageTag=<TAG>",
        ),
        Advice(
            action="Verify the task execution role can pull from the registry",
            why="ECR pulls use the execution role; a missing ecr:GetAuthorizationToken blocks every task.",
            expected_effect="Rules out an IAM permission gap on the execution role.",
            risk=Risk.LOW,
            command=_DESCRIBE_TASKDEF,
        ),
        Advice(
            action="Verify network egress from the task subnets to the registry",
            why="Private Fargate subnets need a NAT path or ECR/S3 VPC endpoints to pull images.",
            expected_effect="Rules out a networking cause for the pull failure.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Verify the image tag referenced by the task definition was actually pushed",
            why="A deployment that references a tag CI never pushed fails every task immediately.",
            expected_effect="Catches a broken build/deploy handoff.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Roll back to the previous task definition revision while the image is fixed",
            why="Rollback restores capacity without waiting for a rebuild.",
            expected_effect="Service returns to its previous, pullable image.",
            risk=Risk.MEDIUM,
            command="aws ecs update-service --cluster {cluster} --service {service} --task-definition {family}:<PREVIOUS>",
        ),
    ],
    "network_failure": [
        Advice(
            action="Check the security groups on the service's network configuration",
            why="Task ENIs that cannot reach dependencies fail health checks and startup probes.",
            expected_effect="Identifies a blocked egress or ingress path.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Verify subnet routing and NAT availability for the task subnets",
            why="A missing NAT route breaks image pulls, secrets retrieval and outbound calls at once.",
            expected_effect="Confirms whether egress is the shared root cause.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check ENI attachment errors in the service events",
            why="Fargate reports ENI provisioning failures as service events rather than task exits.",
            expected_effect="Surfaces account ENI limits or subnet IP exhaustion.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Verify VPC endpoints for ECR, S3, Secrets Manager and CloudWatch Logs",
            why="Private subnets without those endpoints cannot start tasks even when the app is fine.",
            expected_effect="Rules out missing endpoints as the startup blocker.",
            risk=Risk.LOW,
        ),
    ],
    "capacity_failure": [
        Advice(
            action="Read the placement failure messages in the service events",
            why="ECS states exactly which resource (CPU, memory, ports, ENIs) it could not satisfy.",
            expected_effect="Names the exhausted resource.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Check free CPU/memory across the cluster's container instances",
            why="EC2 launch type cannot place tasks when no instance has room for the reservation.",
            expected_effect="Confirms whether the cluster is simply full.",
            risk=Risk.LOW,
            command="aws ecs list-container-instances --cluster {cluster}",
        ),
        Advice(
            action="Check the capacity provider and its auto scaling group limits",
            why="A managed capacity provider at its max size stops adding instances silently.",
            expected_effect="Identifies a scaling ceiling.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check subnet free IP addresses for awsvpc tasks",
            why="Each awsvpc task consumes an IP; an exhausted subnet blocks placement.",
            expected_effect="Rules out IP exhaustion.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Consider raising capacity limits or reducing task reservations",
            why="Placement cannot succeed while demand exceeds the ceiling.",
            expected_effect="Allows pending tasks to be placed.",
            risk=Risk.MEDIUM,
        ),
    ],
    # ----------------------------------------------------------- deployment
    "deployment_failure": [
        Advice(
            action="Read the rollout state reason and failed task count on the deployment",
            why="ECS records why the rollout is not converging on the deployment object itself.",
            expected_effect="Explains the stall without guessing.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Inspect the most recent stopped tasks from this deployment",
            why="Failed deployments almost always leave stopped tasks carrying the real error.",
            expected_effect="Reveals image pull, OOM, or startup crash as the underlying cause.",
            risk=Risk.LOW,
            command=_LIST_STOPPED,
        ),
        Advice(
            action="Verify the health check grace period is long enough for this application",
            why="A grace period shorter than real startup time makes the ALB kill healthy tasks.",
            expected_effect="Stops premature task replacement during deploys.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Consider rolling back to the previous task definition revision",
            why="A deployment that cannot reach its desired count is degrading capacity while it retries.",
            expected_effect="Restores the last converged revision.",
            risk=Risk.MEDIUM,
            command="aws ecs update-service --cluster {cluster} --service {service} --task-definition {family}:<PREVIOUS>",
        ),
        Advice(
            action="Enable deployment circuit breaker with rollback for this service",
            why="The circuit breaker aborts a failing rollout automatically instead of retrying for hours.",
            expected_effect="Future bad deployments self-revert.",
            risk=Risk.MEDIUM,
        ),
    ],
    # ------------------------------------------------------------ resources
    "cpu_high": [
        Advice(
            action="Confirm the CPU rise against the pre-incident baseline",
            why="A step change points at a release; a ramp points at traffic growth.",
            expected_effect="Separates a code regression from organic load.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check whether request rate grew proportionally",
            why="CPU up with flat traffic means work per request increased — usually a code change.",
            expected_effect="Locates the regression.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Review the CPU units reserved in the task definition",
            why="Fargate throttles at the task CPU limit, which shows up as latency, not errors.",
            expected_effect="Identifies throttling as the limiting factor.",
            risk=Risk.LOW,
            command=_DESCRIBE_TASKDEF,
        ),
        Advice(
            action="Consider scaling out the service if the load is legitimate",
            why="More tasks spread the same work across more CPU.",
            expected_effect="Per-task CPU drops; latency recovers.",
            risk=Risk.MEDIUM,
            command="aws ecs update-service --cluster {cluster} --service {service} --desired-count <N>",
        ),
    ],
    "memory_high": [
        Advice(
            action="Compare the working set against the container memory limit",
            why="Sustained usage near the limit precedes OOM kills.",
            expected_effect="Predicts the OOM before it happens.",
            risk=Risk.LOW,
            command=_DESCRIBE_TASKDEF,
        ),
        Advice(
            action="Look for a monotonic upward trend across the window",
            why="Memory that only ever climbs is a leak.",
            expected_effect="Distinguishes a leak from under-provisioning.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check for cache or connection pool growth without bounds",
            why="Unbounded in-process caches are the most common source of container memory growth.",
            expected_effect="Finds a fixable application-level cause.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Consider increasing task memory if usage is legitimate",
            why="A workload that genuinely needs more memory will keep OOMing until it gets it.",
            expected_effect="Reduces the risk of imminent OOM kills.",
            risk=Risk.LOW_MEDIUM,
        ),
    ],
    # -------------------------------------------------------------- traffic
    "latency_high": [
        Advice(
            action="Inspect downstream database connections and slow queries",
            why="Latency that rises without CPU rising is usually spent waiting on a dependency.",
            expected_effect="Locates the slow dependency.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check connection pool utilisation and wait time",
            why="An exhausted pool converts a small slowdown into a service-wide latency cliff.",
            expected_effect="Explains a latency spike far larger than the dependency's own slowdown.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check database CPU and IO on the backing datastore",
            why="Saturated database CPU raises latency for every caller at once.",
            expected_effect="Confirms or clears the datastore.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Review recent database or schema changes",
            why="A new index, migration, or query plan change can degrade latency without any app deploy.",
            expected_effect="Finds a cause outside the service's own release history.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Consider temporary scaling if capacity is contributing",
            why="Queueing at the task level adds latency even when the dependency is healthy.",
            expected_effect="Reduces queueing delay while the root cause is addressed.",
            risk=Risk.MEDIUM,
            command="aws ecs update-service --cluster {cluster} --service {service} --desired-count <N>",
        ),
    ],
    "error_rate_high": [
        Advice(
            action="Group the errors by type and endpoint",
            why="A single failing endpoint and a service-wide failure need very different responses.",
            expected_effect="Narrows the blast radius.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check whether the errors began at the last deployment",
            why="A step change at deploy time is the strongest available signal for rollback.",
            expected_effect="Supports or rules out rollback.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Check dependency health for the calls behind the failing endpoints",
            why="Most 5xx bursts are a dependency failing underneath the service.",
            expected_effect="Moves the investigation to the real failing component.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Consider rolling back if the errors began with the current revision",
            why="Rollback is the fastest mitigation for a release-induced error rate.",
            expected_effect="Error rate returns to baseline.",
            risk=Risk.MEDIUM,
            command="aws ecs update-service --cluster {cluster} --service {service} --task-definition {family}:<PREVIOUS>",
        ),
    ],
    "alb_unhealthy": [
        Advice(
            action="Read the target health descriptions for the unhealthy targets",
            why="The ALB states whether it got a bad status code, a timeout, or a refused connection.",
            expected_effect="Distinguishes a failing app from a misconfigured health check.",
            risk=Risk.LOW,
            command="aws elbv2 describe-target-health --target-group-arn <ARN>",
        ),
        Advice(
            action="Verify the health check path, port, and expected status code",
            why="A health check pointing at a path the app does not serve fails 100% of the time.",
            expected_effect="Catches a configuration error rather than an outage.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Verify the health check grace period covers real startup time",
            why="Tasks killed during startup produce a permanent replace loop with healthy code.",
            expected_effect="Stops the churn.",
            risk=Risk.LOW,
            command=_DESCRIBE_SERVICE,
        ),
        Advice(
            action="Check the security group path from the ALB to the task port",
            why="Targets that the ALB cannot reach are marked unhealthy regardless of app state.",
            expected_effect="Rules out a network path problem.",
            risk=Risk.LOW,
        ),
    ],
    # --------------------------------------------------------- dependencies
    "connection_exhaustion": [
        Advice(
            action="Check the connection pool size against the concurrency the service is handling",
            why="The application is logging pool exhaustion, which caps throughput regardless of CPU.",
            expected_effect="Identifies the pool as the bottleneck.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check for connection leaks — connections acquired and never returned",
            why="A leak exhausts the pool permanently, so restarts appear to 'fix' it temporarily.",
            expected_effect="Explains a pool that never recovers on its own.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check the datastore's own connection limit and current count",
            why="Raising the client pool past the server limit moves the failure, it does not fix it.",
            expected_effect="Bounds any safe pool increase.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check whether pool pressure scales with the number of running tasks",
            why="Scaling out multiplies pool connections and can exhaust the datastore.",
            expected_effect="Prevents making the incident worse by scaling.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Consider tuning pool size or acquisition timeout after the checks above",
            why="Pool changes are only safe once the server-side limit is known.",
            expected_effect="Reduces acquisition waits without overwhelming the datastore.",
            risk=Risk.MEDIUM,
        ),
    ],
    "dependency_failure": [
        Advice(
            action="Identify the failing dependency from the logged exceptions",
            why="The application names the host or client that is failing.",
            expected_effect="Points the investigation at the right system.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check the dependency's own health and error rate",
            why="If the dependency is down, nothing done to this service will help.",
            expected_effect="Moves the incident to the owning team quickly.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check timeouts and retry policy for calls to that dependency",
            why="Long timeouts with aggressive retries turn a slow dependency into an outage.",
            expected_effect="Reduces amplification of the downstream problem.",
            risk=Risk.LOW,
        ),
        Advice(
            action="Check whether a circuit breaker or fallback exists for this call path",
            why="Without one, a single slow dependency consumes every worker.",
            expected_effect="Contains the blast radius of downstream failures.",
            risk=Risk.LOW,
        ),
    ],
}
