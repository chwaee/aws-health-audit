"""Idle EC2 instances."""

from datetime import timedelta

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.pricing import format_usd, instance_monthly_usd
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import classify_cpu, ensure_utc, waste_severity
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, EstimateSource, Finding, Severity


class IdleEc2Check(Check):
    """Running instances with average CPU under the idle threshold.

    Uses one GetMetricData batch per region. Instances launched more recently
    than the window are skipped. Older instances with too few points become
    INFO instead of a waste finding.
    """

    id = "COST-EC2-IDLE"
    title = "Idle EC2 instances"
    category = Category.COST
    scope = Scope.REGIONAL
    description = "Running instances whose average CPU stays under the idle threshold."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        now = utcnow()
        thresholds = ctx.config.thresholds
        samples = ctx.cpu_samples(region)
        findings: list[Finding] = []
        for instance in _running(ctx.instances(region)):
            instance_id = instance["InstanceId"]
            arn = ec2_arn(region, ctx.account_id, "instance", instance_id)
            if ctx.is_ignored(self.id, resource_id=instance_id, arn=arn, tags=instance.get("Tags")):
                continue
            assessment = classify_cpu(samples.get(instance_id, []), now, thresholds)
            if assessment.kind == "insufficient":
                launch = instance.get("LaunchTime")
                old_enough = launch is not None and now - ensure_utc(launch) >= timedelta(
                    days=thresholds.idle_days
                )
                if old_enough:
                    findings.append(
                        finding(
                            self,
                            title=f"EC2 CPU metrics are incomplete: {instance_id}",
                            severity=Severity.INFO,
                            impact=(
                                "The instance looks old enough to price, but CloudWatch "
                                "did not return a full idle window of CPU."
                            ),
                            recommendation=(
                                "Confirm the instance is running and that "
                                "cloudwatch:GetMetricData is allowed, then rerun the audit."
                            ),
                            region=region,
                            resource_arn=arn,
                            resource_id=instance_id,
                            evidence={"datapoints": assessment.idle_points},
                        )
                    )
                continue
            if assessment.kind != "idle":
                continue
            instance_type = instance.get("InstanceType", "unknown")
            monthly, confidence = instance_monthly_usd(instance_type)
            findings.append(
                finding(
                    self,
                    title=(
                        f"Idle EC2 instance: {instance_id} "
                        f"({thresholds.idle_days} days, est. waste: {format_usd(monthly)}/mo)"
                    ),
                    severity=waste_severity(monthly, thresholds) or Severity.LOW,
                    impact=(
                        "A running instance with almost no CPU still bills for compute all month."
                    ),
                    recommendation=(
                        f"Stop or terminate {instance_id} ({instance_type}) if the workload "
                        "is retired. Snapshot any volumes you still need first."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=instance_id,
                    evidence={
                        "instance_type": instance_type,
                        "average_cpu_percent": round(assessment.idle_average or 0, 2),
                        "datapoints": assessment.idle_points,
                        "window_days": thresholds.idle_days,
                        "estimate_confidence": confidence,
                    },
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return findings


def _running(instances: list[dict]) -> list[dict]:
    return [item for item in instances if item.get("State", {}).get("Name") == "running"]
