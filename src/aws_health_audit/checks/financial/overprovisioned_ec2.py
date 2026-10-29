"""EC2 instances that stay well below the CPU they were sized for."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.aws.pricing import downsize_instance_type, format_usd, instance_monthly_usd
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import classify_cpu, waste_severity
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, EstimateSource, Finding, Severity


class OverprovisionedEc2Check(Check):
    """Low CPU that is not already idle, with a one-step downsize suggestion.

    Savings are half the current rate card. When the CloudWatch agent publishes
    mem_used_percent, that average is included. A missing metric is called out
    instead of being treated as low memory.
    """

    id = "COST-EC2-OVERPROV"
    title = "Overprovisioned EC2 instances"
    category = Category.COST
    scope = Scope.REGIONAL
    description = "Running instances with sustained low CPU that can move down a size."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        now = utcnow()
        thresholds = ctx.config.thresholds
        samples = ctx.cpu_samples(region)
        try:
            memory = ctx.memory_used_percent(region)
        except (AccessDeniedError, AwsClientError, ThrottlingError):
            memory = {}
        findings: list[Finding] = []
        for instance in ctx.instances(region):
            if instance.get("State", {}).get("Name") != "running":
                continue
            instance_id = instance["InstanceId"]
            arn = ec2_arn(region, ctx.account_id, "instance", instance_id)
            if ctx.is_ignored(self.id, resource_id=instance_id, arn=arn, tags=instance.get("Tags")):
                continue
            assessment = classify_cpu(samples.get(instance_id, []), now, thresholds)
            if assessment.kind != "overprovisioned":
                continue
            instance_type = instance.get("InstanceType", "")
            smaller = downsize_instance_type(instance_type)
            if smaller is None:
                continue
            monthly, confidence = instance_monthly_usd(instance_type)
            savings = round(monthly / 2, 2)
            memory_average = memory.get(instance_id)
            if memory_average is None:
                memory_note = "Memory is unknown because the CloudWatch agent metric is missing."
            else:
                memory_note = f"CloudWatch agent memory averages {memory_average:.1f}%."
            findings.append(
                finding(
                    self,
                    title=(
                        f"Overprovisioned EC2 instance: {instance_id} "
                        f"({instance_type} -> {smaller}, est. waste: {format_usd(savings)}/mo)"
                    ),
                    severity=waste_severity(savings, thresholds) or Severity.LOW,
                    impact="The instance is paying for CPU it does not use.",
                    recommendation=(
                        f"Test a move from {instance_type} to {smaller}. {memory_note} "
                        "Confirm memory headroom before you resize."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=instance_id,
                    evidence={
                        "instance_type": instance_type,
                        "recommended_type": smaller,
                        "average_cpu_percent": round(assessment.over_average or 0, 2),
                        "datapoints": assessment.over_points,
                        "window_days": thresholds.overprovisioned_days,
                        "memory_used_percent": None
                        if memory_average is None
                        else round(memory_average, 2),
                        "estimate_method": "half_of_current",
                        "estimate_confidence": confidence,
                    },
                    estimated_monthly_waste_usd=savings,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return findings
