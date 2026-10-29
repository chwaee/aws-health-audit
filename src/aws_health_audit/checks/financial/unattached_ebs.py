"""EBS volumes that are not attached to anything."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.pricing import ebs_monthly_usd, format_usd
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import waste_severity
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, EstimateSource, Finding, Severity


class UnattachedEbsCheck(Check):
    """Volumes in the available state. Storage price only, by volume type."""

    id = "COST-EBS-UNATTACHED"
    title = "Unattached EBS volumes"
    category = Category.COST
    scope = Scope.REGIONAL
    description = "EBS volumes in the available state."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        findings: list[Finding] = []
        for volume in ctx.volumes(region):
            if volume.get("State") != "available":
                continue
            volume_id = volume["VolumeId"]
            arn = ec2_arn(region, ctx.account_id, "volume", volume_id)
            if ctx.is_ignored(self.id, resource_id=volume_id, arn=arn, tags=volume.get("Tags")):
                continue
            size = int(volume.get("Size") or 0)
            volume_type = volume.get("VolumeType") or "gp3"
            monthly, confidence = ebs_monthly_usd(volume_type, size)
            findings.append(
                finding(
                    self,
                    title=(
                        f"Unattached EBS volume: {volume_id} "
                        f"({size} GiB {volume_type}, est. waste: {format_usd(monthly)}/mo)"
                    ),
                    severity=waste_severity(monthly, ctx.config.thresholds) or Severity.LOW,
                    impact=(
                        "An available volume is not serving an instance and still accrues storage "
                        "charges."
                    ),
                    recommendation=(
                        f"Snapshot {volume_id} if you need the data, then delete the volume."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=volume_id,
                    evidence={
                        "size_gib": size,
                        "volume_type": volume_type,
                        "estimate_confidence": confidence,
                    },
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return findings
