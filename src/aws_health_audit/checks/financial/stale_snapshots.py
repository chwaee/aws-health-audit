"""Old EBS snapshots that are not backing an AMI you own."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.paginate import collect
from aws_health_audit.aws.pricing import format_usd, snapshot_monthly_usd
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import age_days, snapshot_is_stale, waste_severity
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, EstimateSource, Finding, Severity


class StaleSnapshotCheck(Check):
    """Self-owned snapshots older than the threshold and not referenced by an owned AMI.

    The dollar figure uses the source volume size. That is an upper bound,
    because AWS bills incremental snapshot data.
    """

    id = "COST-SNAP-STALE"
    title = "Stale EBS snapshots"
    category = Category.COST
    scope = Scope.REGIONAL
    description = "Snapshots older than the age threshold that no owned AMI references."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        ec2 = ctx.client("ec2", region)
        images = collect(ec2, "describe_images", "Images", Owners=["self"])
        ami_snapshots = _ami_snapshot_ids(images)
        now = utcnow()
        max_age = ctx.config.thresholds.snapshot_age_days
        findings: list[Finding] = []
        for snapshot in collect(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
            snapshot_id = snapshot["SnapshotId"]
            start = snapshot.get("StartTime")
            if start is None or not snapshot_is_stale(
                start, snapshot_id, ami_snapshots, now, max_age
            ):
                continue
            arn = ec2_arn(region, ctx.account_id, "snapshot", snapshot_id)
            if ctx.is_ignored(self.id, resource_id=snapshot_id, arn=arn, tags=snapshot.get("Tags")):
                continue
            size = int(snapshot.get("VolumeSize") or 0)
            monthly = snapshot_monthly_usd(size)
            days = age_days(start, now) or max_age
            findings.append(
                finding(
                    self,
                    title=(
                        f"Stale snapshot: {snapshot_id} "
                        f"({days} days, est. waste: {format_usd(monthly)}/mo)"
                    ),
                    severity=waste_severity(monthly, ctx.config.thresholds) or Severity.LOW,
                    impact="Old snapshots keep storage charges after the volume or AMI is gone.",
                    recommendation=(
                        f"Delete {snapshot_id} if no backup policy still requires it. "
                        "The estimate uses the source volume size, so the bill may be lower."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=snapshot_id,
                    evidence={
                        "age_days": days,
                        "volume_size_gib": size,
                        "estimate_confidence": "low",
                        "billing": "upper_bound_using_volume_size",
                    },
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return findings


def _ami_snapshot_ids(images: list[dict]) -> set[str]:
    found: set[str] = set()
    for image in images:
        for mapping in image.get("BlockDeviceMappings") or []:
            snapshot_id = (mapping.get("Ebs") or {}).get("SnapshotId")
            if snapshot_id:
                found.add(snapshot_id)
    return found
