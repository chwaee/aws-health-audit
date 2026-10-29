"""EBS volumes that are not encrypted."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class UnencryptedEbsCheck(Check):
    """Volumes with Encrypted false. In-use volumes are HIGH. Available volumes are MEDIUM."""

    id = "SEC-EBS-UNENCRYPTED"
    title = "Unencrypted EBS volumes"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "EBS volumes that do not have encryption at rest."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        findings: list[Finding] = []
        for volume in ctx.volumes(region):
            if volume.get("Encrypted"):
                continue
            state = volume.get("State")
            if state not in {"in-use", "available"}:
                continue
            volume_id = volume["VolumeId"]
            arn = ec2_arn(region, ctx.account_id, "volume", volume_id)
            if ctx.is_ignored(self.id, resource_id=volume_id, arn=arn, tags=volume.get("Tags")):
                continue
            in_use = state == "in-use"
            findings.append(
                finding(
                    self,
                    title=f"Unencrypted EBS volume: {volume_id}",
                    severity=Severity.HIGH if in_use else Severity.MEDIUM,
                    impact=(
                        "A snapshot or stolen disk image of this volume is readable without a key."
                    ),
                    recommendation=(
                        f"Create an encrypted snapshot of {volume_id} and replace the volume. "
                        "Turn on EBS encryption by default so the next volume is covered."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=volume_id,
                    evidence={"state": state, "volume_type": volume.get("VolumeType")},
                )
            )
        return findings
