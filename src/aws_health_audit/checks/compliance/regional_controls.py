"""Regional CIS checks: EBS default encryption, Config, default SG, IMDSv2, GuardDuty."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.paginate import call, collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class EbsDefaultEncryptionCheck(Check):
    """EBS encryption by default is off. CIS v3.0.0 control 2.2.1."""

    id = "CIS-2.2.1-EBS-DEFAULT-ENC"
    title = "EBS encryption by default"
    category = Category.COMPLIANCE
    scope = Scope.REGIONAL
    description = "Regions where EBS encryption by default is disabled."
    cis_controls = ("2.2.1",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        response = call(ctx.client("ec2", region), "get_ebs_encryption_by_default") or {}
        if response.get("EbsEncryptionByDefault"):
            return []
        return [
            finding(
                self,
                title=f"EBS encryption by default is off in {region}",
                severity=Severity.MEDIUM,
                impact=(
                    "New volumes in this region are created unencrypted unless the caller opts in."
                ),
                recommendation=f"Enable EBS encryption by default in {region}.",
                region=region,
                resource_id=region,
            )
        ]


class ConfigRecorderCheck(Check):
    """AWS Config is absent or not recording. CIS v3.0.0 control 3.3."""

    id = "CIS-3.3-CONFIG"
    title = "AWS Config recorder"
    category = Category.COMPLIANCE
    scope = Scope.REGIONAL
    description = "Regions where AWS Config is not recording."
    cis_controls = ("3.3",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        client = ctx.client("config", region)
        recorders = collect(client, "describe_configuration_recorders", "ConfigurationRecorders")
        statuses = collect(
            client,
            "describe_configuration_recorder_status",
            "ConfigurationRecordersStatus",
        )
        recording = any(item.get("recording") for item in statuses)
        if recorders and recording:
            return []
        return [
            finding(
                self,
                title=f"AWS Config is not recording in {region}",
                severity=Severity.MEDIUM,
                impact=(
                    "Resource history for this region is missing, so drift is harder to explain."
                ),
                recommendation=(
                    f"Start a configuration recorder in {region} and deliver it to a centralbucket."
                ),
                region=region,
                resource_id=region,
                evidence={"recorders": len(recorders), "recording": recording},
            )
        ]


class DefaultSecurityGroupCheck(Check):
    """Default security groups that still have rules. CIS v3.0.0 control 5.4."""

    id = "CIS-5.4-DEFAULT-SG"
    title = "Default security group rules"
    category = Category.COMPLIANCE
    scope = Scope.REGIONAL
    description = "Default security groups that allow inbound or outbound traffic."
    cis_controls = ("5.4",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        findings: list[Finding] = []
        for group in ctx.security_groups(region):
            if group.get("GroupName") != "default":
                continue
            if not group.get("IpPermissions") and not group.get("IpPermissionsEgress"):
                continue
            group_id = group["GroupId"]
            arn = ec2_arn(region, ctx.account_id, "security-group", group_id)
            if ctx.is_ignored(self.id, resource_id=group_id, arn=arn, tags=group.get("Tags")):
                continue
            findings.append(
                finding(
                    self,
                    title=f"Default security group has rules: {group_id}",
                    severity=Severity.MEDIUM,
                    impact=(
                        "Resources launched into the default group inherit rules nobody meant to "
                        "review."
                    ),
                    recommendation=f"Remove every inbound and outbound rule from {group_id}.",
                    region=region,
                    resource_arn=arn,
                    resource_id=group_id,
                    evidence={"vpc_id": group.get("VpcId")},
                )
            )
        return findings


class Imdsv2Check(Check):
    """Running instances that do not require IMDSv2. CIS v3.0.0 control 5.6."""

    id = "CIS-5.6-IMDSV2"
    title = "IMDSv2"
    category = Category.COMPLIANCE
    scope = Scope.REGIONAL
    description = "Running instances that do not require IMDSv2."
    cis_controls = ("5.6",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        findings: list[Finding] = []
        for instance in ctx.instances(region):
            if instance.get("State", {}).get("Name") != "running":
                continue
            tokens = (instance.get("MetadataOptions") or {}).get("HttpTokens")
            if tokens == "required":
                continue
            instance_id = instance["InstanceId"]
            arn = ec2_arn(region, ctx.account_id, "instance", instance_id)
            if ctx.is_ignored(self.id, resource_id=instance_id, arn=arn, tags=instance.get("Tags")):
                continue
            findings.append(
                finding(
                    self,
                    title=f"Instance does not require IMDSv2: {instance_id}",
                    severity=Severity.HIGH,
                    impact=(
                        "IMDSv1 lets a server-side request forgery read the instance role "
                        "credentials."
                    ),
                    recommendation=(
                        f"Set HttpTokens to required on{instance_id} and hop limit to 1."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=instance_id,
                    evidence={"http_tokens": tokens},
                )
            )
        return findings


class GuardDutyCheck(Check):
    """No enabled GuardDuty detector in the region."""

    id = "CIS-GUARDDUTY"
    title = "GuardDuty"
    category = Category.COMPLIANCE
    scope = Scope.REGIONAL
    description = "Regions with no enabled GuardDuty detector."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        client = ctx.client("guardduty", region)
        detector_ids = [
            detector_id
            for detector_id in collect(client, "list_detectors", "DetectorIds")
            if isinstance(detector_id, str)
        ]
        enabled = False
        for detector_id in detector_ids:
            details = call(client, "get_detector", DetectorId=detector_id) or {}
            if details.get("Status") == "ENABLED":
                enabled = True
                break
        if enabled:
            return []
        return [
            finding(
                self,
                title=f"GuardDuty is not enabled in {region}",
                severity=Severity.HIGH,
                impact=(
                    "This region has no managed finding stream for credential misuse or "
                    "crypto-mining."
                ),
                recommendation=(
                    f"Enable a GuardDuty detector in {region}, or delegate it from theorganization."
                ),
                region=region,
                resource_id=region,
                evidence={"detectors": len(detector_ids)},
            )
        ]
