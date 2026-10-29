"""Running instances the SSM agent is not reporting as online."""

from datetime import timedelta

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import ensure_utc
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class SsmAgentCheck(Check):
    """Running instances missing from SSM or whose PingStatus is not Online.

    Instances launched in the last hour are INFO. A missing instance profile
    is included in the evidence because the agent cannot register without one.
    """

    id = "SEC-SSM-AGENT"
    title = "SSM agent"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "Running EC2 instances where the SSM agent is not online."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        inventory = collect(
            ctx.client("ssm", region),
            "describe_instance_information",
            "InstanceInformationList",
        )
        online = {
            item["InstanceId"]
            for item in inventory
            if item.get("PingStatus") == "Online" and item.get("InstanceId")
        }
        now = utcnow()
        findings: list[Finding] = []
        for instance in ctx.instances(region):
            if instance.get("State", {}).get("Name") != "running":
                continue
            instance_id = instance["InstanceId"]
            if instance_id in online:
                continue
            arn = ec2_arn(region, ctx.account_id, "instance", instance_id)
            if ctx.is_ignored(self.id, resource_id=instance_id, arn=arn, tags=instance.get("Tags")):
                continue
            launch = instance.get("LaunchTime")
            fresh = launch is not None and now - ensure_utc(launch) < timedelta(hours=1)
            profile = (instance.get("IamInstanceProfile") or {}).get("Arn")
            findings.append(
                finding(
                    self,
                    title=f"SSM agent is not online: {instance_id}",
                    severity=Severity.INFO if fresh else Severity.MEDIUM,
                    impact="The instance cannot be patched or inspected through Systems Manager.",
                    recommendation=(
                        (
                            f"Attach an instance profile with AmazonSSMManagedInstanceCore "
                            f"to {instance_id} and confirm the agent is running."
                        )
                        if not profile
                        else (
                            f"Check the SSM agent and VPC endpoints on {instance_id}. "
                            "The instance profile is present."
                        )
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=instance_id,
                    evidence={"instance_profile": profile, "within_launch_grace": fresh},
                )
            )
        return findings
