"""VPCs without an active flow log."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class VpcFlowLogCheck(Check):
    """A VPC with no ACTIVE flow log whose resource id is the VPC itself.

    CIS AWS Foundations Benchmark v3.0.0 control 3.7.
    """

    id = "SEC-VPC-FLOW-LOGS"
    title = "VPC flow logs"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "VPCs that do not have an active VPC-level flow log."
    cis_controls = ("3.7",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        ec2 = ctx.client("ec2", region)
        covered = {
            item.get("ResourceId")
            for item in collect(ec2, "describe_flow_logs", "FlowLogs")
            if item.get("FlowLogStatus") == "ACTIVE"
            and str(item.get("ResourceId", "")).startswith("vpc-")
        }
        findings: list[Finding] = []
        for vpc in collect(ec2, "describe_vpcs", "Vpcs"):
            vpc_id = vpc["VpcId"]
            if vpc_id in covered:
                continue
            arn = ec2_arn(region, ctx.account_id, "vpc", vpc_id)
            if ctx.is_ignored(self.id, resource_id=vpc_id, arn=arn, tags=vpc.get("Tags")):
                continue
            findings.append(
                finding(
                    self,
                    title=f"VPC flow logs are missing: {vpc_id}",
                    severity=Severity.MEDIUM,
                    impact=(
                        "Rejected and accepted connections in this VPC are not retained for "
                        "investigation."
                    ),
                    recommendation=(
                        f"Create an ACTIVE flow log on {vpc_id} and deliver it to CloudWatch"
                        f"Logs or S3."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=vpc_id,
                    evidence={"is_default": vpc.get("IsDefault", False)},
                )
            )
        return findings
