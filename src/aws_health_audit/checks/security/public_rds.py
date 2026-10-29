"""RDS instances with a public endpoint."""

from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class PublicRdsCheck(Check):
    """DB instances whose PubliclyAccessible flag is true."""

    id = "SEC-RDS-PUBLIC"
    title = "Public RDS instances"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "RDS instances that have a publicly reachable endpoint."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        client = ctx.client("rds", region)
        findings: list[Finding] = []
        for instance in collect(client, "describe_db_instances", "DBInstances"):
            if not instance.get("PubliclyAccessible"):
                continue
            name = instance.get("DBInstanceIdentifier", "unknown")
            arn = instance.get("DBInstanceArn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            findings.append(
                finding(
                    self,
                    title=f"RDS instance is publicly accessible: {name}",
                    severity=Severity.HIGH,
                    impact="The database endpoint accepts connections from outside the VPC.",
                    recommendation=(
                        f"Set PubliclyAccessible to false on {name} and reach it through "
                        "a bastion, VPN, or private network path."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=name,
                    evidence={"engine": instance.get("Engine")},
                )
            )
        return findings
