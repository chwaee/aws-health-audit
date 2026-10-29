"""Security groups that expose SSH or RDP to the internet."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import permission_opens_admin_port
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class OpenSecurityGroupCheck(Check):
    """Ingress from 0.0.0.0/0 or ::/0 to TCP 22, 3389, or all protocols.

    A group attached to an instance or ENI is HIGH. An unused group is MEDIUM.
    CIS AWS Foundations Benchmark v3.0.0 controls 5.2 and 5.3.
    """

    id = "SEC-SG-ADMIN-OPEN"
    title = "Security groups open to SSH or RDP"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "Security groups that allow SSH or RDP from the internet."
    cis_controls = ("5.2", "5.3")

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        attached = _attached_group_ids(ctx, region)
        findings: list[Finding] = []
        for group in ctx.security_groups(region):
            ports: set[int] = set()
            for permission in group.get("IpPermissions") or []:
                ports.update(permission_opens_admin_port(permission))
            if not ports:
                continue
            group_id = group["GroupId"]
            arn = ec2_arn(region, ctx.account_id, "security-group", group_id)
            if ctx.is_ignored(self.id, resource_id=group_id, arn=arn, tags=group.get("Tags")):
                continue
            in_use = group_id in attached
            port_text = ", ".join(str(port) for port in sorted(ports))
            findings.append(
                finding(
                    self,
                    title=f"Security group {group_id} allows {port_text} from the internet",
                    severity=Severity.HIGH if in_use else Severity.MEDIUM,
                    impact=(
                        "Anyone on the internet can attempt SSH or RDP against resources "
                        "that use this group."
                        if in_use
                        else (
                            "The rule is unused today, but attaching the group later would expose "
                            "admin ports."
                        )
                    ),
                    recommendation=(
                        f"Remove 0.0.0.0/0 and ::/0 from ports {port_text} on {group_id}. "
                        "Allow only your office, VPN, or bastion CIDR."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=group_id,
                    evidence={
                        "ports": sorted(ports),
                        "attached": in_use,
                        "group_name": group.get("GroupName"),
                    },
                )
            )
        return findings


def _attached_group_ids(ctx: AuditContext, region: str) -> set[str]:
    found: set[str] = set()
    for interface in ctx.network_interfaces(region):
        for group in interface.get("Groups") or []:
            if group.get("GroupId"):
                found.add(group["GroupId"])
    for instance in ctx.instances(region):
        for group in instance.get("SecurityGroups") or []:
            if group.get("GroupId"):
                found.add(group["GroupId"])
    return found
