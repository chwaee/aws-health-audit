"""IAM users with policies attached directly."""

from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.iamlib import has_direct_policy
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class UserDirectPolicyCheck(Check):
    """Users with an attached or inline policy. CIS v3.0.0 control 1.15."""

    id = "CIS-1.15-USER-POLICIES"
    title = "Policies attached to IAM users"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "IAM users with a policy attached directly instead of through a group."
    cis_controls = ("1.15",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        iam = ctx.client("iam", "us-east-1")
        findings: list[Finding] = []
        for user in collect(iam, "list_users", "Users"):
            name = user["UserName"]
            arn = user.get("Arn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            if not has_direct_policy(iam, name):
                continue
            findings.append(
                finding(
                    self,
                    title=f"IAM user {name} has a policy attached directly",
                    severity=Severity.LOW,
                    impact=(
                        "Permissions on the user are harder to review than the same policy on a "
                        "group."
                    ),
                    recommendation=(
                        f"Move {name}'s policies onto a group or a role, then detach them from the"
                        f"user."
                    ),
                    resource_arn=arn,
                    resource_id=name,
                )
            )
        return findings
