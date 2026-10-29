"""IAM identities with administrator or full IAM access."""

from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.iamlib import admin_reason, list_iam
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class AdminPolicyCheck(Check):
    """Users, groups, and roles with AdministratorAccess, IAMFullAccess, or star admin.

    Service-linked roles under /aws-service-role/ are skipped. Users who inherit
    admin from a group are critical. This was CIS 1.16 in v1.4 and is not a
    current v3.0.0 control. The finding says so.
    """

    id = "SEC-IAM-ADMIN"
    title = "Overly permissive IAM"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "IAM users, groups, and roles with administrator or iam:* access."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        iam = ctx.client("iam", "us-east-1")
        findings: list[Finding] = []
        admin_groups: dict[str, str] = {}
        for group in collect(iam, "list_groups", "Groups"):
            name = group["GroupName"]
            arn = group.get("Arn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            reason = admin_reason(iam, "group", name)
            if not reason:
                continue
            admin_groups[name] = reason
            findings.append(_identity_finding(self, ctx, "group", name, arn, reason, Severity.HIGH))

        for role in collect(iam, "list_roles", "Roles"):
            if str(role.get("Path", "")).startswith("/aws-service-role/"):
                continue
            name = role["RoleName"]
            arn = role.get("Arn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            reason = admin_reason(iam, "role", name)
            if reason:
                findings.append(
                    _identity_finding(self, ctx, "role", name, arn, reason, Severity.HIGH)
                )

        for user in collect(iam, "list_users", "Users"):
            name = user["UserName"]
            arn = user.get("Arn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            reasons: list[str] = []
            direct = admin_reason(iam, "user", name)
            if direct:
                reasons.append(direct)
            for membership in list_iam(iam, "list_groups_for_user", "Groups", UserName=name):
                group_name = membership["GroupName"]
                if group_name in admin_groups:
                    reasons.append(f"group {group_name} ({admin_groups[group_name]})")
            if reasons:
                findings.append(
                    _identity_finding(
                        self,
                        ctx,
                        "user",
                        name,
                        arn,
                        ", ".join(reasons),
                        Severity.CRITICAL,
                    )
                )
        return findings


def _identity_finding(
    check: Check,
    ctx: AuditContext,
    kind: str,
    name: str,
    arn: str | None,
    reason: str,
    severity: Severity,
) -> Finding:
    del ctx
    return finding(
        check,
        title=f"IAM {kind} {name} has administrator access",
        severity=severity,
        impact=f"This {kind} can create, change, or destroy resources across the account.",
        recommendation=(
            f"Replace {reason} on {kind} {name} with a scoped policy. "
            "CIS v3.0.0 dropped the old full-admin control, but the access is still too broad "
            "for a person or an application role."
        ),
        resource_arn=arn,
        resource_id=f"{kind}:{name}",
        evidence={"policy": reason, "identity_type": kind},
    )
