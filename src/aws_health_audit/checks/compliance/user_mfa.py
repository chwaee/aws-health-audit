"""MFA for IAM users who can sign in to the console."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import credential_flag
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class UserMfaCheck(Check):
    """Console users without MFA. CIS v3.0.0 control 1.10."""

    id = "CIS-1.10-USER-MFA"
    title = "IAM user MFA"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "IAM users with a console password and no MFA."
    cis_controls = ("1.10",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        findings: list[Finding] = []
        for row in ctx.credential_report():
            if row.get("user") == "<root_account>":
                continue
            if not credential_flag(row, "password_enabled") or credential_flag(row, "mfa_active"):
                continue
            user = row.get("user", "unknown")
            arn = row.get("arn")
            if ctx.is_ignored(self.id, resource_id=user, arn=arn):
                continue
            findings.append(
                finding(
                    self,
                    title=f"IAM user {user} has a console password and no MFA",
                    severity=Severity.HIGH,
                    impact=(
                        "The console password is a single factor for an identity that can change "
                        "the account."
                    ),
                    recommendation=(
                        f"Enable MFA for {user} or remove the console password if the user is a"
                        f"workload."
                    ),
                    resource_arn=arn,
                    resource_id=user,
                )
            )
        return findings
