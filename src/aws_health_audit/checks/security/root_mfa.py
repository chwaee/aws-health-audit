"""Root account MFA."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import credential_flag, root_credential_row
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class RootMfaCheck(Check):
    """Root user mfa_active is false on the IAM credential report.

    CIS AWS Foundations Benchmark v3.0.0 control 1.5.
    """

    id = "SEC-IAM-ROOT-MFA"
    title = "Root account MFA"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "Root user without MFA enabled."
    cis_controls = ("1.5",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        row = root_credential_row(ctx.credential_report())
        if row is None or credential_flag(row, "mfa_active"):
            return []
        return [
            finding(
                self,
                title="Root account MFA is not enabled",
                severity=Severity.CRITICAL,
                impact="The root user can take every action in the account with only a password.",
                recommendation=(
                    "Enable MFA on the root user and store the device with the account owner. "
                    "Prefer a hardware key. Do not use root for daily work."
                ),
                resource_arn=row.get("arn") or f"arn:aws:iam::{ctx.account_id}:root",
                resource_id="root",
                evidence={"mfa_active": row.get("mfa_active")},
            )
        ]
