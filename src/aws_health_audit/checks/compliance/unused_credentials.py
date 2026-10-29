"""Credentials that have not been used recently."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import (
    credential_flag,
    is_unused,
    parse_credential_time,
)
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class UnusedCredentialsCheck(Check):
    """Passwords or active keys unused for the configured number of days.

    CIS v3.0.0 control 1.12. Never-used credentials count once they are old enough.
    """

    id = "CIS-1.12-UNUSED-CREDS"
    title = "Unused IAM credentials"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "IAM passwords or access keys unused for 45 days or more."
    cis_controls = ("1.12",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        now = utcnow()
        days = ctx.config.thresholds.unused_credential_days
        findings: list[Finding] = []
        for row in ctx.credential_report():
            if row.get("user") == "<root_account>":
                continue
            user = row.get("user", "unknown")
            arn = row.get("arn")
            if ctx.is_ignored(self.id, resource_id=user, arn=arn):
                continue
            created = parse_credential_time(row.get("user_creation_time"))
            if credential_flag(row, "password_enabled") and is_unused(
                parse_credential_time(row.get("password_last_used")),
                created,
                now,
                days,
            ):
                findings.append(_finding(self, user, arn, "password", days))
            for slot in (1, 2):
                if not credential_flag(row, f"access_key_{slot}_active"):
                    continue
                rotated = parse_credential_time(row.get(f"access_key_{slot}_last_rotated"))
                last_used = parse_credential_time(row.get(f"access_key_{slot}_last_used_date"))
                if is_unused(last_used, rotated or created, now, days):
                    findings.append(_finding(self, user, arn, f"access key {slot}", days))
        return findings


def _finding(check: Check, user: str, arn: str | None, kind: str, days: int) -> Finding:
    return finding(
        check,
        title=f"IAM user {user} has an unused {kind}",
        severity=Severity.MEDIUM,
        impact=f"The {kind} has not been used for at least {days} days and can still authenticate.",
        recommendation=(
            f"Disable the unused {kind} for {user}. Delete it after you confirm nothing depends on"
            f"it."
        ),
        resource_arn=arn,
        resource_id=f"{user}:{kind}",
        evidence={"credential": kind, "unused_days": days},
    )
