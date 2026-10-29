"""Recent use of the root user."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import age_days, parse_credential_time, root_credential_row
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class RootUseCheck(Check):
    """Root password or access key used inside the configured window.

    CIS v3.0.0 control 1.7.
    """

    id = "CIS-1.7-ROOT-USE"
    title = "Recent root use"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Root password or access key was used recently."
    cis_controls = ("1.7",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        row = root_credential_row(ctx.credential_report())
        if row is None:
            return []
        now = utcnow()
        limit = ctx.config.thresholds.root_use_days
        fields = (
            "password_last_used",
            "access_key_1_last_used_date",
            "access_key_2_last_used_date",
        )
        recent = []
        for field in fields:
            moment = parse_credential_time(row.get(field))
            days = age_days(moment, now)
            if days is not None and days <= limit:
                recent.append({"field": field, "age_days": days})
        if not recent:
            return []
        return [
            finding(
                self,
                title="Root user was used recently",
                severity=Severity.HIGH,
                impact="Root activity means the break-glass credential is in daily use.",
                recommendation=(
                    "Move that work to an IAM role. "
                    "Keep root for billing and account recovery only."
                ),
                resource_arn=row.get("arn"),
                resource_id="root",
                evidence={"recent_activity": recent, "window_days": limit},
            )
        ]
