"""Root access keys."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import credential_flag, root_credential_row
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class RootKeysCheck(Check):
    """Root has an active access key. CIS v3.0.0 control 1.4."""

    id = "CIS-1.4-ROOT-KEYS"
    title = "Root access keys"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Root user has an active access key."
    cis_controls = ("1.4",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        row = root_credential_row(ctx.credential_report())
        if row is None:
            return []
        active = [slot for slot in (1, 2) if credential_flag(row, f"access_key_{slot}_active")]
        if not active:
            return []
        return [
            finding(
                self,
                title="Root account has an active access key",
                severity=Severity.CRITICAL,
                impact="A root access key is a permanent credential with unlimited account access.",
                recommendation=(
                    "Delete the root access keys and use an IAM role for administration."
                ),
                resource_arn=row.get("arn"),
                resource_id="root",
                evidence={"active_key_slots": active},
            )
        ]
