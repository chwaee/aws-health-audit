"""Hardware MFA for the root user."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import credential_flag, root_credential_row
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class RootHardwareMfaCheck(Check):
    """Virtual MFA on root is LOW. CIS v3.0.0 control 1.6 prefers hardware.

    No finding when root MFA is off, because SEC-IAM-ROOT-MFA already covers that.
    No finding when MFA is on and no virtual device is assigned to root.
    """

    id = "CIS-1.6-ROOT-HW-MFA"
    title = "Root hardware MFA"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Root MFA is a virtual device instead of a hardware key."
    cis_controls = ("1.6",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        row = root_credential_row(ctx.credential_report())
        if row is None or not credential_flag(row, "mfa_active"):
            return []
        virtual = False
        for device in ctx.virtual_mfa_devices():
            user = (device.get("User") or {}).get("Arn", "")
            if user.endswith(":root"):
                virtual = True
                break
        if not virtual:
            return []
        return [
            finding(
                self,
                title="Root MFA is a virtual device",
                severity=Severity.LOW,
                impact="A virtual MFA device can be copied with the phone or seed that holds it.",
                recommendation=(
                    "Register a hardware MFA device for the root user "
                    "and remove the virtual device."
                ),
                resource_arn=row.get("arn"),
                resource_id="root",
                evidence={"virtual_mfa": True},
            )
        ]
