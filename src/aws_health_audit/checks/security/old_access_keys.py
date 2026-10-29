"""IAM access keys that have not been rotated."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import age_days, credential_flag, parse_credential_time
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class OldAccessKeyCheck(Check):
    """Active keys older than the configured age. Over 180 days is HIGH.

    CIS AWS Foundations Benchmark v3.0.0 control 1.14.
    """

    id = "SEC-IAM-OLD-KEYS"
    title = "Old IAM access keys"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "Active IAM access keys older than the rotation threshold."
    cis_controls = ("1.14",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        now = utcnow()
        thresholds = ctx.config.thresholds
        findings: list[Finding] = []
        for row in ctx.credential_report():
            if row.get("user") == "<root_account>":
                continue
            user = row.get("user", "unknown")
            arn = row.get("arn")
            if ctx.is_ignored(self.id, resource_id=user, arn=arn):
                continue
            for slot in (1, 2):
                if not credential_flag(row, f"access_key_{slot}_active"):
                    continue
                rotated = parse_credential_time(row.get(f"access_key_{slot}_last_rotated"))
                days = age_days(rotated, now)
                if days is not None and days <= thresholds.access_key_max_age_days:
                    continue
                unknown = days is None
                age = days if days is not None else thresholds.access_key_high_age_days
                severity = (
                    Severity.HIGH
                    if unknown or age > thresholds.access_key_high_age_days
                    else Severity.MEDIUM
                )
                findings.append(
                    finding(
                        self,
                        title=f"IAM user {user} access key {slot} is {age} days old",
                        severity=severity,
                        impact=(
                            "A long-lived access key is a standing credential "
                            "an attacker can reuse."
                        ),
                        recommendation=(
                            f"Create a new key for {user}, update the workload, then disable "
                            f"and delete key {slot}."
                        ),
                        resource_arn=arn,
                        resource_id=f"{user}:key{slot}",
                        evidence={"age_days": days, "key_slot": slot, "rotation_unknown": unknown},
                    )
                )
        return findings
