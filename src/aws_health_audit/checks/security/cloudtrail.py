"""Multi-region CloudTrail coverage for management events."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import trail_requirement_gaps
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class CloudTrailCheck(Check):
    """Require one multi-region trail that is logging read and write management events.

    CIS AWS Foundations Benchmark v3.0.0 control 3.1.
    """

    id = "SEC-CLOUDTRAIL"
    title = "CloudTrail management events"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "No multi-region CloudTrail trail logging read and write management events."
    cis_controls = ("3.1",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        rows = ctx.trails()
        described = []
        compliant = False
        any_logging = False
        for row in rows:
            gaps = trail_requirement_gaps(row["trail"], row["status"], row["selectors"])
            if row["status"].get("IsLogging"):
                any_logging = True
            if not gaps:
                compliant = True
            described.append(
                {
                    "name": row["trail"].get("Name"),
                    "home_region": row["trail"].get("HomeRegion"),
                    "gaps": gaps,
                }
            )
        if compliant:
            return []
        if not rows or not any_logging:
            severity = Severity.CRITICAL
            title = "CloudTrail is not recording management events"
        else:
            severity = Severity.HIGH
            title = "CloudTrail does not meet the multi-region logging bar"
        return [
            finding(
                self,
                title=title,
                severity=severity,
                impact=(
                    "Without a complete trail, changes to the account can happen with no retained "
                    "record."
                ),
                recommendation=(
                    "Create or fix one multi-region trail that includes global service events, "
                    "logs read and write management events, and has logging turned on."
                ),
                resource_id="cloudtrail",
                evidence={"trails": described},
            )
        ]
