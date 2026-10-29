"""Internet egress and cross-region data transfer from Cost Explorer."""

from datetime import timedelta

from aws_health_audit.aws.paginate import call
from aws_health_audit.aws.pricing import format_usd
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import transfer_kind, waste_severity
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, EstimateSource, Finding, Severity


class DataTransferCheck(Check):
    """Last 30 days of unblended transfer cost, grouped by usage type.

    Requires ce:GetCostAndUsage. A denied call is a check error, not a crash.
    Ingress-only usage types are ignored.
    """

    id = "COST-DATA-TRANSFER"
    title = "Data transfer cost"
    category = Category.COST
    scope = Scope.GLOBAL
    description = "Internet egress and cross-region data transfer above the cost threshold."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        end = utcnow().date()
        start = end - timedelta(days=30)
        client = ctx.client("ce", "us-east-1")
        totals: dict[str, float] = {}
        token: str | None = None
        while True:
            kwargs: dict[str, object] = {
                "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
                "Granularity": "MONTHLY",
                "Metrics": ["UnblendedCost"],
                "GroupBy": [{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
            }
            if token:
                kwargs["NextPageToken"] = token
            response = call(client, "get_cost_and_usage", **kwargs) or {}
            for period in response.get("ResultsByTime", []):
                for group in period.get("Groups", []):
                    usage_type = group.get("Keys", ["unknown"])[0]
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    totals[usage_type] = totals.get(usage_type, 0.0) + amount
            token = response.get("NextPageToken")
            if not token:
                break

        minimum = ctx.config.thresholds.data_transfer_min_usd
        findings: list[Finding] = []
        for usage_type, amount in sorted(totals.items()):
            kind = transfer_kind(usage_type)
            if kind is None or amount < minimum:
                continue
            monthly = round(amount, 2)
            findings.append(
                finding(
                    self,
                    title=(
                        f"Data transfer: {usage_type} ({kind.replace('-', ' ')}, "
                        f"{format_usd(monthly)}/mo)"
                    ),
                    severity=waste_severity(monthly, ctx.config.thresholds) or Severity.LOW,
                    impact=(
                        "Cross-region and internet egress charges are a common surprise on thebill."
                    ),
                    recommendation=(
                        f"Trace {usage_type} in Cost Explorer by service and region. "
                        "Keep chatty traffic in one region, and put a CDN or gateway endpoint "
                        "in front of repeated internet egress."
                    ),
                    region="us-east-1",
                    resource_id=usage_type,
                    evidence={
                        "usage_type": usage_type,
                        "kind": kind,
                        "period_start": start.isoformat(),
                        "period_end": end.isoformat(),
                    },
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.COST_EXPLORER,
                )
            )
        return findings
