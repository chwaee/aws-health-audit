"""Human-readable audit report."""

from aws_health_audit.clock import utc_iso
from aws_health_audit.models import (
    CATEGORY_LABELS,
    SEVERITY_RANK,
    AuditReport,
    Category,
    Finding,
    Severity,
)

_HEADINGS: tuple[tuple[Severity, str], ...] = (
    (Severity.CRITICAL, "CRITICAL FINDINGS"),
    (Severity.HIGH, "HIGH FINDINGS"),
    (Severity.MEDIUM, "MEDIUM FINDINGS"),
    (Severity.LOW, "LOW FINDINGS"),
    (Severity.INFO, "INFO FINDINGS"),
)

_SUMMARY_ORDER = ("critical", "high", "medium", "low", "info")


def render_text(report: AuditReport) -> str:
    """Render the report used on a terminal and in a text output file."""
    lines: list[str] = [
        "AWS Health Audit Report",
        f"Account: {report.account_id}",
        f"Date: {utc_iso(report.generated_at)}",
        f"Regions: {', '.join(report.regions) if report.regions else '(none)'}",
        f"Tool: aws-health-audit {report.tool_version}",
        "",
        "SUMMARY",
    ]
    counts = report.summary()
    for name in _SUMMARY_ORDER:
        lines.append(f"- {name.capitalize()}: {counts[name]}")
    lines.append("")

    numbered = list(enumerate(report.findings, start=1))
    numbers = {id(item): number for number, item in numbered}
    for severity, heading in _HEADINGS:
        group = [(number, item) for number, item in numbered if item.severity is severity]
        if not group:
            continue
        lines.append(heading)
        for number, item in group:
            lines.extend(_finding_lines(number, item))
        lines.append("")

    cost = [item for item in report.findings if item.category is Category.COST]
    if cost:
        lines.append("FINANCIAL FINDINGS")
        ordered = sorted(
            cost,
            key=lambda item: (
                item.estimated_monthly_waste_usd is None,
                -(item.estimated_monthly_waste_usd or 0),
                item.title,
            ),
        )
        for item in ordered:
            lines.extend(_finding_lines(numbers[id(item)], item, show_waste=True))
        lines.append("")

    lines.append("RECOMMENDATIONS BY CATEGORY")
    by_category = report.summary_by_category()
    for category in (Category.SECURITY, Category.COST, Category.COMPLIANCE):
        label = CATEGORY_LABELS[category]
        lines.append(f"- {label}: {by_category[category.value]} findings")

    if report.errors:
        lines.append("")
        lines.append("CHECKS NOT COMPLETED")
        for error in sorted(report.errors, key=lambda item: (item.check_id, item.region or "")):
            where = f" ({error.region})" if error.region else ""
            lines.append(f"- {error.check_id}{where}: {error.code} {error.message}")

    if report.skipped_checks:
        lines.append("")
        lines.append("SKIPPED CHECKS")
        for check_id in report.skipped_checks:
            lines.append(f"- {check_id}")

    lines.append("")
    return "\n".join(lines)


def _finding_lines(number: int, item: Finding, *, show_waste: bool = False) -> list[str]:
    lines = [f"{number}. {item.title}"]
    if show_waste and item.estimated_monthly_waste_usd is not None:
        lines.append(f"   Estimated waste: ${item.estimated_monthly_waste_usd:.2f}/mo")
    lines.append(f"   Impact: {item.impact}")
    lines.append(f"   Recommendation: {item.recommendation}")
    if item.resource_arn:
        lines.append(f"   Resource: {item.resource_arn}")
    if item.region:
        lines.append(f"   Region: {item.region}")
    cis = ", ".join(item.cis_controls)
    if cis:
        lines.append(f"   CIS: {cis}")
    lines.append(f"   Check: {item.check_id}")
    return lines


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Severity, then category, then check id, then resource."""
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK[item.severity],
            item.category.value,
            item.check_id,
            item.resource_arn or "",
            item.region or "",
            item.title,
        ),
    )
