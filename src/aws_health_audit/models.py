"""Report records shared by checks, the runner, and the renderers."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Finding severity. Lower rank is worse."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Category(StrEnum):
    """Audit area a check belongs to."""

    SECURITY = "security"
    COST = "cost"
    COMPLIANCE = "compliance"


CATEGORY_ORDER: dict[Category, int] = {
    Category.SECURITY: 0,
    Category.COST: 1,
    Category.COMPLIANCE: 2,
}

CATEGORY_LABELS: dict[Category, str] = {
    Category.SECURITY: "Security",
    Category.COST: "Cost",
    Category.COMPLIANCE: "Compliance",
}


class EstimateSource(StrEnum):
    """Where a dollar figure came from."""

    RATE_CARD = "rate_card"
    COST_EXPLORER = "cost_explorer"
    NONE = "none"


def more_severe(left: Severity, right: Severity) -> Severity:
    """Return the worse of two severities."""
    if SEVERITY_RANK[left] <= SEVERITY_RANK[right]:
        return left
    return right


@dataclass(frozen=True)
class Finding:
    """One actionable audit result."""

    check_id: str
    title: str
    severity: Severity
    category: Category
    impact: str
    recommendation: str
    resource_arn: str | None = None
    region: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    estimated_monthly_waste_usd: float | None = None
    estimate_source: EstimateSource = EstimateSource.NONE
    cis_controls: tuple[str, ...] = ()
    resource_id: str | None = None

    @property
    def id(self) -> str:
        """Stable identity for dedupe and JSON consumers."""
        region = self.region or "global"
        resource = self.resource_id or self.resource_arn or "account"
        return f"{self.check_id}:{region}:{resource}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding for the JSON report."""
        return {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "cis_controls": list(self.cis_controls),
            "region": self.region,
            "resource_arn": self.resource_arn,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "estimated_monthly_waste_usd": self.estimated_monthly_waste_usd,
            "estimate_source": self.estimate_source.value,
        }


@dataclass(frozen=True)
class CheckError:
    """A check that could not finish in one region."""

    check_id: str
    region: str | None
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "region": self.region,
            "code": self.code,
            "message": self.message,
        }


@dataclass
class AuditReport:
    """Full result of one audit run."""

    account_id: str
    generated_at: datetime
    regions: list[str]
    findings: list[Finding]
    errors: list[CheckError]
    tool_version: str
    profile: str | None = None
    role_arn: str | None = None
    skipped_checks: list[str] = field(default_factory=list)
    ignored_resources: int = 0

    def summary(self) -> dict[str, int]:
        """Count findings by severity. Keys are lowercase."""
        counts = {severity.value.lower(): 0 for severity in Severity}
        for item in self.findings:
            counts[item.severity.value.lower()] += 1
        return counts

    def summary_by_category(self) -> dict[str, int]:
        """Count findings by category."""
        counts = {category.value: 0 for category in Category}
        for item in self.findings:
            counts[item.category.value] += 1
        return counts
