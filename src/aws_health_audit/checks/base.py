"""Check interface and the finding constructor."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from aws_health_audit.aws.pricing import money
from aws_health_audit.context import AuditContext
from aws_health_audit.models import (
    Category,
    CheckError,
    EstimateSource,
    Finding,
    Severity,
)


class Scope(StrEnum):
    """Where a check runs."""

    GLOBAL = "global"
    REGIONAL = "regional"


@dataclass
class CheckResult:
    """Findings plus per-resource errors a check handled itself."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[CheckError] = field(default_factory=list)


class Check(ABC):
    """One audit check. Subclasses set the class attributes and implement run."""

    id: str
    title: str
    category: Category
    scope: Scope
    description: str
    cis_controls: tuple[str, ...] = ()

    @abstractmethod
    def run(self, ctx: AuditContext, region: str | None) -> list[Finding] | CheckResult:
        """Return findings for one region, or for the whole account when global."""


def finding(
    check: Check,
    *,
    title: str,
    severity: Severity,
    impact: str,
    recommendation: str,
    region: str | None = None,
    resource_arn: str | None = None,
    resource_id: str | None = None,
    evidence: dict[str, Any] | None = None,
    estimated_monthly_waste_usd: float | None = None,
    estimate_source: EstimateSource = EstimateSource.NONE,
) -> Finding:
    """Build a finding that inherits category and CIS ids from its check."""
    return Finding(
        check_id=check.id,
        title=title,
        severity=severity,
        category=check.category,
        impact=impact,
        recommendation=recommendation,
        resource_arn=resource_arn,
        region=region,
        evidence=evidence or {},
        estimated_monthly_waste_usd=money(estimated_monthly_waste_usd),
        estimate_source=estimate_source,
        cis_controls=check.cis_controls,
        resource_id=resource_id,
    )
