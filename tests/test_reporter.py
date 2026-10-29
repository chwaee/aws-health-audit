"""Text and JSON report shape."""

import json
from datetime import UTC, datetime

from aws_health_audit.models import (
    AuditReport,
    Category,
    CheckError,
    EstimateSource,
    Finding,
    Severity,
)
from aws_health_audit.reporter.json import render_json
from aws_health_audit.reporter.text import render_text

WHEN = datetime(2026, 3, 22, 18, 4, 11, tzinfo=UTC)


def _finding(**overrides: object) -> Finding:
    payload = {
        "check_id": "SEC-S3-PUBLIC",
        "title": "Public S3 bucket: bucket-name",
        "severity": Severity.CRITICAL,
        "category": Category.SECURITY,
        "impact": "Data exposure risk",
        "recommendation": "Enable block public access",
        "resource_arn": "arn:aws:s3:::bucket-name",
        "region": "us-east-1",
        "resource_id": "bucket-name",
    }
    payload.update(overrides)
    return Finding(**payload)  # type: ignore[arg-type]


def _report() -> AuditReport:
    cost = Finding(
        check_id="COST-EC2-IDLE",
        title="Idle EC2 instance: i-abc (7 days, est. waste: $120/mo)",
        severity=Severity.HIGH,
        category=Category.COST,
        impact="Compute is billed while the instance is idle.",
        recommendation="Stop i-abc.",
        resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
        region="us-east-1",
        resource_id="i-abc",
        estimated_monthly_waste_usd=120.0,
        estimate_source=EstimateSource.RATE_CARD,
    )
    return AuditReport(
        account_id="123456789012",
        generated_at=WHEN,
        regions=["us-east-1"],
        findings=[_finding(), cost],
        errors=[
            CheckError("COST-DATA-TRANSFER", "us-east-1", "AccessDenied", "ce:GetCostAndUsage")
        ],
        tool_version="0.1.0",
        skipped_checks=["CIS-GUARDDUTY"],
    )


def test_text_report_sections_and_reused_numbers():
    text = render_text(_report())
    assert "Account: 123456789012" in text
    assert "Date: 2026-03-22T18:04:11Z" in text
    assert "- Critical: 1" in text
    assert "- High: 1" in text
    assert "CRITICAL FINDINGS" in text
    assert "1. Public S3 bucket: bucket-name" in text
    assert "HIGH FINDINGS" in text
    assert "2. Idle EC2 instance: i-abc" in text
    assert "FINANCIAL FINDINGS" in text
    assert "2. Idle EC2 instance: i-abc" in text.split("FINANCIAL FINDINGS", 1)[1]
    assert "Estimated waste: $120.00/mo" in text
    assert "- Security: 1 findings" in text
    assert "- Cost: 1 findings" in text
    assert "COST-DATA-TRANSFER (us-east-1): AccessDenied ce:GetCostAndUsage" in text
    assert "CIS-GUARDDUTY" in text


def test_json_schema():
    payload = json.loads(render_json(_report()))
    assert payload["schema_version"] == "1.0"
    assert payload["summary"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0}
    assert payload["summary_by_category"]["cost"] == 1
    assert payload["findings"][1]["estimated_monthly_waste_usd"] == 120.0
    assert payload["findings"][1]["estimate_source"] == "rate_card"
    assert payload["check_errors"][0]["code"] == "AccessDenied"
    assert payload["metadata"]["skipped_checks"] == ["CIS-GUARDDUTY"]
