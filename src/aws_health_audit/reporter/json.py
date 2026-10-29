"""Stable JSON report for CI and downstream tools."""

import json
from typing import Any

from aws_health_audit import __version__
from aws_health_audit.clock import utc_iso
from aws_health_audit.models import AuditReport


def render_json(report: AuditReport) -> str:
    """Serialize the report. schema_version 1.0 is the supported contract."""
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "tool_version": report.tool_version or __version__,
        "account_id": report.account_id,
        "generated_at": utc_iso(report.generated_at),
        "regions": report.regions,
        "summary": report.summary(),
        "summary_by_category": report.summary_by_category(),
        "findings": [item.to_dict() for item in report.findings],
        "check_errors": [item.to_dict() for item in report.errors],
        "metadata": {
            "profile": report.profile,
            "role_arn": report.role_arn,
            "skipped_checks": report.skipped_checks,
            "ignored_resources": report.ignored_resources,
        },
    }
    return json.dumps(payload, indent=2) + "\n"
