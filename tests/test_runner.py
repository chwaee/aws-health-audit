"""The runner keeps partial results and honors skip tokens."""

import pytest

from aws_health_audit.aws.errors import AccessDeniedError, ConfigError
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.config import AppConfig
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Severity
from aws_health_audit.runner import failure_exit_code, run_audit, select_checks


class _Boom(Check):
    id = "SEC-BOOM"
    title = "boom"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "raises"

    def run(self, ctx: AuditContext, region: str | None) -> list:
        raise AccessDeniedError("ce:GetCostAndUsage")


class _Ok(Check):
    id = "SEC-OK"
    title = "ok"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "returns"

    def run(self, ctx: AuditContext, region: str | None) -> list:
        return [
            finding(
                self,
                title="open group",
                severity=Severity.HIGH,
                impact="impact",
                recommendation="fix it",
                region=region,
                resource_id="sg-1",
            )
        ]


def test_access_denied_does_not_drop_other_findings():
    ctx = AuditContext(
        session=None,  # type: ignore[arg-type]
        account_id="123456789012",
        regions=["us-east-1"],
        config=AppConfig(),
        clients=object(),  # type: ignore[arg-type]
    )
    report = run_audit(
        ctx,
        [_Boom(), _Ok()],
        skipped=[],
        max_workers=2,
        progress=lambda _message: None,
    )
    assert [item.check_id for item in report.findings] == ["SEC-OK"]
    assert report.errors[0].check_id == "SEC-BOOM"
    assert report.errors[0].code == "AccessDenied"
    assert "ce:GetCostAndUsage" in report.errors[0].message


def test_financial_alias_skips_cost_checks():
    selected, skipped = select_checks(["financial"])
    assert skipped
    assert all(check.category is not Category.COST for check in selected)
    assert "COST-EC2-IDLE" in skipped
    assert any(check.id == "SEC-S3-PUBLIC" for check in selected)


def test_unknown_check_is_a_config_error():
    with pytest.raises(ConfigError, match="Unknown check"):
        select_checks(["not-a-check"])


def test_fail_on_threshold():
    from aws_health_audit.models import Finding

    item = Finding(
        check_id="SEC-OK",
        title="open group",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        impact="impact",
        recommendation="fix",
    )
    assert failure_exit_code([item], "never") == 0
    assert failure_exit_code([item], "critical") == 0
    assert failure_exit_code([item], "high") == 1
    assert failure_exit_code([item], "low") == 1
