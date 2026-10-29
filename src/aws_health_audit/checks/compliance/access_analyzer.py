"""IAM Access Analyzer presence."""

from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, CheckError, Severity


class AccessAnalyzerCheck(Check):
    """At least one active external-access analyzer in the account."""

    id = "CIS-ACCESS-ANALYZER"
    title = "IAM Access Analyzer"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "No active IAM Access Analyzer in the account."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region
        errors: list[CheckError] = []
        readable = 0
        for current in ctx.regions:
            try:
                analyzers = collect(
                    ctx.client("accessanalyzer", current),
                    "list_analyzers",
                    "analyzers",
                )
            except AccessDeniedError as exc:
                errors.append(CheckError(self.id, current, "AccessDenied", str(exc)))
                continue
            except ThrottlingError as exc:
                errors.append(CheckError(self.id, current, "Throttling", str(exc)))
                continue
            except AwsClientError as exc:
                errors.append(CheckError(self.id, current, exc.code, str(exc)))
                continue
            readable += 1
            if any(item.get("status") == "ACTIVE" for item in analyzers):
                return CheckResult([], errors)
        if readable == 0:
            return CheckResult([], errors)
        return CheckResult(
            [
                finding(
                    self,
                    title="IAM Access Analyzer is not active",
                    severity=Severity.LOW,
                    impact=(
                        "External shares of roles and buckets are not flagged by Access Analyzer."
                    ),
                    recommendation="Create an active account analyzer in the home region.",
                    resource_id=ctx.account_id,
                    evidence={"regions_checked": readable},
                )
            ],
            errors,
        )
