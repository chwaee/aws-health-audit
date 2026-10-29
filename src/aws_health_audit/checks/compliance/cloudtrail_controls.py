"""CloudTrail log validation, KMS encryption, and log-bucket access logging."""

from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.aws.paginate import call
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, CheckError, Finding, Severity


def _logging_multi_region(rows: list[dict]) -> list[dict]:
    selected = []
    for row in rows:
        trail = row["trail"]
        if trail.get("IsMultiRegionTrail") and row["status"].get("IsLogging"):
            selected.append(row)
    return selected


class CloudTrailValidationCheck(Check):
    """Logging multi-region trails without log file validation. CIS v3.0.0 control 3.2."""

    id = "CIS-3.2-CT-VALIDATION"
    title = "CloudTrail log file validation"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Multi-region trails that are logging without log file validation."
    cis_controls = ("3.2",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        findings: list[Finding] = []
        for row in _logging_multi_region(ctx.trails()):
            trail = row["trail"]
            if trail.get("LogFileValidationEnabled"):
                continue
            name = trail.get("Name", "trail")
            findings.append(
                finding(
                    self,
                    title=f"CloudTrail log file validation is off: {name}",
                    severity=Severity.MEDIUM,
                    impact="A changed or deleted log file would not be detectable from the digest.",
                    recommendation=f"Enable log file validation on {name}.",
                    resource_arn=trail.get("TrailARN"),
                    resource_id=name,
                    region=trail.get("HomeRegion"),
                )
            )
        return findings


class CloudTrailKmsCheck(Check):
    """Logging multi-region trails without a KMS key. CIS v3.0.0 control 3.5."""

    id = "CIS-3.5-CT-KMS"
    title = "CloudTrail KMS encryption"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Multi-region trails that are logging without a KMS key."
    cis_controls = ("3.5",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        findings: list[Finding] = []
        for row in _logging_multi_region(ctx.trails()):
            trail = row["trail"]
            if trail.get("KmsKeyId"):
                continue
            name = trail.get("Name", "trail")
            findings.append(
                finding(
                    self,
                    title=f"CloudTrail logs are not KMS-encrypted: {name}",
                    severity=Severity.MEDIUM,
                    impact=(
                        "Anyone who can read the log bucket can read the trail with only SSE-S3."
                    ),
                    recommendation=(
                        f"Set a customer managed KMS key on {name} and grant the trail permission"
                        f"to use it."
                    ),
                    resource_arn=trail.get("TrailARN"),
                    resource_id=name,
                    region=trail.get("HomeRegion"),
                )
            )
        return findings


class CloudTrailBucketLoggingCheck(Check):
    """CloudTrail log buckets without S3 server access logging. CIS v3.0.0 control 3.4."""

    id = "CIS-3.4-CT-BUCKET-LOGGING"
    title = "CloudTrail bucket access logging"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "CloudTrail log buckets that do not have S3 server access logging."
    cis_controls = ("3.4",)

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region
        locations = {bucket.name: bucket for bucket in ctx.bucket_index()}
        findings: list[Finding] = []
        errors: list[CheckError] = []
        seen: set[str] = set()
        for row in _logging_multi_region(ctx.trails()):
            bucket_name = row["trail"].get("S3BucketName")
            if not bucket_name or bucket_name in seen:
                continue
            seen.add(bucket_name)
            info = locations.get(bucket_name)
            bucket_region = info.region if info and info.region else "us-east-1"
            try:
                logging = call(
                    ctx.client("s3", bucket_region),
                    "get_bucket_logging",
                    Bucket=bucket_name,
                )
            except AccessDeniedError as exc:
                errors.append(
                    CheckError(self.id, bucket_region, "AccessDenied", f"{bucket_name}: {exc}")
                )
                continue
            except ThrottlingError as exc:
                errors.append(
                    CheckError(self.id, bucket_region, "Throttling", f"{bucket_name}: {exc}")
                )
                continue
            except AwsClientError as exc:
                errors.append(CheckError(self.id, bucket_region, exc.code, f"{bucket_name}: {exc}"))
                continue
            if (logging or {}).get("LoggingEnabled"):
                continue
            findings.append(
                finding(
                    self,
                    title=f"CloudTrail log bucket has no access logging: {bucket_name}",
                    severity=Severity.LOW,
                    impact="Reads of the trail itself are not recorded in a separate bucket.",
                    recommendation=(
                        f"Enable S3 server access logging on{bucket_name} to a different bucket."
                    ),
                    region=bucket_region,
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    resource_id=bucket_name,
                )
            )
        return CheckResult(findings, errors)
