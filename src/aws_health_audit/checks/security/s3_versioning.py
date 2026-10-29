"""S3 versioning, with a higher severity for configured critical buckets."""

from aws_health_audit.aws.paginate import call
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.checks.evaluate import name_matches_globs
from aws_health_audit.checks.s3common import each_bucket
from aws_health_audit.context import AuditContext, BucketInfo
from aws_health_audit.models import Category, Finding, Severity


class S3VersioningCheck(Check):
    """Versioning status is not Enabled.

    Buckets matching critical_buckets globs are HIGH. Others are LOW.
    """

    id = "SEC-S3-VERSIONING"
    title = "S3 versioning"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "S3 buckets that do not have versioning enabled."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region

        def visit(bucket: BucketInfo) -> list[Finding]:
            assert bucket.region is not None
            response = call(
                ctx.client("s3", bucket.region), "get_bucket_versioning", Bucket=bucket.name
            )
            if (response or {}).get("Status") == "Enabled":
                return []
            critical = name_matches_globs(bucket.name, ctx.config.critical_buckets)
            return [
                finding(
                    self,
                    title=f"S3 versioning is off: {bucket.name}",
                    severity=Severity.HIGH if critical else Severity.LOW,
                    impact=(
                        "A deleted or overwritten object cannot be restored from version history."
                    ),
                    recommendation=(
                        f"Enable versioning on {bucket.name}"
                        + (" because it matches the critical bucket list." if critical else ".")
                        + " Add a lifecycle rule so old versions do not grow forever."
                    ),
                    region=bucket.region,
                    resource_arn=bucket.arn,
                    resource_id=bucket.name,
                    evidence={
                        "critical_bucket": critical,
                        "status": (response or {}).get("Status"),
                    },
                )
            ]

        return each_bucket(ctx, self.id, visit)
