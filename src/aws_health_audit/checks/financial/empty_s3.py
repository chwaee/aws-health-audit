"""Empty buckets and abandoned multipart uploads."""

from datetime import timedelta
from typing import Any

from aws_health_audit.aws.metrics import get_metric_data
from aws_health_audit.aws.paginate import call, paginate
from aws_health_audit.aws.pricing import format_usd, s3_storage_monthly_usd
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.checks.evaluate import waste_severity
from aws_health_audit.checks.s3common import each_bucket
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext, BucketInfo
from aws_health_audit.models import Category, EstimateSource, Finding, Severity, more_severe

_MULTIPART_CAP = 200


class EmptyS3Check(Check):
    """Near-empty buckets, plus incomplete multipart uploads on any bucket.

    Storage bytes come from the daily BucketSizeBytes metric. A bucket with no
    metric is confirmed with a single ListObjectsV2 call. Multipart waste is
    capped at the first 200 uploads per bucket.
    """

    id = "COST-S3-EMPTY"
    title = "Empty S3 buckets and multipart uploads"
    category = Category.COST
    scope = Scope.GLOBAL
    description = "Empty or near-empty buckets, and incomplete multipart uploads."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region

        def visit(bucket: BucketInfo) -> list[Finding]:
            return _inspect(self, ctx, bucket)

        return each_bucket(ctx, self.id, visit)


def _inspect(check: EmptyS3Check, ctx: AuditContext, bucket: BucketInfo) -> list[Finding]:
    assert bucket.region is not None
    s3 = ctx.client("s3", bucket.region)
    size = _bucket_size_bytes(ctx, bucket)
    multipart_bytes, capped = _multipart_bytes(s3, bucket.name)
    if size is None:
        listed = call(s3, "list_objects_v2", Bucket=bucket.name, MaxKeys=1) or {}
        size = 0 if not listed.get("KeyCount") else ctx.config.thresholds.s3_near_empty_bytes + 1
    findings: list[Finding] = []
    if multipart_bytes > 0:
        monthly = s3_storage_monthly_usd(multipart_bytes)
        severity = more_severe(
            waste_severity(monthly, ctx.config.thresholds) or Severity.LOW,
            Severity.LOW,
        )
        findings.append(
            finding(
                check,
                title=(
                    f"Incomplete S3 multipart uploads: {bucket.name} "
                    f"(est. waste: {format_usd(monthly)}/mo)"
                ),
                severity=severity,
                impact=(
                    "Abandoned multipart uploads are billed as stored data until they are aborted."
                ),
                recommendation=(
                    f"Abort incomplete multipart uploads in {bucket.name}, and add a lifecycle "
                    "rule so they do not accumulate again."
                ),
                region=bucket.region,
                resource_arn=bucket.arn,
                resource_id=f"{bucket.name}:multipart",
                evidence={
                    "multipart_bytes": multipart_bytes,
                    "enumeration_capped": capped,
                    "estimate_confidence": "high",
                },
                estimated_monthly_waste_usd=monthly,
                estimate_source=EstimateSource.RATE_CARD,
            )
        )
    if size <= ctx.config.thresholds.s3_near_empty_bytes and multipart_bytes == 0:
        label = "Empty" if size == 0 else "Near-empty"
        storage = s3_storage_monthly_usd(size)
        findings.append(
            finding(
                check,
                title=f"{label} S3 bucket: {bucket.name}",
                severity=Severity.LOW,
                impact=(
                    "The bucket is not holding meaningful data. Storage cost is about "
                    f"{format_usd(storage)}/mo. It still adds clutter and can collect uploads "
                    "later."
                ),
                recommendation=(
                    f"Delete {bucket.name} if no application still expects it to exist."
                ),
                region=bucket.region,
                resource_arn=bucket.arn,
                resource_id=bucket.name,
                evidence={"size_bytes": size, "estimate_confidence": "high"},
                estimated_monthly_waste_usd=storage if storage > 0 else None,
                estimate_source=EstimateSource.RATE_CARD if storage > 0 else EstimateSource.NONE,
            )
        )
    return findings


def _bucket_size_bytes(ctx: AuditContext, bucket: BucketInfo) -> int | None:
    assert bucket.region is not None
    safe_name = bucket.name.replace("\\", "").replace('"', "")
    expression = (
        "SEARCH('{AWS/S3,BucketName,StorageType} "
        f'MetricName="BucketSizeBytes" BucketName="{safe_name}"\', \'Average\', 86400)'
    )
    end = utcnow()
    start = end - timedelta(days=3)
    results = get_metric_data(
        ctx.client("cloudwatch", bucket.region),
        [{"Id": "size", "Expression": expression, "ReturnData": True}],
        start,
        end,
    )
    total = 0
    seen = False
    for series in results.values():
        values = series.get("Values") or []
        if not values:
            continue
        seen = True
        total += int(float(values[0]))
    if not seen:
        return None
    return total


def _multipart_bytes(s3: Any, bucket: str) -> tuple[int, bool]:
    total = 0
    seen = 0
    capped = False
    for page in paginate(s3, "list_multipart_uploads", Bucket=bucket):
        for upload in page.get("Uploads") or []:
            seen += 1
            if seen > _MULTIPART_CAP:
                capped = True
                return total, capped
            for part_page in paginate(
                s3,
                "list_parts",
                Bucket=bucket,
                Key=upload["Key"],
                UploadId=upload["UploadId"],
            ):
                for part in part_page.get("Parts") or []:
                    total += int(part.get("Size") or 0)
    return total, capped
