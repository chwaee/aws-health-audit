"""Walk every bucket and keep going when one bucket denies access."""

from collections.abc import Callable

from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.checks.base import CheckResult
from aws_health_audit.context import AuditContext, BucketInfo
from aws_health_audit.models import CheckError, Finding


def each_bucket(
    ctx: AuditContext,
    check_id: str,
    visitor: Callable[[BucketInfo], list[Finding]],
) -> CheckResult:
    """Call visitor for every bucket that is not ignored."""
    try:
        buckets = ctx.bucket_index()
    except AccessDeniedError as exc:
        return CheckResult([], [CheckError(check_id, None, "AccessDenied", str(exc))])
    except ThrottlingError as exc:
        return CheckResult([], [CheckError(check_id, None, "Throttling", str(exc))])
    findings: list[Finding] = []
    errors: list[CheckError] = []
    for bucket in buckets:
        if ctx.is_ignored(check_id, resource_id=bucket.name, arn=bucket.arn, tags=bucket.tags):
            continue
        if bucket.region is None:
            errors.append(
                CheckError(
                    check_id,
                    None,
                    "AccessDenied",
                    f"{bucket.name}: bucket region is not readable",
                )
            )
            continue
        try:
            findings.extend(visitor(bucket))
        except AccessDeniedError as exc:
            errors.append(
                CheckError(check_id, bucket.region, "AccessDenied", f"{bucket.name}: {exc}")
            )
        except ThrottlingError as exc:
            errors.append(
                CheckError(check_id, bucket.region, "Throttling", f"{bucket.name}: {exc}")
            )
        except AwsClientError as exc:
            errors.append(CheckError(check_id, bucket.region, exc.code, f"{bucket.name}: {exc}"))
    return CheckResult(findings, errors)
