"""S3 buckets that are effectively public."""

from aws_health_audit.aws.errors import AccessDeniedError
from aws_health_audit.aws.paginate import call
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.checks.evaluate import acl_grants_are_public, effective_s3_public
from aws_health_audit.checks.s3common import each_bucket
from aws_health_audit.context import AuditContext, BucketInfo
from aws_health_audit.models import Category, Finding, Severity

_MISSING = ("NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration")


class PublicS3Check(Check):
    """Effective public access, after bucket and account Block Public Access.

    GetBucketPolicyStatus reports the policy. The ACL is checked separately.
    A public policy that BPA already blocks is not a critical finding.
    """

    id = "SEC-S3-PUBLIC"
    title = "Public S3 buckets"
    category = Category.SECURITY
    scope = Scope.GLOBAL
    description = "Buckets whose ACL or policy allows public access despite Block Public Access."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region
        try:
            account_bpa = ctx.account_public_access_block()
        except AccessDeniedError:
            account_bpa = None

        def visit(bucket: BucketInfo) -> list[Finding]:
            return _visit(self, ctx, bucket, account_bpa)

        return each_bucket(ctx, self.id, visit)


def _visit(
    check: PublicS3Check,
    ctx: AuditContext,
    bucket: BucketInfo,
    account_bpa: dict | None,
) -> list[Finding]:
    assert bucket.region is not None
    s3 = ctx.client("s3", bucket.region)
    status = call(s3, "get_bucket_policy_status", Bucket=bucket.name, missing_ok=_MISSING)
    policy_public = bool((status or {}).get("PolicyStatus", {}).get("IsPublic"))
    acl = call(s3, "get_bucket_acl", Bucket=bucket.name) or {}
    acl_public = acl_grants_are_public(acl.get("Grants"))
    block = call(s3, "get_public_access_block", Bucket=bucket.name, missing_ok=_MISSING)
    bucket_bpa = None if block is None else block.get("PublicAccessBlockConfiguration")
    if not effective_s3_public(
        policy_public=policy_public,
        acl_public=acl_public,
        bucket_bpa=bucket_bpa,
        account_bpa=account_bpa,
    ):
        return []
    return [
        finding(
            check,
            title=f"Public S3 bucket: {bucket.name}",
            severity=Severity.CRITICAL,
            impact="Objects in this bucket can be read or listed from the public internet.",
            recommendation=(
                f"Turn on all four Block Public Access settings for {bucket.name}, "
                "then remove AllUsers and AuthenticatedUsers from the ACL and review the bucket "
                "policy."
            ),
            region=bucket.region,
            resource_arn=bucket.arn,
            resource_id=bucket.name,
            evidence={
                "policy_public": policy_public,
                "acl_public": acl_public,
                "account_block_public_access_known": account_bpa is not None,
            },
        )
    ]
