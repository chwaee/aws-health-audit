"""S3 TLS, bucket Block Public Access, and account Block Public Access."""

import json

from aws_health_audit.aws.paginate import call
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.checks.evaluate import bpa_fully_enabled, policy_denies_insecure_transport
from aws_health_audit.checks.s3common import each_bucket
from aws_health_audit.context import AuditContext, BucketInfo
from aws_health_audit.models import Category, Finding, Severity

_NO_POLICY = ("NoSuchBucketPolicy",)
_NO_BPA = ("NoSuchPublicAccessBlockConfiguration",)


class S3TlsCheck(Check):
    """Bucket policy does not deny aws:SecureTransport false. CIS v3.0.0 control 2.1.1."""

    id = "CIS-2.1.1-S3-TLS"
    title = "S3 TLS-only access"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "S3 buckets that do not deny non-TLS requests."
    cis_controls = ("2.1.1",)

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region

        def visit(bucket: BucketInfo) -> list[Finding]:
            assert bucket.region is not None
            raw = call(
                ctx.client("s3", bucket.region),
                "get_bucket_policy",
                Bucket=bucket.name,
                missing_ok=_NO_POLICY,
            )
            policy = _policy_document(raw)
            if policy_denies_insecure_transport(policy):
                return []
            return [
                finding(
                    self,
                    title=f"S3 bucket allows non-TLS requests: {bucket.name}",
                    severity=Severity.MEDIUM,
                    impact=(
                        "Clients can send objects and credentials to this bucket over plain HTTP."
                    ),
                    recommendation=(
                        f"Add a Deny statement on {bucket.name} for aws:SecureTransport false."
                    ),
                    region=bucket.region,
                    resource_arn=bucket.arn,
                    resource_id=bucket.name,
                )
            ]

        return each_bucket(ctx, self.id, visit)


class S3BucketBpaCheck(Check):
    """Any of the four bucket BPA flags is off. CIS v3.0.0 control 2.1.4.

    Stays MEDIUM even when the bucket is also publicly reachable. The public
    finding is SEC-S3-PUBLIC.
    """

    id = "CIS-2.1.4-S3-BPA"
    title = "S3 bucket Block Public Access"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "S3 buckets missing one or more Block Public Access settings."
    cis_controls = ("2.1.4",)

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region

        def visit(bucket: BucketInfo) -> list[Finding]:
            assert bucket.region is not None
            response = call(
                ctx.client("s3", bucket.region),
                "get_public_access_block",
                Bucket=bucket.name,
                missing_ok=_NO_BPA,
            )
            config = None if response is None else response.get("PublicAccessBlockConfiguration")
            if bpa_fully_enabled(config):
                return []
            return [
                finding(
                    self,
                    title=f"S3 Block Public Access is incomplete: {bucket.name}",
                    severity=Severity.MEDIUM,
                    impact="A later ACL or bucket policy change can make this bucket public.",
                    recommendation=(
                        f"Enable all four Block Public Access settings on {bucket.name} "
                        "and at the account."
                    ),
                    region=bucket.region,
                    resource_arn=bucket.arn,
                    resource_id=bucket.name,
                    evidence={"configuration": config},
                )
            ]

        return each_bucket(ctx, self.id, visit)


class S3AccountBpaCheck(Check):
    """Account-level S3 Block Public Access is not fully on."""

    id = "CIS-S3-ACCOUNT-BPA"
    title = "Account S3 Block Public Access"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Account-level S3 Block Public Access is not fully enabled."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        config = ctx.account_public_access_block()
        if bpa_fully_enabled(config):
            return []
        return [
            finding(
                self,
                title="Account-level S3 Block Public Access is not fully enabled",
                severity=Severity.HIGH,
                impact="Every bucket depends on its own settings to stay private.",
                recommendation=(
                    "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                    "and RestrictPublicBuckets on the account."
                ),
                resource_id=ctx.account_id,
                evidence={"configuration": config},
            )
        ]


def _policy_document(raw: dict | None) -> dict | None:
    if not raw or "Policy" not in raw:
        return None
    body = raw["Policy"]
    if isinstance(body, dict):
        return body
    if isinstance(body, str):
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else None
    return None
