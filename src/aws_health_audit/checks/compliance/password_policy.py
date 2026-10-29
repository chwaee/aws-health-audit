"""IAM password length and reuse. Two checks share one policy read."""

from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import password_length_ok, password_reuse_ok
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class PasswordLengthCheck(Check):
    """Minimum password length is under 14, or no password policy exists.

    CIS v3.0.0 control 1.8.
    """

    id = "CIS-1.8-PASSWORD-LENGTH"
    title = "IAM password length"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "IAM password policy does not require 14 characters."
    cis_controls = ("1.8",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        policy = ctx.password_policy()
        if password_length_ok(policy):
            return []
        length = None if policy is None else policy.get("MinimumPasswordLength")
        return [
            finding(
                self,
                title="IAM password policy does not require 14 characters",
                severity=Severity.HIGH,
                impact="Short console passwords are easier to guess on every IAM user.",
                recommendation="Set the account password policy minimum length to at least 14.",
                resource_id="password-policy",
                evidence={"minimum_length": length, "policy_present": policy is not None},
            )
        ]


class PasswordReuseCheck(Check):
    """Password reuse prevention is under 24. CIS v3.0.0 control 1.9."""

    id = "CIS-1.9-PASSWORD-REUSE"
    title = "IAM password reuse"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "IAM password policy does not remember 24 passwords."
    cis_controls = ("1.9",)

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        del region
        policy = ctx.password_policy()
        if password_reuse_ok(policy):
            return []
        reuse = None if policy is None else policy.get("PasswordReusePrevention")
        return [
            finding(
                self,
                title="IAM password policy allows password reuse",
                severity=Severity.MEDIUM,
                impact="Users can rotate back to a password that was already exposed.",
                recommendation="Set password reuse prevention to at least 24 remembered passwords.",
                resource_id="password-policy",
                evidence={"reuse_prevention": reuse, "policy_present": policy is not None},
            )
        ]
