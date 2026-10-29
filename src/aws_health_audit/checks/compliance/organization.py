"""Organization and Control Tower posture for this account only."""

from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.aws.paginate import call, collect
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, CheckError, Finding, Severity

_NOT_IN_ORG = ("AWSOrganizationsNotInUseException",)


class OrganizationCheck(Check):
    """Guardrails visible from this account. Member accounts are not enumerated.

    Access denied on DescribeOrganization is INFO, because a standalone account
    is a supported setup. A missing organization trail is HIGH when the account
    is in an organization.
    """

    id = "GRD-ORG"
    title = "Organization guardrails"
    category = Category.COMPLIANCE
    scope = Scope.GLOBAL
    description = "Organization, SCP, organization trail, and Control Tower posture."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult | list[Finding]:
        del region
        client = ctx.client("organizations", "us-east-1")
        try:
            response = call(client, "describe_organization", missing_ok=_NOT_IN_ORG)
        except AccessDeniedError:
            return [
                finding(
                    self,
                    title="Organization guardrails were not evaluated",
                    severity=Severity.INFO,
                    impact=(
                        "This audit cannot tell whether the account sits under Control Tower or "
                        "SCPs."
                    ),
                    recommendation=(
                        "Grant organizations:DescribeOrganization if this account should be "
                        "assessed as part of an organization. Standalone accounts can ignore this."
                    ),
                    resource_id=ctx.account_id,
                )
            ]
        if response is None:
            return [
                finding(
                    self,
                    title="Account is not part of an AWS Organization",
                    severity=Severity.INFO,
                    impact="Control Tower guardrails and organization trails do not apply here.",
                    recommendation="No organization action is required for a standalone account.",
                    resource_id=ctx.account_id,
                )
            ]

        org = response["Organization"]
        org_id = org.get("Id", "unknown")
        master = org.get("MasterAccountId", "")
        feature = org.get("FeatureSet", "")
        is_management = master == ctx.account_id
        findings = [
            finding(
                self,
                title=f"Account is in organization {org_id}",
                severity=Severity.INFO,
                impact="Guardrail findings below apply to this account's view of the organization.",
                recommendation=(
                    "Review the SCP and organization trail findings with the management account "
                    "owner."
                ),
                resource_id=org_id,
                evidence={
                    "organization_id": org_id,
                    "management_account_id": master,
                    "feature_set": feature,
                    "is_management_account": is_management,
                },
            )
        ]
        errors: list[CheckError] = []
        if is_management and feature == "ALL":
            try:
                findings.extend(self._scps(client, org_id))
            except AccessDeniedError as exc:
                errors.append(CheckError(self.id, "us-east-1", "AccessDenied", str(exc)))
            except ThrottlingError as exc:
                errors.append(CheckError(self.id, "us-east-1", "Throttling", str(exc)))
            except AwsClientError as exc:
                errors.append(CheckError(self.id, "us-east-1", exc.code, str(exc)))
            findings.append(self._control_tower(ctx))
        findings.extend(self._org_trail(ctx, feature, errors))
        return CheckResult(findings, errors)

    def _scps(self, client: object, org_id: str) -> list[Finding]:
        policies = collect(
            client,
            "list_policies",
            "Policies",
            Filter="SERVICE_CONTROL_POLICY",
        )
        customer = [item for item in policies if not item.get("AwsManaged")]
        if customer:
            return []
        return [
            finding(
                self,
                title="Organization has no customer service control policy",
                severity=Severity.MEDIUM,
                impact="FullAWSAccess is the only SCP, so it is not restricting member accounts.",
                recommendation=(
                    "Attach a customer SCP that denies the actions member accounts must not take."
                ),
                resource_id=org_id,
                evidence={"service_control_policies": len(policies)},
            )
        ]

    def _control_tower(self, ctx: AuditContext) -> Finding:
        try:
            response = call(ctx.client("controltower", "us-east-1"), "list_landing_zones") or {}
        except (AccessDeniedError, AwsClientError, ThrottlingError) as exc:
            return finding(
                self,
                title="Control Tower was not evaluated",
                severity=Severity.INFO,
                impact="The landing zone status is unknown from this role.",
                recommendation=(
                    "Grant controltower:ListLandingZones on the management account if you use "
                    "Control Tower."
                ),
                resource_id="control-tower",
                evidence={"error": exc.code},
            )
        zones = response.get("landingZones") or []
        if not zones:
            return finding(
                self,
                title="Control Tower is not enabled",
                severity=Severity.INFO,
                impact="Preventive and detective guardrails from a landing zone are not in place.",
                recommendation=(
                    "Enable Control Tower if this organization is meant to use those guardrails."
                ),
                resource_id="control-tower",
            )
        return finding(
            self,
            title="Control Tower landing zone is present",
            severity=Severity.INFO,
            impact="A landing zone exists. This audit does not score individual guardrails.",
            recommendation="Review landing zone drift in the Control Tower console.",
            resource_id="control-tower",
            evidence={"statuses": [zone.get("status") for zone in zones]},
        )

    def _org_trail(
        self, ctx: AuditContext, feature: str, errors: list[CheckError]
    ) -> list[Finding]:
        try:
            rows = ctx.trails()
        except AccessDeniedError as exc:
            errors.append(CheckError(self.id, "us-east-1", "AccessDenied", str(exc)))
            return []
        except ThrottlingError as exc:
            errors.append(CheckError(self.id, "us-east-1", "Throttling", str(exc)))
            return []
        except AwsClientError as exc:
            errors.append(CheckError(self.id, "us-east-1", exc.code, str(exc)))
            return []
        logging = [
            row
            for row in rows
            if row["trail"].get("IsOrganizationTrail") and row["status"].get("IsLogging")
        ]
        if logging:
            return []
        advice = "Create a multi-region organization trail and turn logging on."
        if feature != "ALL":
            advice = (
                "Organization trails require all features. Enable all features, then create "
                "a multi-region organization trail."
            )
        return [
            finding(
                self,
                title="No organization CloudTrail trail is logging",
                severity=Severity.HIGH,
                impact="Member-account activity is not collected in one organization trail.",
                recommendation=advice,
                resource_id="organization-trail",
                evidence={"feature_set": feature},
            )
        ]
