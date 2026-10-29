"""Elastic IPs that are not associated with a network interface."""

from aws_health_audit.aws.arns import ec2_arn
from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.aws.paginate import collect
from aws_health_audit.aws.pricing import eip_monthly_usd, format_usd
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, CheckError, EstimateSource, Finding, Severity


class UnusedEipCheck(Check):
    """Unassociated addresses. Five or more in the account raise each one to MEDIUM."""

    id = "COST-EIP-UNUSED"
    title = "Unused Elastic IPs"
    category = Category.COST
    scope = Scope.GLOBAL
    description = "Elastic IP addresses that are not associated with a resource."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        del region
        unused: list[tuple[str, dict]] = []
        errors: list[CheckError] = []
        for current in ctx.regions:
            try:
                addresses = collect(ctx.client("ec2", current), "describe_addresses", "Addresses")
            except AccessDeniedError as exc:
                errors.append(CheckError(self.id, current, "AccessDenied", str(exc)))
                continue
            except ThrottlingError as exc:
                errors.append(CheckError(self.id, current, "Throttling", str(exc)))
                continue
            except AwsClientError as exc:
                errors.append(CheckError(self.id, current, exc.code, str(exc)))
                continue
            for address in addresses:
                if _associated(address):
                    continue
                allocation_id = address.get("AllocationId") or address.get("PublicIp")
                arn = ec2_arn(current, ctx.account_id, "elastic-ip", allocation_id)
                if ctx.is_ignored(
                    self.id,
                    resource_id=allocation_id,
                    arn=arn,
                    tags=address.get("Tags"),
                ):
                    continue
                unused.append((current, address))

        severity = (
            Severity.MEDIUM
            if len(unused) >= ctx.config.thresholds.eip_medium_count
            else Severity.LOW
        )
        monthly = eip_monthly_usd()
        findings: list[Finding] = []
        for current, address in unused:
            allocation_id = address.get("AllocationId") or address.get("PublicIp")
            public_ip = address.get("PublicIp", allocation_id)
            findings.append(
                finding(
                    self,
                    title=f"Unused Elastic IP: {public_ip} (est. waste: {format_usd(monthly)}/mo)",
                    severity=severity,
                    impact=(
                        "AWS charges for an Elastic IP that is notattached to a running resource."
                    ),
                    recommendation=f"Release {public_ip} if nothing still needs that address.",
                    region=current,
                    resource_arn=ec2_arn(current, ctx.account_id, "elastic-ip", allocation_id),
                    resource_id=allocation_id,
                    evidence={"public_ip": public_ip, "unused_in_account": len(unused)},
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return CheckResult(findings, errors)


def _associated(address: dict) -> bool:
    return bool(
        address.get("AssociationId")
        or address.get("InstanceId")
        or address.get("NetworkInterfaceId")
    )
