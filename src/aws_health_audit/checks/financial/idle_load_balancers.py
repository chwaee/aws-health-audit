"""Load balancers with no registered targets."""

from aws_health_audit.aws.arns import classic_elb_arn
from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.aws.paginate import call, collect
from aws_health_audit.aws.pricing import format_usd, load_balancer_monthly_usd
from aws_health_audit.checks.base import Check, CheckResult, Scope, finding
from aws_health_audit.checks.evaluate import waste_severity
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, CheckError, EstimateSource, Severity, more_severe


class IdleLoadBalancerCheck(Check):
    """ALB, NLB, GWLB, and classic ELB resources that have no registered targets.

    Unhealthy targets still count as attached. The estimate is the base hourly
    charge and does not include LCU or NLCU usage.
    """

    id = "COST-ELB-IDLE"
    title = "Load balancers with no targets"
    category = Category.COST
    scope = Scope.REGIONAL
    description = "Load balancers that have no registered targets."

    def run(self, ctx: AuditContext, region: str | None) -> CheckResult:
        assert region is not None
        errors: list[CheckError] = []
        findings = []
        try:
            findings.extend(self._v2(ctx, region))
        except AccessDeniedError as exc:
            errors.append(CheckError(self.id, region, "AccessDenied", str(exc)))
        except ThrottlingError as exc:
            errors.append(CheckError(self.id, region, "Throttling", str(exc)))
        except AwsClientError as exc:
            errors.append(CheckError(self.id, region, exc.code, str(exc)))
        try:
            findings.extend(self._classic(ctx, region))
        except AccessDeniedError as exc:
            errors.append(CheckError(self.id, region, "AccessDenied", f"classic: {exc}"))
        except ThrottlingError as exc:
            errors.append(CheckError(self.id, region, "Throttling", f"classic: {exc}"))
        except AwsClientError as exc:
            errors.append(CheckError(self.id, region, exc.code, f"classic: {exc}"))
        return CheckResult(findings, errors)

    def _v2(self, ctx: AuditContext, region: str) -> list:
        client = ctx.client("elbv2", region)
        load_balancers = collect(client, "describe_load_balancers", "LoadBalancers")
        groups = collect(client, "describe_target_groups", "TargetGroups")
        by_lb: dict[str, list[dict]] = {}
        for group in groups:
            for arn in group.get("LoadBalancerArns") or []:
                by_lb.setdefault(arn, []).append(group)
        findings = []
        for balancer in load_balancers:
            arn = balancer["LoadBalancerArn"]
            name = balancer.get("LoadBalancerName", arn)
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            attached = by_lb.get(arn, [])
            if attached and any(_target_group_has_targets(client, group) for group in attached):
                continue
            kind = balancer.get("Type", "application")
            monthly = load_balancer_monthly_usd(kind)
            severity = more_severe(
                waste_severity(monthly, ctx.config.thresholds) or Severity.LOW,
                Severity.MEDIUM,
            )
            findings.append(
                finding(
                    self,
                    title=(
                        f"Load balancer with no targets: {name} (est. waste:"
                        f"{format_usd(monthly)}/mo)"
                    ),
                    severity=severity,
                    impact=(
                        "The load balancer base hourly charge continues with nothing registered "
                        "behind it."
                    ),
                    recommendation=(
                        f"Delete {name} if the service is gone, or register its targets."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=name,
                    evidence={"type": kind, "target_groups": len(attached)},
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return findings

    def _classic(self, ctx: AuditContext, region: str) -> list:
        client = ctx.client("elb", region)
        findings = []
        for balancer in collect(client, "describe_load_balancers", "LoadBalancerDescriptions"):
            name = balancer["LoadBalancerName"]
            arn = classic_elb_arn(region, ctx.account_id, name)
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            if balancer.get("Instances"):
                continue
            monthly = load_balancer_monthly_usd("classic")
            severity = more_severe(
                waste_severity(monthly, ctx.config.thresholds) or Severity.LOW,
                Severity.MEDIUM,
            )
            findings.append(
                finding(
                    self,
                    title=(
                        f"Classic load balancer with no instances: {name} "
                        f"(est. waste: {format_usd(monthly)}/mo)"
                    ),
                    severity=severity,
                    impact=(
                        "A classic load balancer with an empty instance list still has an hourly "
                        "charge."
                    ),
                    recommendation=(
                        f"Delete {name} or register the instancesthat should receive traffic."
                    ),
                    region=region,
                    resource_arn=arn,
                    resource_id=name,
                    evidence={"type": "classic"},
                    estimated_monthly_waste_usd=monthly,
                    estimate_source=EstimateSource.RATE_CARD,
                )
            )
        return findings


def _target_group_has_targets(client: object, group: dict) -> bool:
    health = call(client, "describe_target_health", TargetGroupArn=group["TargetGroupArn"]) or {}
    return bool(health.get("TargetHealthDescriptions"))
