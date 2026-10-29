"""Lambda functions whose memory is far above recent use."""

import time
from datetime import timedelta

from aws_health_audit.aws.errors import AwsClientError
from aws_health_audit.aws.metrics import get_metric_data, metric_query_id
from aws_health_audit.aws.paginate import call, collect
from aws_health_audit.aws.pricing import (
    lambda_monthly_waste_usd,
    lambda_recommended_memory,
)
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.checks.evaluate import ensure_utc, parse_credential_time, waste_severity
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, EstimateSource, Finding, Severity

_QUERY = """
fields @log, @message
| filter @message like /REPORT RequestId/
| parse @message /Max Memory Used: (?<maxmem>\\d+) MB/
| stats max(maxmem) as maxmem by @log
"""


class LambdaMemoryCheck(Check):
    """Compare configured memory with CloudWatch Logs Insights REPORT lines.

    One Insights query is issued per batch of log groups. Functions with no
    recent invocations and an old LastModified time are reported separately,
    without an invented dollar amount.
    """

    id = "COST-LAMBDA-MEM"
    title = "Lambda memory and unused functions"
    category = Category.COST
    scope = Scope.REGIONAL
    description = "Functions with unused memory headroom or no recent invocations."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        functions = collect(ctx.client("lambda", region), "list_functions", "Functions")
        if not functions:
            return []
        thresholds = ctx.config.thresholds
        now = utcnow()
        observed = _max_memory_by_function(ctx, region, now, thresholds.lambda_lookback_days)
        usage = _invocation_stats(ctx, region, functions, thresholds.lambda_lookback_days, now)
        findings: list[Finding] = []
        for function in functions:
            name = function["FunctionName"]
            arn = function.get("FunctionArn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            allocated = int(function.get("MemorySize") or 0)
            used = observed.get(name)
            stats = usage.get(name, {"invocations": 0.0, "duration_ms": 0.0})
            if (
                used is not None
                and allocated >= thresholds.lambda_min_memory_mb
                and used < allocated * thresholds.lambda_memory_used_ratio
            ):
                recommended = lambda_recommended_memory(used)
                if recommended < allocated:
                    waste = lambda_monthly_waste_usd(
                        allocated,
                        recommended,
                        stats["duration_ms"],
                        stats["invocations"],
                        thresholds.lambda_lookback_days,
                    )
                    severity = waste_severity(waste, thresholds) or Severity.LOW
                    findings.append(
                        finding(
                            self,
                            title=(
                                f"Lambda function memory is oversized: {name} "
                                f"({allocated} MB, max used {used:.0f} MB)"
                            ),
                            severity=severity,
                            impact=(
                                "Allocated memory is billed for every millisecond the functionruns."
                            ),
                            recommendation=(
                                f"Lower {name} from {allocated} MB to {recommended} MB "
                                "and watch errors and duration for one release."
                            ),
                            region=region,
                            resource_arn=arn,
                            resource_id=name,
                            evidence={
                                "allocated_mb": allocated,
                                "max_used_mb": used,
                                "recommended_mb": recommended,
                                "invocations": stats["invocations"],
                            },
                            estimated_monthly_waste_usd=waste,
                            estimate_source=EstimateSource.RATE_CARD
                            if waste
                            else EstimateSource.NONE,
                        )
                    )
                    continue
            if (
                used is None
                and stats["invocations"] <= 0
                and _is_old(function, now, thresholds.lambda_lookback_days)
            ):
                findings.append(
                    finding(
                        self,
                        title=f"Lambda function has no recent invocations: {name}",
                        severity=Severity.LOW,
                        impact=(
                            "An unused function still has an execution role and a code package to "
                            "review."
                        ),
                        recommendation=(
                            f"Delete {name} if the integration that called it has been retired."
                        ),
                        region=region,
                        resource_arn=arn,
                        resource_id=name,
                        evidence={
                            "memory_mb": allocated,
                            "lookback_days": thresholds.lambda_lookback_days,
                        },
                    )
                )
        return findings


def _max_memory_by_function(
    ctx: AuditContext,
    region: str,
    now: object,
    lookback_days: int,
) -> dict[str, float]:
    logs = ctx.client("logs", region)
    groups = collect(logs, "describe_log_groups", "logGroups", logGroupNamePrefix="/aws/lambda/")
    names = [group["logGroupName"] for group in groups if group.get("logGroupName")]
    found: dict[str, float] = {}
    end = (
        int(ensure_utc(now).timestamp()) if hasattr(now, "timestamp") else int(utcnow().timestamp())
    )
    start = end - lookback_days * 86400
    for offset in range(0, len(names), 50):
        chunk = names[offset : offset + 50]
        started = call(
            logs,
            "start_query",
            logGroupNames=chunk,
            startTime=start,
            endTime=end,
            queryString=_QUERY,
        )
        if not started:
            continue
        for row in _wait_for_query(logs, started["queryId"]):
            cells = {cell["field"]: cell["value"] for cell in row}
            function_name = _function_from_log(cells.get("@log", ""))
            raw = cells.get("maxmem")
            if function_name and raw not in (None, ""):
                found[function_name] = float(raw)
    return found


def _wait_for_query(logs: object, query_id: str) -> list:
    deadline = time.monotonic() + 30
    while True:
        result = call(logs, "get_query_results", queryId=query_id) or {}
        status = result.get("status")
        if status == "Complete":
            rows = list(result.get("results") or [])
            token = result.get("nextToken")
            while token:
                page = call(logs, "get_query_results", queryId=query_id, nextToken=token) or {}
                rows.extend(page.get("results") or [])
                token = page.get("nextToken")
            return rows
        if status in {"Failed", "Cancelled", "Timeout"}:
            raise AwsClientError(f"Logs Insights query {status}", status or "Failed")
        if time.monotonic() > deadline:
            raise AwsClientError("Logs Insights query timed out", "Timeout")
        time.sleep(0.5)


def _function_from_log(value: str) -> str | None:
    marker = "/aws/lambda/"
    if marker not in value:
        return None
    return value.split(marker, 1)[1].split(":", 1)[0] or None


def _invocation_stats(
    ctx: AuditContext,
    region: str,
    functions: list[dict],
    lookback_days: int,
    now: object,
) -> dict[str, dict[str, float]]:
    end = ensure_utc(now) if hasattr(now, "tzinfo") else utcnow()
    start = end - timedelta(days=lookback_days)
    queries = []
    owners: dict[str, tuple[str, str]] = {}
    for function in functions:
        name = function["FunctionName"]
        for kind, metric, stat in (
            ("inv", "Invocations", "Sum"),
            ("dur", "Duration", "Average"),
        ):
            query_id = metric_query_id(kind, name)
            owners[query_id] = (name, kind)
            queries.append(
                {
                    "Id": query_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": metric,
                            "Dimensions": [{"Name": "FunctionName", "Value": name}],
                        },
                        "Period": 86400,
                        "Stat": stat,
                    },
                    "ReturnData": True,
                }
            )
    series = (
        get_metric_data(ctx.client("cloudwatch", region), queries, start, end) if queries else {}
    )
    stats: dict[str, dict[str, float]] = {}
    for query_id, (name, kind) in owners.items():
        values = (series.get(query_id) or {}).get("Values") or []
        bucket = stats.setdefault(name, {"invocations": 0.0, "duration_ms": 0.0})
        if kind == "inv":
            bucket["invocations"] = float(sum(values))
        elif values:
            bucket["duration_ms"] = float(sum(values) / len(values))
    return stats


def _is_old(function: dict, now: object, days: int) -> bool:
    modified = parse_credential_time(str(function.get("LastModified", "")))
    if modified is None or not hasattr(now, "tzinfo"):
        return False
    return ensure_utc(now) - modified >= timedelta(days=days)
