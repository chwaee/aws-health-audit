"""CloudWatch GetMetricData helpers."""

from datetime import datetime
from typing import Any

from aws_health_audit.aws.paginate import call


def metric_query_id(prefix: str, resource_id: str) -> str:
    """Build a GetMetricData Id. It must start with a lowercase letter."""
    safe = "".join(char if char.isalnum() else "_" for char in resource_id)
    return f"{prefix}_{safe}"[:255]


def get_metric_data(
    client: Any,
    queries: list[dict[str, Any]],
    start: datetime,
    end: datetime,
    *,
    batch_size: int = 400,
) -> dict[str, dict[str, Any]]:
    """Run GetMetricData in batches and follow NextToken. Keyed by query id."""
    found: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(queries), batch_size):
        chunk = queries[offset : offset + batch_size]
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {
                "MetricDataQueries": chunk,
                "StartTime": start,
                "EndTime": end,
            }
            if token:
                kwargs["NextToken"] = token
            page = call(client, "get_metric_data", **kwargs) or {}
            for series in page.get("MetricDataResults", []):
                found[series["Id"]] = series
            token = page.get("NextToken")
            if not token:
                break
    return found


def series_points(series: dict[str, Any] | None) -> list[tuple[datetime, float]]:
    """Pair timestamps and values from one MetricDataResult."""
    if not series:
        return []
    timestamps = series.get("Timestamps") or []
    values = series.get("Values") or []
    points: list[tuple[datetime, float]] = []
    for stamp, value in zip(timestamps, values, strict=False):
        points.append((stamp, float(value)))
    points.sort(key=lambda item: item[0])
    return points
