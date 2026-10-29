"""Shared AWS reads so checks do not repeat the same API call."""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, TypeVar

from boto3.session import Session

from aws_health_audit.aws.arns import s3_arn
from aws_health_audit.aws.clients import ClientFactory
from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError
from aws_health_audit.aws.metrics import get_metric_data, metric_query_id, series_points
from aws_health_audit.aws.paginate import call, paginate
from aws_health_audit.checks.evaluate import (
    normalize_bucket_region,
    parse_credential_csv,
    tag_value,
)
from aws_health_audit.clock import utcnow
from aws_health_audit.config import AppConfig

IGNORE_TAG = "aws-health-audit:ignore"
_T = TypeVar("_T")


@dataclass(frozen=True)
class BucketInfo:
    """One bucket plus the region and tags needed by every S3 check."""

    name: str
    region: str | None
    arn: str
    tags: tuple[tuple[str, str], ...]


class AuditContext:
    """Session, account scope, and cached inventory."""

    def __init__(
        self,
        session: Session,
        account_id: str,
        regions: list[str],
        config: AppConfig,
        clients: ClientFactory | None = None,
        profile: str | None = None,
        role_arn: str | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.regions = list(regions)
        self.config = config
        self.clients = clients or ClientFactory(session)
        self.profile = profile
        self.role_arn = role_arn
        self.ignored_resources = 0
        self._lock = threading.Lock()
        self._instances: dict[str, list[dict[str, Any]]] = {}
        self._volumes: dict[str, list[dict[str, Any]]] = {}
        self._security_groups: dict[str, list[dict[str, Any]]] = {}
        self._network_interfaces: dict[str, list[dict[str, Any]]] = {}
        self._cpu: dict[str, dict[str, list[tuple[Any, float]]]] = {}
        self._memory: dict[str, dict[str, float]] = {}
        self._buckets: list[BucketInfo] | None = None
        self._credential_rows: list[dict[str, str]] | None = None
        self._password_policy: dict[str, Any] | None = None
        self._password_policy_loaded = False
        self._virtual_mfas: list[dict[str, Any]] | None = None
        self._account_bpa: dict[str, Any] | None = None
        self._account_bpa_loaded = False
        self._trails: list[dict[str, Any]] | None = None

    def client(self, service: str, region: str | None = None) -> Any:
        """Return a cached boto3 client."""
        return self.clients.client(service, region)

    def is_ignored(
        self,
        check_id: str,
        *,
        resource_id: str | None = None,
        arn: str | None = None,
        tags: object = None,
    ) -> bool:
        """True when config or the ignore tag excludes this resource."""
        value = tag_value(tags, IGNORE_TAG)
        tagged = value is not None and (
            value.lower() in {"true", "yes", "1"} or value.lower() == check_id.lower()
        )
        listed = (resource_id is not None and resource_id in self.config.ignore_resources) or (
            arn is not None and arn in self.config.ignore_resources
        )
        if not tagged and not listed:
            return False
        with self._lock:
            self.ignored_resources += 1
        return True

    def instances(self, region: str) -> list[dict[str, Any]]:
        """Every EC2 instance in the region."""
        return self._cached(self._instances, region, lambda: self._load_instances(region))

    def volumes(self, region: str) -> list[dict[str, Any]]:
        """Every EBS volume in the region."""
        return self._cached(self._volumes, region, lambda: self._load_volumes(region))

    def security_groups(self, region: str) -> list[dict[str, Any]]:
        """Every security group in the region."""
        return self._cached(
            self._security_groups, region, lambda: self._load_security_groups(region)
        )

    def network_interfaces(self, region: str) -> list[dict[str, Any]]:
        """Every ENI in the region, used to see whether a security group is attached."""
        return self._cached(
            self._network_interfaces, region, lambda: self._load_network_interfaces(region)
        )

    def cpu_samples(self, region: str) -> dict[str, list[tuple[Any, float]]]:
        """Hourly average CPU for running instances, keyed by instance id."""
        return self._cached(self._cpu, region, lambda: self._load_cpu(region))

    def memory_used_percent(self, region: str) -> dict[str, float]:
        """Average CloudWatch agent memory use, keyed by instance id.

        Missing keys mean the agent metric is not published for that instance.
        """
        return self._cached(self._memory, region, lambda: self._load_memory(region))

    def bucket_index(self) -> list[BucketInfo]:
        """Every bucket, with region and tags. Region is None when location is denied."""
        with self._lock:
            if self._buckets is not None:
                return self._buckets
        s3 = self.client("s3", "us-east-1")
        names: list[str] = []
        for page in paginate(s3, "list_buckets"):
            names.extend(item["Name"] for item in page.get("Buckets", []))
        refs = [self._bucket_info(s3, name) for name in names]
        with self._lock:
            if self._buckets is None:
                self._buckets = refs
            return self._buckets

    def credential_report(self) -> list[dict[str, str]]:
        """Generate the IAM credential report once and share it across checks."""
        with self._lock:
            if self._credential_rows is not None:
                return self._credential_rows
        rows = self._load_credential_report()
        with self._lock:
            if self._credential_rows is None:
                self._credential_rows = rows
            return self._credential_rows

    def password_policy(self) -> dict[str, Any] | None:
        """Account password policy, or None when IAM has no policy set."""
        with self._lock:
            if self._password_policy_loaded:
                return self._password_policy
        iam = self.client("iam", "us-east-1")
        response = call(iam, "get_account_password_policy", missing_ok=("NoSuchEntity",))
        policy = None if response is None else response.get("PasswordPolicy")
        with self._lock:
            self._password_policy = policy
            self._password_policy_loaded = True
            return self._password_policy

    def virtual_mfa_devices(self) -> list[dict[str, Any]]:
        """Assigned and unassigned virtual MFA devices."""
        with self._lock:
            if self._virtual_mfas is not None:
                return self._virtual_mfas
        iam = self.client("iam", "us-east-1")
        devices: list[dict[str, Any]] = []
        for page in paginate(iam, "list_virtual_mfa_devices"):
            devices.extend(page.get("VirtualMFADevices", []))
        with self._lock:
            if self._virtual_mfas is None:
                self._virtual_mfas = devices
            return self._virtual_mfas

    def account_public_access_block(self) -> dict[str, Any] | None:
        """Account-level S3 Block Public Access, or None when it is unset."""
        with self._lock:
            if self._account_bpa_loaded:
                return self._account_bpa
        s3control = self.client("s3control", "us-east-1")
        response = call(
            s3control,
            "get_public_access_block",
            missing_ok=("NoSuchPublicAccessBlockConfiguration",),
            AccountId=self.account_id,
        )
        config = None if response is None else response.get("PublicAccessBlockConfiguration")
        with self._lock:
            self._account_bpa = config
            self._account_bpa_loaded = True
            return self._account_bpa

    def trails(self) -> list[dict[str, Any]]:
        """CloudTrail trails with status and event selectors attached.

        Each item is ``{"trail", "status", "selectors"}``.
        """
        with self._lock:
            if self._trails is not None:
                return self._trails
        home = self.client("cloudtrail", "us-east-1")
        raw: list[dict[str, Any]] = []
        for page in paginate(home, "describe_trails", includeShadowTrails=True):
            raw.extend(page.get("trailList", []))
        enriched: list[dict[str, Any]] = []
        for trail in raw:
            region = trail.get("HomeRegion") or "us-east-1"
            client = self.client("cloudtrail", region)
            name = trail.get("TrailARN") or trail["Name"]
            status = call(client, "get_trail_status", Name=name) or {}
            selectors = call(client, "get_event_selectors", TrailName=name) or {}
            enriched.append({"trail": trail, "status": status, "selectors": selectors})
        with self._lock:
            if self._trails is None:
                self._trails = enriched
            return self._trails

    def _bucket_info(self, s3: Any, name: str) -> BucketInfo:
        arn = s3_arn(name)
        try:
            location = call(s3, "get_bucket_location", Bucket=name)
        except AccessDeniedError:
            return BucketInfo(name, None, arn, ())
        if location is None:
            return BucketInfo(name, None, arn, ())
        region = normalize_bucket_region(location.get("LocationConstraint"))
        tags: tuple[tuple[str, str], ...] = ()
        try:
            regional = self.client("s3", region)
            tagging = call(
                regional,
                "get_bucket_tagging",
                Bucket=name,
                missing_ok=("NoSuchTagSet",),
            )
        except AccessDeniedError:
            tagging = None
        if tagging:
            tags = tuple(
                (tag.get("Key", ""), str(tag.get("Value", ""))) for tag in tagging.get("TagSet", [])
            )
        return BucketInfo(name, region, arn, tags)

    def _load_instances(self, region: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for page in paginate(self.client("ec2", region), "describe_instances"):
            for reservation in page.get("Reservations", []):
                found.extend(reservation.get("Instances", []))
        return found

    def _load_volumes(self, region: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for page in paginate(self.client("ec2", region), "describe_volumes"):
            found.extend(page.get("Volumes", []))
        return found

    def _load_security_groups(self, region: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for page in paginate(self.client("ec2", region), "describe_security_groups"):
            found.extend(page.get("SecurityGroups", []))
        return found

    def _load_network_interfaces(self, region: str) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for page in paginate(self.client("ec2", region), "describe_network_interfaces"):
            found.extend(page.get("NetworkInterfaces", []))
        return found

    def _load_cpu(self, region: str) -> dict[str, list[tuple[Any, float]]]:
        days = max(
            self.config.thresholds.idle_days,
            self.config.thresholds.overprovisioned_days,
        )
        end = utcnow()
        start = end - timedelta(days=days)
        running = [
            item
            for item in self.instances(region)
            if item.get("State", {}).get("Name") == "running"
        ]
        queries: list[dict[str, Any]] = []
        owners: dict[str, str] = {}
        for instance in running:
            instance_id = instance["InstanceId"]
            query_id = metric_query_id("cpu", instance_id)
            owners[query_id] = instance_id
            queries.append(_cpu_query(query_id, instance_id))
        series = (
            get_metric_data(self.client("cloudwatch", region), queries, start, end)
            if queries
            else {}
        )
        return {owners[query_id]: series_points(series.get(query_id)) for query_id in owners}

    def _load_memory(self, region: str) -> dict[str, float]:
        cloudwatch = self.client("cloudwatch", region)
        metrics: list[dict[str, Any]] = []
        for page in paginate(
            cloudwatch,
            "list_metrics",
            Namespace="CWAgent",
            MetricName="mem_used_percent",
        ):
            metrics.extend(page.get("Metrics", []))
        end = utcnow()
        start = end - timedelta(days=self.config.thresholds.overprovisioned_days)
        queries = []
        owners: list[tuple[str, str]] = []
        for index, metric in enumerate(metrics):
            dimensions = metric.get("Dimensions") or []
            instance_id = next(
                (item["Value"] for item in dimensions if item.get("Name") == "InstanceId"),
                None,
            )
            if not instance_id:
                continue
            query_id = metric_query_id("mem", f"{index}_{instance_id}")
            owners.append((query_id, instance_id))
            queries.append(
                {
                    "Id": query_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "CWAgent",
                            "MetricName": "mem_used_percent",
                            "Dimensions": dimensions,
                        },
                        "Period": 3600,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                }
            )
        series = get_metric_data(cloudwatch, queries, start, end) if queries else {}
        grouped: dict[str, list[float]] = {}
        for query_id, instance_id in owners:
            points = series_points(series.get(query_id))
            if not points:
                continue
            grouped.setdefault(instance_id, []).append(
                sum(value for _, value in points) / len(points)
            )
        return {
            instance_id: sum(values) / len(values)
            for instance_id, values in grouped.items()
            if values
        }

    def _load_credential_report(self) -> list[dict[str, str]]:
        iam = self.client("iam", "us-east-1")
        deadline = time.monotonic() + 30
        content: bytes | str | None = None
        while time.monotonic() < deadline:
            try:
                call(iam, "generate_credential_report")
            except AwsClientError as exc:
                if exc.code not in {"ReportInProgress", "ReportNotPresent"}:
                    raise
            try:
                report = call(iam, "get_credential_report")
            except AwsClientError as exc:
                if exc.code in {"ReportInProgress", "ReportNotPresent"}:
                    time.sleep(0.5)
                    continue
                raise
            if report and report.get("Content") is not None:
                content = report["Content"]
                break
            time.sleep(0.5)
        if content is None:
            raise AwsClientError("IAM credential report was not ready", "ReportInProgress")
        text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
        return parse_credential_csv(text)

    def _cached(self, store: dict[str, _T], key: str, loader: Callable[[], _T]) -> _T:
        with self._lock:
            if key in store:
                return store[key]
        loaded = loader()
        with self._lock:
            return store.setdefault(key, loaded)


def _cpu_query(query_id: str, instance_id: str) -> dict[str, Any]:
    return {
        "Id": query_id,
        "MetricStat": {
            "Metric": {
                "Namespace": "AWS/EC2",
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
            },
            "Period": 3600,
            "Stat": "Average",
        },
        "ReturnData": True,
    }
