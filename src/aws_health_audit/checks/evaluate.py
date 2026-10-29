"""Pure decision helpers. No boto3 imports."""

import csv
import io
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase

from aws_health_audit.config import Thresholds
from aws_health_audit.models import Severity

ADMIN_PORTS = (22, 3389)
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
BPA_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
ADMIN_POLICY_NAMES = {"AdministratorAccess", "IAMFullAccess"}
_MISSING_TIMES = {"", "N/A", "no_information", "not_supported", "null", "None"}


@dataclass(frozen=True)
class CpuAssessment:
    """How a CPU series compares with the idle and overprovisioned windows."""

    kind: str
    idle_average: float | None
    idle_points: int
    over_average: float | None
    over_points: int


def waste_severity(monthly_usd: float | None, thresholds: Thresholds) -> Severity | None:
    """Map dollars to severity. None stays None so the caller can choose a floor."""
    from aws_health_audit.aws.pricing import waste_severity_value

    return waste_severity_value(monthly_usd, thresholds)


def as_list(value: object) -> list:
    """Normalize an IAM string-or-list field."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def is_admin_policy(document: dict | None) -> bool:
    """True for an unconditional allow of * or iam:* on resource *."""
    if not isinstance(document, dict):
        return False
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return any(
        _statement_is_unconditional_admin(item) for item in statements if isinstance(item, dict)
    )


def _statement_is_unconditional_admin(statement: dict) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    if statement.get("Condition"):
        return False
    if "NotAction" in statement or "NotResource" in statement:
        return False
    actions = {str(action) for action in as_list(statement.get("Action"))}
    resources = {str(resource) for resource in as_list(statement.get("Resource"))}
    if "*" not in resources:
        return False
    return "*" in actions or "iam:*" in actions


def is_named_admin_policy(policy_name: str | None, policy_arn: str | None = None) -> bool:
    """True for AdministratorAccess and IAMFullAccess, AWS-managed or local."""
    if policy_name in ADMIN_POLICY_NAMES:
        return True
    if policy_arn:
        return policy_arn.rsplit("/", 1)[-1] in ADMIN_POLICY_NAMES
    return False


def permission_opens_admin_port(permission: dict) -> set[int]:
    """Return 22 and/or 3389 when this ingress rule opens them to the world."""
    protocol = str(permission.get("IpProtocol", ""))
    if protocol not in {"tcp", "6", "-1"}:
        return set()
    public = False
    for entry in permission.get("IpRanges") or []:
        if entry.get("CidrIp") in WORLD_CIDRS:
            public = True
    for entry in permission.get("Ipv6Ranges") or []:
        if entry.get("CidrIpv6") in WORLD_CIDRS:
            public = True
    if not public:
        return set()
    if protocol == "-1":
        return set(ADMIN_PORTS)
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return set()
    return {port for port in ADMIN_PORTS if from_port <= port <= to_port}


def acl_grants_are_public(grants: list[dict] | None) -> bool:
    """True when an ACL grants AllUsers or AuthenticatedUsers."""
    for grant in grants or []:
        uri = (grant.get("Grantee") or {}).get("URI", "")
        if uri in {ALL_USERS, AUTHENTICATED_USERS}:
            return True
    return False


def bpa_fully_enabled(config: dict | None) -> bool:
    """True only when all four Block Public Access flags are on."""
    if not config:
        return False
    return all(bool(config.get(key)) for key in BPA_KEYS)


def effective_s3_public(
    *,
    policy_public: bool,
    acl_public: bool,
    bucket_bpa: dict | None,
    account_bpa: dict | None,
) -> bool:
    """True when a public ACL or policy is not blocked by bucket or account BPA."""
    acl_blocked = _flag(bucket_bpa, "IgnorePublicAcls") or _flag(account_bpa, "IgnorePublicAcls")
    policy_blocked = _flag(bucket_bpa, "RestrictPublicBuckets") or _flag(
        account_bpa, "RestrictPublicBuckets"
    )
    return (acl_public and not acl_blocked) or (policy_public and not policy_blocked)


def _flag(config: dict | None, key: str) -> bool:
    return bool(config and config.get(key))


def policy_denies_insecure_transport(policy: dict | None) -> bool:
    """True when a Deny statement requires aws:SecureTransport to be false."""
    if not isinstance(policy, dict):
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Deny":
            continue
        conditions = statement.get("Condition") or {}
        for key, block in conditions.items():
            if key.lower() != "bool" or not isinstance(block, dict):
                continue
            for condition_key, value in block.items():
                if condition_key.lower() == "aws:securetransport" and str(value).lower() == "false":
                    return True
    return False


def selectors_cover_management_read_write(selectors: dict | None) -> bool:
    """True when a trail records read and write management events.

    An empty selector list keeps the CloudTrail default, which is all
    management events.
    """
    if not selectors:
        return True
    classic = selectors.get("EventSelectors") or []
    advanced = selectors.get("AdvancedEventSelectors") or []
    if not classic and not advanced:
        return True
    for selector in classic:
        if (
            selector.get("IncludeManagementEvents")
            and selector.get("ReadWriteType", "All") == "All"
        ):
            return True
    for selector in advanced:
        fields = {item.get("Field"): item for item in selector.get("FieldSelectors") or []}
        category = fields.get("eventCategory")
        if not category or "Management" not in set(category.get("Equals") or []):
            continue
        read_only = fields.get("readOnly")
        if read_only is None:
            return True
        values = {str(item).lower() for item in (read_only.get("Equals") or [])}
        if not values or {"true", "false"} <= values:
            return True
    return False


def trail_requirement_gaps(trail: dict, status: dict, selectors: dict | None) -> list[str]:
    """Human-readable reasons a trail misses the multi-region logging bar."""
    gaps: list[str] = []
    if not trail.get("IsMultiRegionTrail"):
        gaps.append("not multi-region")
    if trail.get("IncludeGlobalServiceEvents") is False:
        gaps.append("global service events excluded")
    if not (status or {}).get("IsLogging"):
        gaps.append("not logging")
    if not selectors_cover_management_read_write(selectors):
        gaps.append("management events are not read and write")
    return gaps


def classify_cpu(
    samples: list[tuple[datetime, float]],
    now: datetime,
    thresholds: Thresholds,
) -> CpuAssessment:
    """Classify CPU as idle, overprovisioned, insufficient, or ok.

    Idle wins. An instance that is idle is not also overprovisioned.
    """
    now = _aware(now)
    idle_cut = now - timedelta(days=thresholds.idle_days)
    over_cut = now - timedelta(days=thresholds.overprovisioned_days)
    idle_values = [value for stamp, value in samples if _aware(stamp) >= idle_cut]
    over_values = [value for stamp, value in samples if _aware(stamp) >= over_cut]
    idle_average = _mean(idle_values)
    over_average = _mean(over_values)
    minimum = thresholds.min_metric_datapoints
    if (
        len(idle_values) >= minimum
        and idle_average is not None
        and idle_average < thresholds.idle_cpu_percent
    ):
        kind = "idle"
    elif (
        len(over_values) >= minimum
        and over_average is not None
        and over_average < thresholds.overprovisioned_cpu_percent
    ):
        kind = "overprovisioned"
    elif len(idle_values) < minimum:
        kind = "insufficient"
    else:
        kind = "ok"
    return CpuAssessment(kind, idle_average, len(idle_values), over_average, len(over_values))


def snapshot_is_stale(
    start: datetime,
    snapshot_id: str,
    ami_snapshot_ids: set[str],
    now: datetime,
    max_age_days: int,
) -> bool:
    """True when a snapshot is old and not the backing store of an owned AMI."""
    if snapshot_id in ami_snapshot_ids:
        return False
    return _aware(now) - _aware(start) > timedelta(days=max_age_days)


def name_matches_globs(name: str, patterns: tuple[str, ...]) -> bool:
    """Case-sensitive glob match used for critical bucket names."""
    return any(fnmatchcase(name, pattern) for pattern in patterns)


def normalize_bucket_region(constraint: str | None) -> str:
    """Map GetBucketLocation values onto region names."""
    if constraint in (None, "", "US"):
        return "us-east-1"
    if constraint == "EU":
        return "eu-west-1"
    return constraint


def transfer_kind(usage_type: str) -> str | None:
    """Classify a Cost Explorer usage type. None and ingress are ignored."""
    text = usage_type.lower()
    interesting = "datatransfer" in text or "aws-out-bytes" in text or "aws-in-bytes" in text
    if not interesting:
        return None
    if "regional" in text or "aws-out-bytes" in text or "aws-in-bytes" in text:
        return "inter-region"
    if "out-bytes" in text:
        return "internet-egress"
    return None


def parse_credential_csv(text: str) -> list[dict[str, str]]:
    """Parse an IAM credential report."""
    return list(csv.DictReader(io.StringIO(text)))


def parse_credential_time(value: str | None) -> datetime | None:
    """Parse a credential-report timestamp. N/A and friends become None."""
    if value is None or value.strip() in _MISSING_TIMES:
        return None
    text = value.strip().replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    return _aware(datetime.fromisoformat(text))


def age_days(moment: datetime | None, now: datetime) -> int | None:
    """Whole days between a past timestamp and now."""
    if moment is None:
        return None
    return (_aware(now) - _aware(moment)).days


def is_unused(
    last_used: datetime | None,
    created: datetime | None,
    now: datetime,
    days: int,
) -> bool:
    """True when a credential is unused for `days`, including never-used old ones."""
    if last_used is not None:
        return _aware(now) - _aware(last_used) >= timedelta(days=days)
    if created is None:
        return False
    return _aware(now) - _aware(created) >= timedelta(days=days)


def password_length_ok(policy: dict | None) -> bool:
    if not policy:
        return False
    return int(policy.get("MinimumPasswordLength") or 0) >= 14


def password_reuse_ok(policy: dict | None) -> bool:
    if not policy:
        return False
    return int(policy.get("PasswordReusePrevention") or 0) >= 24


def ensure_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime."""
    return _aware(value)


def credential_flag(row: dict[str, str], key: str) -> bool:
    """True when a credential-report cell is the string true."""
    return str(row.get(key, "")).lower() == "true"


def root_credential_row(rows: list[dict[str, str]]) -> dict[str, str] | None:
    """Return the credential-report row for the account root user."""
    for row in rows:
        if row.get("user") == "<root_account>":
            return row
    return None


def tag_value(tags: object, key: str) -> str | None:
    """Read a tag from an EC2 tag list, an S3 tag set, or a dict."""
    if not tags:
        return None
    if isinstance(tags, dict):
        value = tags.get(key)
        return None if value is None else str(value)
    if isinstance(tags, list | tuple):
        for item in tags:
            if isinstance(item, dict) and item.get("Key") == key:
                value = item.get("Value")
                return None if value is None else str(value)
            if isinstance(item, tuple) and len(item) == 2 and item[0] == key:
                return str(item[1])
    return None


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
