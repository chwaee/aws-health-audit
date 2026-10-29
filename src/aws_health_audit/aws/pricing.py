"""Directional public-price estimates. These are not a bill.

Rates follow common us-east-1 Linux on-demand prices. A known instance family
uses its large size as the base and scales by the usual size ladder. Unknown
families use a generic large price and are marked low confidence. Snapshot
estimates use the source volume size, which overstates incremental storage.
"""

from aws_health_audit.config import Thresholds
from aws_health_audit.models import Severity

HOURS_PER_MONTH = 730

# Hourly USD for the "large" size of each family.
FAMILY_LARGE_HOURLY: dict[str, float] = {
    "t2": 0.0928,
    "t3": 0.0832,
    "t3a": 0.0752,
    "t4g": 0.0672,
    "m5": 0.096,
    "m5a": 0.086,
    "m5n": 0.119,
    "m6a": 0.0864,
    "m6g": 0.077,
    "m6i": 0.096,
    "m7a": 0.11592,
    "m7g": 0.0816,
    "m7i": 0.1008,
    "c5": 0.085,
    "c5a": 0.077,
    "c6a": 0.0765,
    "c6g": 0.068,
    "c6i": 0.085,
    "c7g": 0.0725,
    "c7i": 0.08925,
    "r5": 0.126,
    "r5a": 0.113,
    "r6a": 0.1134,
    "r6g": 0.1008,
    "r6i": 0.126,
    "r7g": 0.1071,
    "r7i": 0.1323,
}

GENERIC_LARGE_HOURLY = 0.096

SIZE_FACTOR: dict[str, float] = {
    "nano": 0.0625,
    "micro": 0.125,
    "small": 0.25,
    "medium": 0.5,
    "large": 1,
    "xlarge": 2,
    "metal": 96,
}

SIZE_LADDER: tuple[str, ...] = (
    "nano",
    "micro",
    "small",
    "medium",
    "large",
    "xlarge",
    "2xlarge",
    "3xlarge",
    "4xlarge",
    "6xlarge",
    "8xlarge",
    "9xlarge",
    "10xlarge",
    "12xlarge",
    "16xlarge",
    "18xlarge",
    "24xlarge",
    "32xlarge",
    "48xlarge",
    "metal",
)

EBS_GB_MONTH: dict[str, float] = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}

SNAPSHOT_GB_MONTH = 0.05
S3_STANDARD_GB_MONTH = 0.023
EIP_HOURLY = 0.005
ALB_HOURLY = 0.0225
CLASSIC_ELB_HOURLY = 0.025
LAMBDA_GB_SECOND = 0.0000166667
LAMBDA_MEMORY_STEPS: tuple[int, ...] = (
    128,
    256,
    512,
    1024,
    1536,
    2048,
    3008,
    4096,
    5120,
    6144,
    7168,
    8192,
    10240,
)


def format_usd(amount: float | None) -> str:
    """Format a monthly estimate for a finding title."""
    if amount is None:
        return "n/a"
    rounded = round(float(amount), 2)
    if abs(rounded - round(rounded)) < 0.001:
        return f"${rounded:.0f}"
    return f"${rounded:.2f}"


def money(value: float | None) -> float | None:
    """Round a dollar amount to cents."""
    if value is None:
        return None
    return round(float(value), 2)


def size_factor(size: str) -> float | None:
    """Return the multiplier versus a large instance, or None if unknown."""
    if size in SIZE_FACTOR:
        return SIZE_FACTOR[size]
    if size.endswith("xlarge"):
        count = size[: -len("xlarge")]
        if count.isdigit():
            return int(count) * 2
    return None


def instance_monthly_usd(instance_type: str) -> tuple[float, str]:
    """Return (usd per month, confidence). Confidence is high or low."""
    family, separator, size = instance_type.partition(".")
    factor = size_factor(size) if separator else None
    if factor is None:
        return money(GENERIC_LARGE_HOURLY * HOURS_PER_MONTH) or 0.0, "low"
    if family in FAMILY_LARGE_HOURLY:
        hourly = FAMILY_LARGE_HOURLY[family] * factor
        return money(hourly * HOURS_PER_MONTH) or 0.0, "high"
    hourly = GENERIC_LARGE_HOURLY * factor
    return money(hourly * HOURS_PER_MONTH) or 0.0, "low"


def downsize_instance_type(instance_type: str) -> str | None:
    """Return the next size down in the same family, or None at the bottom."""
    family, separator, size = instance_type.partition(".")
    if not separator or size not in SIZE_LADDER:
        return None
    index = SIZE_LADDER.index(size)
    if index == 0:
        return None
    return f"{family}.{SIZE_LADDER[index - 1]}"


def ebs_monthly_usd(volume_type: str, size_gib: int) -> tuple[float, str]:
    """Price EBS storage only. Extra IOPS and throughput are not included."""
    rate = EBS_GB_MONTH.get(volume_type)
    if rate is None:
        return money(size_gib * EBS_GB_MONTH["gp3"]) or 0.0, "low"
    return money(size_gib * rate) or 0.0, "high"


def snapshot_monthly_usd(size_gib: int) -> float:
    """Upper bound. AWS bills incremental snapshot data, not the full volume."""
    return money(size_gib * SNAPSHOT_GB_MONTH) or 0.0


def s3_storage_monthly_usd(size_bytes: int) -> float:
    """Standard-class storage estimate."""
    gib = size_bytes / (1024**3)
    return money(gib * S3_STANDARD_GB_MONTH) or 0.0


def eip_monthly_usd() -> float:
    return money(EIP_HOURLY * HOURS_PER_MONTH) or 0.0


def load_balancer_monthly_usd(kind: str) -> float:
    """Base hourly charge only. LCU and NLC charges are excluded."""
    hourly = CLASSIC_ELB_HOURLY if kind == "classic" else ALB_HOURLY
    return money(hourly * HOURS_PER_MONTH) or 0.0


def lambda_recommended_memory(max_used_mb: float) -> int:
    """Smallest Lambda memory step at or above 1.25 times observed use."""
    target = max_used_mb * 1.25
    for step in LAMBDA_MEMORY_STEPS:
        if step >= target:
            return step
    return LAMBDA_MEMORY_STEPS[-1]


def lambda_monthly_waste_usd(
    allocated_mb: int,
    recommended_mb: int,
    average_duration_ms: float,
    invocations: float,
    lookback_days: int,
) -> float | None:
    """Scale lookback GB-seconds to 30 days. None when there is nothing to price."""
    if invocations <= 0 or average_duration_ms <= 0 or lookback_days <= 0:
        return None
    if recommended_mb >= allocated_mb:
        return 0.0
    seconds = (average_duration_ms / 1000) * invocations
    delta_gb = (allocated_mb - recommended_mb) / 1024
    window = delta_gb * seconds * LAMBDA_GB_SECOND
    return money(window * (30 / lookback_days))


def waste_severity_value(monthly_usd: float | None, thresholds: Thresholds) -> Severity | None:
    """Map a monthly dollar figure onto the configured waste scale."""
    if monthly_usd is None:
        return None
    if monthly_usd >= thresholds.waste_critical_usd:
        return Severity.CRITICAL
    if monthly_usd >= thresholds.waste_high_usd:
        return Severity.HIGH
    if monthly_usd >= thresholds.waste_medium_usd:
        return Severity.MEDIUM
    if monthly_usd > 0:
        return Severity.LOW
    return Severity.INFO
