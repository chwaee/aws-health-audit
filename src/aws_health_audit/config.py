"""Load and validate audit thresholds from YAML."""

from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

import yaml

from aws_health_audit.aws.errors import ConfigError


@dataclass(frozen=True)
class Thresholds:
    """Numeric cutoffs. Dollar amounts are USD per month."""

    idle_cpu_percent: float = 5
    idle_days: int = 7
    overprovisioned_cpu_percent: float = 20
    overprovisioned_memory_percent: float = 30
    overprovisioned_days: int = 14
    snapshot_age_days: int = 90
    access_key_max_age_days: int = 90
    access_key_high_age_days: int = 180
    unused_credential_days: int = 45
    root_use_days: int = 14
    s3_near_empty_bytes: int = 1_048_576
    lambda_memory_used_ratio: float = 0.5
    lambda_lookback_days: int = 14
    lambda_min_memory_mb: int = 256
    data_transfer_min_usd: float = 10
    waste_critical_usd: float = 500
    waste_high_usd: float = 100
    waste_medium_usd: float = 20
    min_metric_datapoints: int = 24
    eip_medium_count: int = 5

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "Thresholds":
        raw = raw or {}
        if not isinstance(raw, dict):
            raise ConfigError("thresholds must be a mapping")
        known = {item.name for item in fields(cls)}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ConfigError(f"Unknown threshold: {unknown[0]}")
        base = cls()
        values: dict[str, Any] = {}
        for name in known:
            if name not in raw:
                continue
            current = getattr(base, name)
            values[name] = _coerce(name, raw[name], type(current))
        return replace(base, **values)


@dataclass(frozen=True)
class AppConfig:
    """Runtime configuration after YAML and built-in defaults are merged."""

    thresholds: Thresholds = field(default_factory=Thresholds)
    critical_buckets: tuple[str, ...] = ()
    ignore_resources: frozenset[str] = field(default_factory=frozenset)
    regions: tuple[str, ...] = ()
    max_workers: int = 8
    disabled_checks: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "AppConfig":
        raw = raw or {}
        if not isinstance(raw, dict):
            raise ConfigError("Config file must be a mapping")
        known = {
            "thresholds",
            "critical_buckets",
            "ignore_resources",
            "regions",
            "max_workers",
            "checks",
        }
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ConfigError(f"Unknown config key: {unknown[0]}")
        checks = raw.get("checks") or {}
        if not isinstance(checks, dict):
            raise ConfigError("checks must be a mapping")
        check_unknown = sorted(set(checks) - {"disabled"})
        if check_unknown:
            raise ConfigError(f"Unknown checks key: {check_unknown[0]}")
        workers = raw.get("max_workers", 8)
        if not isinstance(workers, int) or isinstance(workers, bool) or workers < 1:
            raise ConfigError("max_workers must be an integer >= 1")
        return cls(
            thresholds=Thresholds.from_mapping(raw.get("thresholds")),
            critical_buckets=tuple(_string_list(raw.get("critical_buckets"), "critical_buckets")),
            ignore_resources=frozenset(
                _string_list(raw.get("ignore_resources"), "ignore_resources")
            ),
            regions=tuple(_string_list(raw.get("regions"), "regions")),
            max_workers=workers,
            disabled_checks=tuple(_string_list(checks.get("disabled"), "checks.disabled")),
        )


def load_config(path: Path | None) -> AppConfig:
    """Load YAML. An explicit path wins. Otherwise ./config.yaml if it exists."""
    if path is not None:
        return AppConfig.from_mapping(_read_yaml(path))
    default = Path("config.yaml")
    if default.is_file():
        return AppConfig.from_mapping(_read_yaml(default))
    return AppConfig()


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config {path}: {exc}") from exc
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"Config file must be a mapping: {path}")
    return loaded


def _string_list(value: Any, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ConfigError(f"{key} must be a list of strings")
    return [item.strip() for item in value]


def _coerce(name: str, value: Any, expected: type) -> Any:
    if isinstance(value, bool) or value is None:
        raise ConfigError(f"Invalid value for thresholds.{name}")
    try:
        if expected is int:
            if isinstance(value, float) and not value.is_integer():
                raise ValueError
            return int(value)
        if expected is float:
            return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid value for thresholds.{name}") from exc
    raise ConfigError(f"Invalid value for thresholds.{name}")
