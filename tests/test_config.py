"""Config loading and validation."""

from pathlib import Path

import pytest

from aws_health_audit.aws.errors import ConfigError
from aws_health_audit.config import AppConfig, load_config


def test_defaults_when_file_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    config = load_config(None)
    assert config.thresholds.idle_cpu_percent == 5
    assert config.max_workers == 8
    assert config.regions == ()


def test_yaml_overrides_and_rejects_unknown_keys(tmp_path: Path):
    path = tmp_path / "audit.yaml"
    path.write_text(
        "thresholds:\n"
        "  idle_days: 14\n"
        "critical_buckets:\n"
        "  - prod-*\n"
        "checks:\n"
        "  disabled:\n"
        "    - COST-EC2-IDLE\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.thresholds.idle_days == 14
    assert config.critical_buckets == ("prod-*",)
    assert config.disabled_checks == ("COST-EC2-IDLE",)

    path.write_text("not_a_key: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="Unknown config key"):
        load_config(path)


def test_threshold_type_error(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("thresholds:\n  idle_days: 1.5\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="idle_days"):
        AppConfig.from_mapping({"thresholds": {"idle_days": 1.5}})
