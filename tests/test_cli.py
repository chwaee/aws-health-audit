"""CLI help, selection, and startup failures."""

import pytest
from click.testing import CliRunner

from aws_health_audit.aws.errors import CredentialsError
from aws_health_audit.cli import main


def test_help_lists_check_ids():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "SEC-S3-PUBLIC" in result.output
    assert "COST-EC2-IDLE" in result.output
    assert "CIS 1.5" in result.output


def test_invalid_format_fails():
    result = CliRunner().invoke(main, ["--format", "xml"])
    assert result.exit_code != 0


def test_skip_checks_are_forwarded(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    def fake_execute(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr("aws_health_audit.cli.execute", fake_execute)
    result = CliRunner().invoke(main, ["--skip-checks", "financial,compliance"])
    assert result.exit_code == 0
    assert captured["skip_checks"] == ["financial", "compliance"]


def test_missing_credentials_exit_2(monkeypatch: pytest.MonkeyPatch):
    def boom(*_args: object, **_kwargs: object) -> object:
        raise CredentialsError("No AWS credentials found.")

    monkeypatch.setattr("aws_health_audit.cli.build_session", boom)
    result = CliRunner().invoke(main, [])
    assert result.exit_code == 2
    assert "No AWS credentials found." in result.output
