"""The published check list and the code stay in sync."""

from pathlib import Path

from aws_health_audit.checks.registry import all_checks


def test_readme_names_every_check():
    readme = Path("README.md").read_text(encoding="utf-8")
    missing = [check.id for check in all_checks() if check.id not in readme]
    assert missing == []
