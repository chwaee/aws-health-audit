"""Command line entry point for aws-health-audit."""

import logging
import sys
from pathlib import Path

import click

from aws_health_audit import __version__
from aws_health_audit.aws.errors import ConfigError, CredentialsError
from aws_health_audit.checks.registry import all_checks
from aws_health_audit.config import load_config
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category
from aws_health_audit.reporter import render_json, render_text
from aws_health_audit.runner import failure_exit_code, run_audit, select_checks
from aws_health_audit.session import build_session, discover_regions, require_account_id


def _catalog() -> str:
    """Help epilog. A leading ``\\b`` tells Click not to rewrap the block."""
    lines = ["\b", "Check ids:"]
    grouped: dict[str, list] = {category.value: [] for category in Category}
    for check in all_checks():
        grouped[check.category.value].append(check)
    for category in ("cost", "security", "compliance"):
        lines.append(category)
        for check in grouped[category]:
            cis = ""
            if check.cis_controls:
                cis = f" [CIS {', '.join(check.cis_controls)}]"
            lines.append(f"  {check.id}{cis}")
            lines.append(f"    {check.description}")
    return "\n".join(lines) + "\n"


@click.command(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=_catalog(),
)
@click.version_option(__version__, prog_name="aws-health-audit")
@click.option("--profile", default=None, help="AWS shared-config profile.")
@click.option("--role-arn", default=None, help="Role to assume before the audit.")
@click.option("--external-id", default=None, help="External id for AssumeRole.")
@click.option("--regions", default=None, help="Comma-separated regions. Default: all opted-in.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Report format written to stdout and, when set, to --output-file.",
)
@click.option(
    "--output-file",
    type=click.Path(dir_okay=False),
    default=None,
    help="Also write the report here.",
)
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option(
    "--skip-checks", default=None, help="Comma-separated categories or check ids to skip."
)
@click.option("--only-checks", default=None, help="Comma-separated categories or check ids to run.")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "never"]),
    default="never",
    show_default=True,
    help="Exit 1 when a finding is at least this severe.",
)
@click.option(
    "--max-workers", type=click.IntRange(1, 64), default=None, help="Parallel check workers."
)
@click.option(
    "--verbose", is_flag=True, help="Debug logging, including unexpected check tracebacks."
)
@click.option("--quiet", is_flag=True, help="Suppress per-check progress on stderr.")
def main(
    profile: str | None,
    role_arn: str | None,
    external_id: str | None,
    regions: str | None,
    output_format: str,
    output_file: str | None,
    config_path: str | None,
    skip_checks: str | None,
    only_checks: str | None,
    fail_on: str,
    max_workers: int | None,
    verbose: bool,
    quiet: bool,
) -> None:
    """Audit one AWS account for cost, security, and CIS Foundations findings.

    The audit is read-only aside from iam:GenerateCredentialReport. It does not
    change resources. Use --skip-checks financial,compliance to run one area.
    """
    if verbose and quiet:
        raise click.UsageError("--verbose and --quiet cannot be used together")
    if external_id and not role_arn:
        raise click.UsageError("--external-id requires --role-arn")
    try:
        code = execute(
            profile=profile,
            role_arn=role_arn,
            external_id=external_id,
            regions=regions,
            output_format=output_format,
            output_file=output_file,
            config_path=Path(config_path) if config_path else None,
            skip_checks=_tokens(skip_checks),
            only_checks=_tokens(only_checks),
            fail_on=fail_on,
            max_workers=max_workers,
            verbose=verbose,
            quiet=quiet,
        )
    except (ConfigError, CredentialsError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    sys.exit(code)


def execute(
    *,
    profile: str | None,
    role_arn: str | None,
    external_id: str | None,
    regions: str | None,
    output_format: str,
    output_file: str | None,
    config_path: Path | None,
    skip_checks: list[str],
    only_checks: list[str],
    fail_on: str,
    max_workers: int | None,
    verbose: bool,
    quiet: bool,
) -> int:
    """Run the audit and return a process exit code."""
    _configure_logging(verbose)
    config = load_config(config_path)
    session = build_session(profile, role_arn, external_id)
    account_id = require_account_id(session)
    chosen = _tokens(regions) if regions else list(config.regions)
    region_list = chosen or discover_regions(session)
    disabled = list(config.disabled_checks) + skip_checks
    checks, skipped = select_checks(disabled, only_checks or None)
    ctx = AuditContext(
        session=session,
        account_id=account_id,
        regions=region_list,
        config=config,
        profile=profile,
        role_arn=role_arn,
    )
    workers = max_workers if max_workers is not None else config.max_workers

    def progress(message: str) -> None:
        if not quiet:
            click.echo(message, err=True)

    report = run_audit(ctx, checks, skipped=skipped, max_workers=workers, progress=progress)
    rendered = render_json(report) if output_format == "json" else render_text(report)
    click.echo(rendered, nl=False)
    if output_file:
        path = Path(output_file)
        if not path.parent.exists():
            raise ConfigError(f"Output directory does not exist: {path.parent}")
        path.write_text(rendered, encoding="utf-8")
    return failure_exit_code(report.findings, fail_on)


def _tokens(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING, format="%(levelname)s %(message)s"
    )
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
