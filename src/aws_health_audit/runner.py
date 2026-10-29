"""Run checks concurrently and keep going when one of them fails."""

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from aws_health_audit import __version__
from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError
from aws_health_audit.checks.base import Check, CheckResult, Scope
from aws_health_audit.checks.registry import all_checks
from aws_health_audit.clock import utcnow
from aws_health_audit.context import AuditContext
from aws_health_audit.models import (
    SEVERITY_RANK,
    AuditReport,
    Category,
    CheckError,
    Finding,
    Severity,
)
from aws_health_audit.reporter.text import sort_findings

logger = logging.getLogger(__name__)

CATEGORY_ALIASES = {
    "financial": Category.COST,
    "cost": Category.COST,
    "security": Category.SECURITY,
    "compliance": Category.COMPLIANCE,
}

FAIL_RANK = {
    "critical": SEVERITY_RANK[Severity.CRITICAL],
    "high": SEVERITY_RANK[Severity.HIGH],
    "medium": SEVERITY_RANK[Severity.MEDIUM],
    "low": SEVERITY_RANK[Severity.LOW],
}


def select_checks(
    disabled: list[str] | tuple[str, ...],
    only: list[str] | tuple[str, ...] | None = None,
) -> tuple[list[Check], list[str]]:
    """Apply category aliases and check ids. Unknown tokens raise ConfigError."""
    from aws_health_audit.aws.errors import ConfigError

    checks = all_checks()
    known = {check.id: check.id for check in checks}
    disabled_categories, disabled_ids = _resolve(disabled, known)
    if only:
        only_categories, only_ids = _resolve(only, known)
    else:
        only_categories, only_ids = set(), set()

    selected: list[Check] = []
    skipped: list[str] = []
    for check in checks:
        dropped = check.category in disabled_categories or check.id in disabled_ids
        if only and check.category not in only_categories and check.id not in only_ids:
            dropped = True
        if dropped:
            skipped.append(check.id)
        else:
            selected.append(check)
    if not selected:
        raise ConfigError("No checks selected.")
    return selected, skipped


def run_audit(
    ctx: AuditContext,
    checks: list[Check],
    *,
    skipped: list[str],
    max_workers: int,
    progress: Callable[[str], None] | None = None,
) -> AuditReport:
    """Run every selected check. A failed check is recorded and does not stop the others."""
    announce = progress or (lambda _message: None)
    findings: list[Finding] = []
    errors: list[CheckError] = []
    tasks: list[tuple[Check, str | None]] = []
    for check in checks:
        if check.scope is Scope.GLOBAL:
            tasks.append((check, None))
        else:
            tasks.extend((check, region) for region in ctx.regions)

    workers = max(1, min(max_workers, len(tasks) or 1))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_run_one, check, region, ctx, announce) for check, region in tasks]
        for future in as_completed(futures):
            result = future.result()
            findings.extend(result.findings)
            errors.extend(result.errors)

    unique: dict[str, Finding] = {}
    for item in sort_findings(findings):
        unique.setdefault(item.id, item)
    return AuditReport(
        account_id=ctx.account_id,
        generated_at=utcnow(),
        regions=list(ctx.regions),
        findings=list(unique.values()),
        errors=sorted(errors, key=lambda item: (item.check_id, item.region or "", item.message)),
        tool_version=__version__,
        profile=ctx.profile,
        role_arn=ctx.role_arn,
        skipped_checks=list(skipped),
        ignored_resources=ctx.ignored_resources,
    )


def failure_exit_code(findings: list[Finding], fail_on: str) -> int:
    """Return 1 when a finding is at least as severe as fail_on."""
    if fail_on == "never":
        return 0
    limit = FAIL_RANK[fail_on]
    for item in findings:
        if SEVERITY_RANK[item.severity] <= limit:
            return 1
    return 0


def _run_one(
    check: Check,
    region: str | None,
    ctx: AuditContext,
    progress: Callable[[str], None],
) -> CheckResult:
    where = region or "global"
    progress(f"Running {check.id} ({where})")
    try:
        result = check.run(ctx, region)
    except AccessDeniedError as exc:
        return CheckResult([], [CheckError(check.id, region, "AccessDenied", str(exc))])
    except ThrottlingError as exc:
        return CheckResult([], [CheckError(check.id, region, "Throttling", str(exc))])
    except AwsClientError as exc:
        return CheckResult([], [CheckError(check.id, region, exc.code, str(exc))])
    except Exception as exc:
        logger.debug("check %s failed in %s", check.id, where, exc_info=True)
        return CheckResult([], [CheckError(check.id, region, "Unexpected", str(exc))])
    if isinstance(result, CheckResult):
        return result
    return CheckResult(list(result))


def _resolve(
    tokens: list[str] | tuple[str, ...],
    known: dict[str, str],
) -> tuple[set[Category], set[str]]:
    from aws_health_audit.aws.errors import ConfigError

    categories: set[Category] = set()
    ids: set[str] = set()
    lookup = {check_id.lower(): check_id for check_id in known}
    for token in tokens:
        key = token.strip()
        if not key:
            continue
        alias = CATEGORY_ALIASES.get(key.lower())
        if alias is not None:
            categories.add(alias)
            continue
        match = lookup.get(key.lower())
        if match is None:
            raise ConfigError(f"Unknown check or category: {token}")
        ids.add(match)
    return categories, ids
