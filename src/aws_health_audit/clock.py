"""Clock helpers so tests can pin the audit time."""

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current time in UTC."""
    return datetime.now(UTC)


def utc_iso(value: datetime) -> str:
    """Format a timestamp as UTC ISO-8601 with a Z suffix."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")
