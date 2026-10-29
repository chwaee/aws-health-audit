"""Call boto3 and always walk every page."""

from collections.abc import Iterator
from typing import Any

from botocore.exceptions import ClientError

from aws_health_audit.aws.errors import AccessDeniedError, AwsClientError, ThrottlingError

ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "NotAuthorized",
    "AuthorizationError",
    "Forbidden",
}

THROTTLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
    "PriorRequestNotComplete",
}


def map_client_error(
    exc: ClientError, *, missing_ok: frozenset[str] = frozenset()
) -> Exception | None:
    """Turn a ClientError into an audit error. None means the caller treats it as empty."""
    error = exc.response.get("Error", {})
    code = str(error.get("Code", "ClientError"))
    message = str(error.get("Message", str(exc)))
    if code in missing_ok:
        return None
    if code in ACCESS_DENIED_CODES or "AccessDenied" in code or code.startswith("Unauthorized"):
        return AccessDeniedError(message, code)
    if code in THROTTLE_CODES or "Throttl" in code:
        return ThrottlingError(message, code)
    return AwsClientError(message, code)


def call(
    client: Any,
    operation: str,
    *,
    missing_ok: tuple[str, ...] | frozenset[str] = (),
    **kwargs: Any,
) -> dict[str, Any] | None:
    """Invoke one boto3 operation and normalize its errors."""
    method = getattr(client, operation)
    try:
        result = method(**kwargs)
    except ClientError as exc:
        mapped = map_client_error(exc, missing_ok=frozenset(missing_ok))
        if mapped is None:
            return None
        raise mapped from exc
    return result


def paginate(client: Any, operation: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
    """Yield every page from a botocore paginator, or from NextToken/Marker."""
    if _can_paginate(client, operation):
        paginator = client.get_paginator(operation)
        try:
            yield from paginator.paginate(**kwargs)
        except ClientError as exc:
            mapped = map_client_error(exc)
            if mapped is not None:
                raise mapped from exc
        return

    request = dict(kwargs)
    while True:
        page = call(client, operation, **request)
        if not page:
            return
        yield page
        token = page.get("NextToken")
        marker = page.get("Marker")
        if token:
            request["NextToken"] = token
            continue
        if marker:
            request["Marker"] = marker
            continue
        return


def collect(client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
    """Collect one result list across every page."""
    items: list[Any] = []
    for page in paginate(client, operation, **kwargs):
        items.extend(page.get(key, []))
    return items


def _can_paginate(client: Any, operation: str) -> bool:
    probe = getattr(client, "can_paginate", None)
    if probe is None:
        return False
    try:
        return bool(probe(operation))
    except Exception:
        return False
