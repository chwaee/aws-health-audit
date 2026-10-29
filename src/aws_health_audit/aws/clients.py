"""Thread-safe boto3 client cache and retry settings."""

import threading
from typing import Any

from boto3.session import Session
from botocore.config import Config

RETRY_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


class ClientFactory:
    """Create one client per service and region and reuse it."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._lock = threading.Lock()
        self._clients: dict[tuple[str, str], Any] = {}

    def client(self, service: str, region: str | None = None) -> Any:
        """Return a cached client. Global services should pass us-east-1."""
        chosen = region or self._session.region_name or "us-east-1"
        key = (service, chosen)
        with self._lock:
            existing = self._clients.get(key)
            if existing is None:
                existing = self._session.client(service, region_name=chosen, config=RETRY_CONFIG)
                self._clients[key] = existing
            return existing
