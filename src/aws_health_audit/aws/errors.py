"""Errors that either stop the audit or become a line in the report."""


class ConfigError(Exception):
    """The config file or CLI selection cannot be used. Exit 2."""


class CredentialsError(Exception):
    """AWS credentials or assume-role failed before checks started. Exit 2."""


class AccessDeniedError(Exception):
    """The check is missing an IAM permission. The audit continues."""

    def __init__(self, message: str, code: str = "AccessDenied") -> None:
        super().__init__(message)
        self.code = code


class ThrottlingError(Exception):
    """Retries were exhausted. The audit continues."""

    def __init__(self, message: str, code: str = "Throttling") -> None:
        super().__init__(message)
        self.code = code


class AwsClientError(Exception):
    """Any other AWS client error. The audit continues."""

    def __init__(self, message: str, code: str = "ClientError") -> None:
        super().__init__(message)
        self.code = code
