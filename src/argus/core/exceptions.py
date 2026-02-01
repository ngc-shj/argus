"""Custom exceptions for Argus."""


class ArgusError(Exception):
    """Base exception for all Argus errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationError(ArgusError):
    """Raised when input validation fails."""

    pass


class ScanError(ArgusError):
    """Raised when a scan operation fails."""

    def __init__(
        self,
        message: str,
        scanner: str | None = None,
        target: str | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.scanner = scanner
        self.target = target


class RateLimitError(ArgusError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        retry_after: float | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.retry_after = retry_after


class AIProviderError(ArgusError):
    """Raised when AI provider operations fail."""

    def __init__(
        self,
        message: str,
        provider: str | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.provider = provider


class NetworkError(ArgusError):
    """Raised when network operations fail."""

    pass


class TimeoutError(ArgusError):
    """Raised when an operation times out."""

    pass


class ConfigurationError(ArgusError):
    """Raised when configuration is invalid."""

    pass
