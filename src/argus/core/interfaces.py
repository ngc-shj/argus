"""Abstract interfaces for scanner modules and AI providers."""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

# Type variable for scanner results
TResult = TypeVar("TResult", bound=BaseModel)


class ScanTarget(BaseModel):
    """Target specification for scanning."""

    domain: str | None = None
    ip_address: str | None = None

    @property
    def identifier(self) -> str:
        """Return primary target identifier."""
        return self.domain or self.ip_address or "unknown"


class ScanOptions(BaseModel):
    """Base scan options."""

    timeout_seconds: int = 30
    max_concurrent: int = 50


class IScanner(ABC, Generic[TResult]):
    """Base interface for all scanner modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner module name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        ...

    @abstractmethod
    async def scan(
        self,
        target: ScanTarget,
        options: ScanOptions | None = None,
    ) -> TResult:
        """Execute the scan and return results."""
        ...

    @abstractmethod
    async def validate_target(self, target: ScanTarget) -> bool:
        """Check if this scanner can handle the target."""
        ...

    @abstractmethod
    def get_capabilities(self) -> list[str]:
        """List of capabilities this scanner provides."""
        ...


class IAIProvider(ABC):
    """Interface for AI analysis providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        ...

    @abstractmethod
    async def analyze(
        self,
        scan_results: dict[str, Any],
        prompt_template: str,
    ) -> str:
        """Run AI analysis on scan results."""
        ...

    @abstractmethod
    async def summarize(self, text: str, max_length: int = 500) -> str:
        """Generate a summary of the provided text."""
        ...

    @abstractmethod
    async def assess_risk(
        self,
        scan_results: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess security risks from scan results."""
        ...


class ICache(ABC):
    """Caching interface."""

    @abstractmethod
    async def get(self, key: str) -> Any | None:
        """Get value from cache."""
        ...

    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Set value in cache with TTL."""
        ...

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete value from cache."""
        ...

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        ...


class IEventEmitter(ABC):
    """Event emitter for real-time updates."""

    @abstractmethod
    async def emit(self, event: str, data: dict[str, Any]) -> None:
        """Emit an event with data."""
        ...

    @abstractmethod
    def subscribe(
        self,
        event: str,
        handler: Any,
    ) -> None:
        """Subscribe to an event."""
        ...

    @abstractmethod
    def unsubscribe(
        self,
        event: str,
        handler: Any,
    ) -> None:
        """Unsubscribe from an event."""
        ...
