"""Base scanner class."""

from abc import abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel

from argus.core.interfaces import IScanner
from argus.core.logging import get_logger
from argus.models import ScanTarget, ScanOptions

TResult = TypeVar("TResult", bound=BaseModel)


class BaseScanner(IScanner[TResult], Generic[TResult]):
    """Base class for all scanner implementations."""

    def __init__(self) -> None:
        self.logger = get_logger(self.name)

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

    async def validate_target(self, target: ScanTarget) -> bool:
        """Check if this scanner can handle the target."""
        return target.domain is not None or target.ip_address is not None

    def get_capabilities(self) -> list[str]:
        """List of capabilities this scanner provides."""
        return []
