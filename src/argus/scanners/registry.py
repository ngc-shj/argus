"""Scanner plugin registry."""

from typing import Any

from argus.scanners.base import BaseScanner


class ScannerRegistry:
    """Registry for scanner plugins."""

    _scanners: dict[str, type[BaseScanner[Any]]] = {}

    @classmethod
    def register(cls, scanner_class: type[BaseScanner[Any]]) -> type[BaseScanner[Any]]:
        """Register a scanner class."""
        # Create instance to get name
        instance = scanner_class()
        cls._scanners[instance.name] = scanner_class
        return scanner_class

    @classmethod
    def get(cls, name: str) -> type[BaseScanner[Any]] | None:
        """Get a scanner class by name."""
        return cls._scanners.get(name)

    @classmethod
    def get_instance(cls, name: str) -> BaseScanner[Any] | None:
        """Get a scanner instance by name."""
        scanner_class = cls.get(name)
        if scanner_class:
            return scanner_class()
        return None

    @classmethod
    def list_all(cls) -> list[str]:
        """List all registered scanner names."""
        return list(cls._scanners.keys())

    @classmethod
    def get_all_instances(cls) -> list[BaseScanner[Any]]:
        """Get instances of all registered scanners."""
        return [scanner_class() for scanner_class in cls._scanners.values()]
