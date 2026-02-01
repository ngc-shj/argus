"""JSON formatter for CLI output."""

import json
from typing import Any

from rich.console import Console

from argus.models import ScanSession


def format_json(console: Console, result: ScanSession) -> None:
    """Format and display scan results as JSON."""
    console.print_json(result.model_dump_json(indent=2))


def export_json(result: ScanSession, path: str) -> None:
    """Export scan results to a JSON file."""
    with open(path, "w") as f:
        json.dump(result.model_dump(mode="json"), f, indent=2, default=str)


def to_dict(result: ScanSession) -> dict[str, Any]:
    """Convert scan results to a dictionary."""
    return result.model_dump(mode="json")
