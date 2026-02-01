"""CLI output formatters."""

from argus.cli.formatters.table import format_scan_result
from argus.cli.formatters.json_fmt import format_json

__all__ = ["format_scan_result", "format_json"]
