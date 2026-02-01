"""SQLModel ORM models for database storage."""

import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlmodel import Column, Field, SQLModel, Text


class ScanRecord(SQLModel, table=True):
    """Database model for storing scan sessions."""

    __tablename__ = "scans"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    target_domain: str | None = Field(default=None, index=True)
    target_ip: str | None = Field(default=None, index=True)
    status: str = Field(default="pending", index=True)

    # Store complex data as JSON
    options_json: str = Field(default="{}", sa_column=Column(Text))
    results_json: str = Field(default="{}", sa_column=Column(Text))

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Errors stored as JSON array
    errors_json: str = Field(default="[]", sa_column=Column(Text))

    @property
    def target_identifier(self) -> str:
        """Get the target identifier."""
        return self.target_domain or self.target_ip or "unknown"

    @property
    def duration_seconds(self) -> float | None:
        """Calculate scan duration."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def options(self) -> dict[str, Any]:
        """Parse options from JSON."""
        return json.loads(self.options_json)

    @options.setter
    def options(self, value: dict[str, Any]) -> None:
        """Store options as JSON."""
        self.options_json = json.dumps(value, default=str)

    @property
    def results(self) -> dict[str, Any]:
        """Parse results from JSON."""
        return json.loads(self.results_json)

    @results.setter
    def results(self, value: dict[str, Any]) -> None:
        """Store results as JSON."""
        self.results_json = json.dumps(value, default=str)

    @property
    def errors(self) -> list[str]:
        """Parse errors from JSON."""
        return json.loads(self.errors_json)

    @errors.setter
    def errors(self, value: list[str]) -> None:
        """Store errors as JSON."""
        self.errors_json = json.dumps(value)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "target": self.target_identifier,
            "target_domain": self.target_domain,
            "target_ip": self.target_ip,
            "status": self.status,
            "options": self.options,
            "results": self.results,
            "errors": self.errors,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
        }
