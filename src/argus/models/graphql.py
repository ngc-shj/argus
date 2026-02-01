"""GraphQL scanning models."""

from datetime import datetime
from typing import Any

from pydantic import Field

from argus.models.base import BaseSchema


class GraphQLEndpoint(BaseSchema):
    """Discovered GraphQL endpoint."""

    url: str
    exists: bool = False
    method: str | None = None  # GET or POST
    introspection_enabled: bool = False
    schema_data: dict[str, Any] | None = None


class GraphQLField(BaseSchema):
    """GraphQL type field."""

    name: str
    type_name: str
    description: str | None = None
    is_deprecated: bool = False
    arguments: list[str] = Field(default_factory=list)
    is_sensitive: bool = False


class GraphQLType(BaseSchema):
    """GraphQL type."""

    name: str
    kind: str  # OBJECT, INPUT_OBJECT, ENUM, etc.
    description: str | None = None
    fields: list[GraphQLField] = Field(default_factory=list)


class GraphQLQuery(BaseSchema):
    """GraphQL query."""

    name: str
    return_type: str
    arguments: list[str] = Field(default_factory=list)
    description: str | None = None


class GraphQLMutation(BaseSchema):
    """GraphQL mutation."""

    name: str
    return_type: str
    arguments: list[str] = Field(default_factory=list)
    description: str | None = None
    is_dangerous: bool = False


class GraphQLResult(BaseSchema):
    """Complete GraphQL scan result."""

    target: str

    # Discovered endpoints
    endpoints: list[GraphQLEndpoint] = Field(default_factory=list)

    # Schema analysis
    types: list[GraphQLType] = Field(default_factory=list)
    queries: list[GraphQLQuery] = Field(default_factory=list)
    mutations: list[GraphQLMutation] = Field(default_factory=list)

    # Security findings
    sensitive_fields: list[str] = Field(default_factory=list)
    dangerous_mutations: list[str] = Field(default_factory=list)
    security_issues: list[str] = Field(default_factory=list)

    scanned_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def has_introspection(self) -> bool:
        """Check if any endpoint has introspection enabled."""
        return any(e.introspection_enabled for e in self.endpoints)

    @property
    def total_types(self) -> int:
        return len(self.types)

    @property
    def total_queries(self) -> int:
        return len(self.queries)

    @property
    def total_mutations(self) -> int:
        return len(self.mutations)
