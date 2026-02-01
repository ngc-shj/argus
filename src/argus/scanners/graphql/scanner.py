"""GraphQL introspection scanner."""

import asyncio
import time
from datetime import datetime
from urllib.parse import urljoin

import httpx

from argus.core.config import get_settings
from argus.core.logging import get_logger
from argus.models.graphql import (
    GraphQLResult,
    GraphQLEndpoint,
    GraphQLType,
    GraphQLField,
    GraphQLQuery,
    GraphQLMutation,
)


class GraphQLScanner:
    """Scanner for GraphQL endpoint discovery and introspection."""

    # Common GraphQL endpoint paths
    GRAPHQL_PATHS = [
        "/graphql",
        "/graphiql",
        "/gql",
        "/v1/graphql",
        "/v2/graphql",
        "/api/graphql",
        "/api/gql",
        "/query",
        "/graphql/v1",
        "/graphql/console",
        "/playground",
        "/altair",
        "/_graphql",
        "/graphql-explorer",
        "/api/v1/graphql",
        "/api/v2/graphql",
        "/data/graphql",
    ]

    # Introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            type {
              name
              kind
              ofType {
                name
                kind
              }
            }
            args {
              name
              type {
                name
                kind
              }
            }
            isDeprecated
          }
        }
      }
    }
    """

    # Simple query to detect GraphQL
    SIMPLE_QUERY = '{"query": "{ __typename }"}'

    # Sensitive field patterns
    SENSITIVE_PATTERNS = [
        "password", "secret", "token", "apikey", "api_key", "auth",
        "credential", "private", "ssn", "credit", "cvv", "pin",
        "email", "phone", "address", "dob", "birthdate", "salary",
        "bank", "account", "key", "cert", "session", "jwt",
    ]

    # Interesting mutation patterns
    INTERESTING_MUTATIONS = [
        "create", "update", "delete", "remove", "add", "set",
        "register", "login", "logout", "reset", "change", "upload",
        "admin", "execute", "run", "send", "transfer", "grant",
    ]

    def __init__(self) -> None:
        self.logger = get_logger("graphql_scanner")

    async def scan(self, target: str) -> GraphQLResult:
        """Scan target for GraphQL endpoints."""
        start_time = time.time()
        settings = get_settings()

        # Normalize URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info("graphql_scan_started", target=target)

        result = GraphQLResult(target=target)

        async with httpx.AsyncClient(
            timeout=settings.http_timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            # Probe for GraphQL endpoints
            tasks = [
                self._probe_endpoint(client, urljoin(target, path))
                for path in self.GRAPHQL_PATHS
            ]

            probe_results = await asyncio.gather(*tasks, return_exceptions=True)

            for probe_result in probe_results:
                if isinstance(probe_result, GraphQLEndpoint):
                    result.endpoints.append(probe_result)

            # Run introspection on discovered endpoints
            for endpoint in result.endpoints:
                if endpoint.introspection_enabled:
                    await self._run_introspection(client, endpoint, result)

        # Analyze schema
        self._analyze_schema(result)

        result.scanned_at = datetime.utcnow()
        duration = time.time() - start_time

        self.logger.info(
            "graphql_scan_completed",
            target=target,
            endpoints_found=len(result.endpoints),
            introspection_enabled=sum(1 for e in result.endpoints if e.introspection_enabled),
            duration=duration,
        )

        return result

    async def _probe_endpoint(
        self, client: httpx.AsyncClient, url: str
    ) -> GraphQLEndpoint | None:
        """Probe a URL to check if it's a GraphQL endpoint."""
        endpoint = GraphQLEndpoint(url=url)

        try:
            # Try POST with simple query
            response = await client.post(
                url,
                content=self.SIMPLE_QUERY,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if "data" in data or "errors" in data:
                        endpoint.exists = True
                        endpoint.method = "POST"

                        # Check if introspection is enabled
                        intro_response = await client.post(
                            url,
                            json={"query": self.INTROSPECTION_QUERY},
                            headers={"Content-Type": "application/json"},
                        )

                        if intro_response.status_code == 200:
                            intro_data = intro_response.json()
                            if "data" in intro_data and "__schema" in intro_data.get("data", {}):
                                endpoint.introspection_enabled = True
                                endpoint.schema_data = intro_data["data"]["__schema"]

                        return endpoint
                except Exception:
                    pass

            # Try GET
            response = await client.get(
                url,
                params={"query": "{ __typename }"},
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if "data" in data or "errors" in data:
                        endpoint.exists = True
                        endpoint.method = "GET"
                        return endpoint
                except Exception:
                    pass

        except Exception as e:
            self.logger.debug("graphql_probe_failed", url=url, error=str(e))

        return None

    async def _run_introspection(
        self,
        client: httpx.AsyncClient,
        endpoint: GraphQLEndpoint,
        result: GraphQLResult,
    ) -> None:
        """Run full introspection on an endpoint."""
        if not endpoint.schema_data:
            return

        schema = endpoint.schema_data

        # Extract types
        types_data = schema.get("types", [])
        for type_data in types_data:
            name = type_data.get("name", "")

            # Skip internal types
            if name.startswith("__"):
                continue

            kind = type_data.get("kind", "")
            description = type_data.get("description")

            type_obj = GraphQLType(
                name=name,
                kind=kind,
                description=description,
            )

            # Extract fields
            fields_data = type_data.get("fields") or []
            for field_data in fields_data:
                field_name = field_data.get("name", "")
                field_type = field_data.get("type", {})

                type_name = self._get_type_name(field_type)

                # Check if sensitive
                is_sensitive = any(
                    pattern in field_name.lower()
                    for pattern in self.SENSITIVE_PATTERNS
                )

                args = [arg.get("name", "") for arg in field_data.get("args", [])]

                field_obj = GraphQLField(
                    name=field_name,
                    type_name=type_name,
                    description=field_data.get("description"),
                    is_deprecated=field_data.get("isDeprecated", False),
                    arguments=args,
                    is_sensitive=is_sensitive,
                )

                type_obj.fields.append(field_obj)

            # Categorize type
            if kind == "OBJECT":
                result.types.append(type_obj)

        # Extract queries
        query_type_name = schema.get("queryType", {}).get("name")
        if query_type_name:
            for type_obj in result.types:
                if type_obj.name == query_type_name:
                    for field in type_obj.fields:
                        result.queries.append(GraphQLQuery(
                            name=field.name,
                            return_type=field.type_name,
                            arguments=field.arguments,
                            description=field.description,
                        ))
                    break

        # Extract mutations
        mutation_type_name = schema.get("mutationType", {}).get("name")
        if mutation_type_name:
            for type_obj in result.types:
                if type_obj.name == mutation_type_name:
                    for field in type_obj.fields:
                        # Check if interesting mutation
                        is_dangerous = any(
                            pattern in field.name.lower()
                            for pattern in self.INTERESTING_MUTATIONS
                        )

                        result.mutations.append(GraphQLMutation(
                            name=field.name,
                            return_type=field.type_name,
                            arguments=field.arguments,
                            description=field.description,
                            is_dangerous=is_dangerous,
                        ))
                    break

    def _get_type_name(self, type_data: dict) -> str:
        """Extract type name from GraphQL type object."""
        kind = type_data.get("kind", "")
        name = type_data.get("name")

        if name:
            return name

        of_type = type_data.get("ofType")
        if of_type:
            inner = self._get_type_name(of_type)
            if kind == "NON_NULL":
                return f"{inner}!"
            elif kind == "LIST":
                return f"[{inner}]"
            return inner

        return "Unknown"

    def _analyze_schema(self, result: GraphQLResult) -> None:
        """Analyze schema for security issues."""
        # Find sensitive fields
        for type_obj in result.types:
            for field in type_obj.fields:
                if field.is_sensitive:
                    result.sensitive_fields.append(f"{type_obj.name}.{field.name}")

        # Find dangerous mutations
        for mutation in result.mutations:
            if mutation.is_dangerous:
                result.dangerous_mutations.append(mutation.name)

        # Determine security issues
        for endpoint in result.endpoints:
            if endpoint.introspection_enabled:
                result.security_issues.append(
                    f"Introspection enabled at {endpoint.url} - may expose schema"
                )

        if result.sensitive_fields:
            result.security_issues.append(
                f"Found {len(result.sensitive_fields)} potentially sensitive fields"
            )

        if result.dangerous_mutations:
            result.security_issues.append(
                f"Found {len(result.dangerous_mutations)} potentially dangerous mutations"
            )
