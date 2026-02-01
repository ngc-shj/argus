"""Configuration management using pydantic-settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # AI Provider API Keys
    anthropic_api_key: SecretStr | None = Field(default=None)
    openai_api_key: SecretStr | None = Field(default=None)

    # Ollama Configuration
    ollama_host: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="gpt-oss:20b")

    # Database
    database_url: str = Field(default="sqlite+aiosqlite:///./argus.db")

    # API Configuration
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_key: SecretStr | None = Field(default=None)

    # Scan Configuration
    max_concurrent_scans: int = Field(default=5, ge=1, le=50)
    dns_timeout: int = Field(default=10, ge=1, le=60)
    port_scan_timeout: int = Field(default=5, ge=1, le=30)
    http_timeout: int = Field(default=30, ge=1, le=120)

    # Rate Limiting
    dns_queries_per_second: int = Field(default=50, ge=1, le=500)
    whois_queries_per_minute: int = Field(default=10, ge=1, le=60)
    port_scans_per_second: int = Field(default=100, ge=1, le=1000)

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )
    log_format: Literal["json", "text"] = Field(default="json")

    # CORS Configuration (set CORS_ORIGINS env var, comma-separated)
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        description="Allowed CORS origins. Set to ['*'] for development only.",
    )
    cors_allow_credentials: bool = Field(default=True)

    # Default AI Provider
    default_ai_provider: Literal["anthropic", "openai", "ollama"] = Field(
        default="anthropic"
    )

    def get_anthropic_key(self) -> str | None:
        """Get Anthropic API key value."""
        if self.anthropic_api_key:
            return self.anthropic_api_key.get_secret_value()
        return None

    def get_openai_key(self) -> str | None:
        """Get OpenAI API key value."""
        if self.openai_api_key:
            return self.openai_api_key.get_secret_value()
        return None

    def get_api_key(self) -> str | None:
        """Get API authentication key value."""
        if self.api_key:
            return self.api_key.get_secret_value()
        return None


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
