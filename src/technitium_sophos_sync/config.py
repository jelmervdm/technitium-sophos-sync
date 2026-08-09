"""Configuration management for Technitium to Sophos sync."""

from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Technitium Settings
    technitium_ip: str | None = Field(
        default=None,
        validation_alias=AliasChoices("TECHNITIUM_IP", "TECHNITIUM_HOST"),
        description="Technitium Server IP Address or Hostname",
    )
    technitium_port: int = Field(
        default=5380,
        validation_alias=AliasChoices("TECHNITIUM_PORT"),
        description="Technitium Server Web Interface Port",
    )
    technitium_url: str = Field(
        default="",
        validation_alias=AliasChoices("TECHNITIUM_URL"),
        description="Technitium Web Interface URL (including scheme and port, overrides IP/Port)",
    )
    technitium_token: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("TECHNITIUM_TOKEN", "TECHNITIUM_API_KEY", "TECHNITIUM_KEY"),
        description="Technitium API Token or Key",
    )
    technitium_timeout: float = Field(
        default=10.0,
        description="HTTP request timeout for Technitium API calls in seconds",
    )

    # Sophos Firewall Settings
    sophos_firewall_ip: str = Field(
        default="192.168.1.1",
        validation_alias=AliasChoices("SOPHOS_FIREWALL_IP", "SOPHOS_IP", "SOPHOS_HOST"),
        description="Sophos Firewall Management IP or Hostname",
    )
    sophos_firewall_port: int = Field(
        default=4444,
        validation_alias=AliasChoices("SOPHOS_FIREWALL_PORT", "SOPHOS_PORT"),
        description="Sophos Admin Web Console API Port",
    )
    sophos_user: str = Field(
        default="admin",
        validation_alias=AliasChoices("SOPHOS_USER", "SOPHOS_LOGIN", "SOPHOS_USERNAME"),
        description="Sophos Firewall API Admin Username / Login",
    )
    sophos_pass: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("SOPHOS_PASS", "SOPHOS_PASSWORD"),
        description="Sophos Firewall API Admin Password",
    )
    sophos_clientless_group: str = Field(
        default="Clientless Open Group",
        description="Sophos Clientless Group Name for synced users",
    )
    sophos_api_version: str = Field(
        default="2200.1",
        validation_alias=AliasChoices("SOPHOS_API_VERSION"),
        description="Sophos Firewall XML API Version",
    )
    sophos_verify_ssl: bool = Field(
        default=False,
        description="Verify SSL certificates when calling Sophos Firewall API",
    )
    sophos_timeout: float = Field(
        default=15.0,
        description="HTTP request timeout for Sophos Firewall API calls in seconds",
    )

    @model_validator(mode="after")
    def _resolve_urls(self) -> "Settings":
        if not self.technitium_url:
            ip = self.technitium_ip or "192.168.1.10"
            self.technitium_url = f"http://{ip}:{self.technitium_port}"
        return self

    # Sync Options
    static_leases_only: bool = Field(
        default=False,
        description="Sync reserved/static leases only if set to True",
    )
    sync_interval: int = Field(
        default=0,
        description="Sync interval in seconds for daemon mode (0 for one-shot)",
    )
    dry_run: bool = Field(
        default=False,
        description="If True, log changes without executing API calls against Sophos Firewall",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging verbosity level",
    )

    @property
    def sophos_api_url(self) -> str:
        """Construct full Sophos API endpoint URL."""
        return f"https://{self.sophos_firewall_ip}:{self.sophos_firewall_port}/webconsole/APIController"
