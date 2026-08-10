import pytest
from pydantic import SecretStr

from technitium_sophos_sync.config import Settings


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test default values for Settings."""
    monkeypatch.delenv("TECHNITIUM_URL", raising=False)
    monkeypatch.delenv("TECHNITIUM_IP", raising=False)
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        technitium_token=SecretStr("token"),
        sophos_pass=SecretStr("pass"),
    )
    assert settings.technitium_url == "http://192.168.1.10:5380"
    assert settings.sophos_firewall_ip == "192.168.1.1"
    assert settings.sophos_firewall_port == 4444
    assert settings.sophos_user == "admin"
    assert settings.sophos_clientless_group == "Clientless Open Group"
    assert settings.static_leases_only is False
    assert settings.dry_run is False
    assert settings.max_consecutive_failures == 3
    assert settings.exit_on_auth_failure is True
    assert settings.mac_disambiguation == "duplicates_only"
    assert settings.log_level == "INFO"
    assert settings.sophos_api_url == "https://192.168.1.1:4444/webconsole/APIController"


def test_settings_custom_values() -> None:
    """Test custom configuration values."""
    settings = Settings(
        technitium_url="https://dns.example.com",
        technitium_token=SecretStr("mytoken"),
        sophos_firewall_ip="10.0.0.1",
        sophos_firewall_port=8443,
        sophos_pass=SecretStr("secret"),
        static_leases_only=True,
        dry_run=True,
        max_consecutive_failures=5,
        exit_on_auth_failure=False,
        mac_disambiguation="always",
    )
    assert settings.technitium_url == "https://dns.example.com"
    assert settings.sophos_api_url == "https://10.0.0.1:8443/webconsole/APIController"
    assert settings.static_leases_only is True
    assert settings.dry_run is True
    assert settings.max_consecutive_failures == 5
    assert settings.exit_on_auth_failure is False
    assert settings.mac_disambiguation == "always"


def test_settings_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test environment variable aliases like TECHNITIUM_IP, SOPHOS_LOGIN, etc."""
    monkeypatch.delenv("TECHNITIUM_URL", raising=False)
    monkeypatch.setenv("TECHNITIUM_IP", "10.0.1.5")
    monkeypatch.setenv("TECHNITIUM_PORT", "5380")
    monkeypatch.setenv("TECHNITIUM_API_KEY", "key123")
    monkeypatch.setenv("SOPHOS_IP", "10.0.1.1")
    monkeypatch.setenv("SOPHOS_PORT", "8443")
    monkeypatch.setenv("SOPHOS_LOGIN", "secadmin")
    monkeypatch.setenv("SOPHOS_PASSWORD", "secpass")
    monkeypatch.setenv("MAC_SUFFIX_MODE", "off")

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.technitium_url == "http://10.0.1.5:5380"
    assert settings.technitium_token.get_secret_value() == "key123"
    assert settings.sophos_firewall_ip == "10.0.1.1"
    assert settings.sophos_firewall_port == 8443
    assert settings.sophos_user == "secadmin"
    assert settings.sophos_pass.get_secret_value() == "secpass"
    assert settings.sophos_api_url == "https://10.0.1.1:8443/webconsole/APIController"
    assert settings.mac_disambiguation == "off"
