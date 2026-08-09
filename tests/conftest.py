"""Pytest configuration and global test fixtures."""

import pytest
from pydantic import SecretStr

from technitium_sophos_sync.config import Settings


@pytest.fixture
def mock_settings() -> Settings:
    """Fixture providing test settings."""
    return Settings(
        technitium_url="http://technitium.test:5380",
        technitium_token=SecretStr("test_tech_token"),
        sophos_firewall_ip="192.168.1.254",
        sophos_firewall_port=4444,
        sophos_user="admin",
        sophos_pass=SecretStr("test_sophos_pass"),
        sophos_clientless_group="Test Group",
        sophos_verify_ssl=False,
        dry_run=False,
    )
