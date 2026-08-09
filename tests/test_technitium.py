"""Unit tests for Technitium API client."""

import pytest
import respx
from httpx import Response

from technitium_sophos_sync.technitium import (
    DHCPLease,
    TechnitiumClient,
    TechnitiumClientError,
)


def test_sanitize_hostname() -> None:
    """Test hostname cleaning rules for Sophos XML compliance."""
    res = TechnitiumClient.sanitize_hostname("laptop-john.local", "00-11-22-33-44-55")
    assert res == "laptop-john_local"
    assert TechnitiumClient.sanitize_hostname("My Device!@#$", "00:11:22") == "My_Device____"
    assert TechnitiumClient.sanitize_hostname("", "AA-BB-CC-DD-EE-FF") == "Device_AABBCCDDEEFF"
    assert TechnitiumClient.sanitize_hostname(None, None) == "Device_Unknown"
    # Truncation test
    long_name = "a" * 100
    assert len(TechnitiumClient.sanitize_hostname(long_name, None)) == 60


@respx.mock
def test_get_dhcp_leases_success() -> None:
    """Test successful fetching and parsing of DHCP leases."""
    client = TechnitiumClient(base_url="http://technitium.local:5380", token="secret_token")

    mock_response = {
        "status": "ok",
        "response": {
            "leases": [
                {
                    "hostName": "desktop-pc",
                    "ipAddress": "192.168.1.50",
                    "macAddress": "00-11-22-33-44-55",
                    "isReserved": True,
                },
                {
                    "hostName": "phone-guest",
                    "ipAddress": "192.168.1.101",
                    "macAddress": "AA-BB-CC-DD-EE-FF",
                    "isReserved": False,
                },
            ]
        },
    }

    respx.get("http://technitium.local:5380/api/dhcp/leases/list").mock(
        return_value=Response(200, json=mock_response)
    )

    leases = client.get_dhcp_leases(static_leases_only=False)
    assert len(leases) == 2
    assert leases[0] == DHCPLease(
        name="desktop-pc",
        ip="192.168.1.50",
        mac="00-11-22-33-44-55",
        is_reserved=True,
    )
    assert leases[1].is_reserved is False


@respx.mock
def test_get_dhcp_leases_static_only() -> None:
    """Test filtering static/reserved leases."""
    client = TechnitiumClient(base_url="http://technitium.local:5380", token="secret_token")

    mock_response = {
        "status": "ok",
        "response": {
            "leases": [
                {
                    "hostName": "server1",
                    "ipAddress": "192.168.1.10",
                    "macAddress": "11-22-33",
                    "isReserved": True,
                },
                {
                    "hostName": "guest-phone",
                    "ipAddress": "192.168.1.102",
                    "macAddress": "44-55-66",
                    "isReserved": False,
                },
            ]
        },
    }

    respx.get("http://technitium.local:5380/api/dhcp/leases/list").mock(
        return_value=Response(200, json=mock_response)
    )

    leases = client.get_dhcp_leases(static_leases_only=True)
    assert len(leases) == 1
    assert leases[0].name == "server1"


@respx.mock
def test_get_dhcp_leases_api_error() -> None:
    """Test handling API error status from Technitium."""
    client = TechnitiumClient(base_url="http://technitium.local:5380", token="invalid_token")

    mock_response = {"status": "error", "errorMessage": "Invalid authentication token"}

    respx.get("http://technitium.local:5380/api/dhcp/leases/list").mock(
        return_value=Response(200, json=mock_response)
    )

    with pytest.raises(TechnitiumClientError, match="Invalid authentication token"):
        client.get_dhcp_leases()
