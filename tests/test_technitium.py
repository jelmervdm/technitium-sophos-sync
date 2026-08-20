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

    mock_leases_response = {
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

    mock_scopes_list_response = {
        "status": "ok",
        "response": {
            "scopes": [
                {
                    "name": "LAN Scope",
                    "enabled": True,
                }
            ]
        },
    }

    mock_scope_detail_response = {
        "status": "ok",
        "response": {
            "name": "LAN Scope",
            "reservedLeases": [
                {
                    "hostName": "offline-static-server",
                    "address": "192.168.1.200",
                    "hardwareAddress": "11-22-33-44-55-66",
                }
            ],
        },
    }

    respx.get("http://technitium.local:5380/api/dhcp/leases/list").mock(
        return_value=Response(200, json=mock_leases_response)
    )
    respx.get("http://technitium.local:5380/api/dhcp/scopes/list").mock(
        return_value=Response(200, json=mock_scopes_list_response)
    )
    respx.get("http://technitium.local:5380/api/dhcp/scopes/get").mock(
        return_value=Response(200, json=mock_scope_detail_response)
    )

    leases = client.get_dhcp_leases(static_leases_only=False)
    assert len(leases) == 3
    assert leases[0] == DHCPLease(
        name="desktop-pc",
        ip="192.168.1.50",
        mac="00-11-22-33-44-55",
        is_reserved=True,
    )
    assert leases[1].is_reserved is False
    assert leases[2] == DHCPLease(
        name="offline-static-server",
        ip="192.168.1.200",
        mac="11-22-33-44-55-66",
        is_reserved=True,
    )


@respx.mock
def test_get_dhcp_leases_static_only() -> None:
    """Test filtering static/reserved leases."""
    client = TechnitiumClient(base_url="http://technitium.local:5380", token="secret_token")

    mock_leases_response = {
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

    mock_scopes_list_response = {
        "status": "ok",
        "response": {
            "scopes": [
                {
                    "name": "LAN Scope",
                }
            ]
        },
    }

    mock_scope_detail_response = {
        "status": "ok",
        "response": {
            "name": "LAN Scope",
            "reservedLeases": [
                {
                    "hostName": "offline-static-nas",
                    "address": "192.168.1.20",
                    "hardwareAddress": "77-88-99",
                }
            ],
        },
    }

    respx.get("http://technitium.local:5380/api/dhcp/leases/list").mock(
        return_value=Response(200, json=mock_leases_response)
    )
    respx.get("http://technitium.local:5380/api/dhcp/scopes/list").mock(
        return_value=Response(200, json=mock_scopes_list_response)
    )
    respx.get("http://technitium.local:5380/api/dhcp/scopes/get").mock(
        return_value=Response(200, json=mock_scope_detail_response)
    )

    leases = client.get_dhcp_leases(static_leases_only=True)
    assert len(leases) == 2
    names = {lease.name for lease in leases}
    assert names == {"server1", "offline-static-nas"}


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


@respx.mock
def test_get_dhcp_scope_reservations_with_empty_reserved_leases_in_list() -> None:
    """Test fetching scope reservations when scopes/list returns empty reservedLeases list."""
    client = TechnitiumClient(base_url="http://technitium.local:5380", token="secret_token")

    mock_scopes_list_response = {
        "status": "ok",
        "response": {
            "scopes": [
                {
                    "name": "Scope_10_50",
                    "reservedLeases": [],
                }
            ]
        },
    }

    mock_scope_detail_response = {
        "status": "ok",
        "response": {
            "name": "Scope_10_50",
            "reservedLeases": [
                {
                    "hostName": "MacBookAir_guest",
                    "address": "10.50.1.4",
                    "hardwareAddress": "AA-BB-CC-DD-EE-FF",
                }
            ],
        },
    }

    respx.get("http://technitium.local:5380/api/dhcp/scopes/list").mock(
        return_value=Response(200, json=mock_scopes_list_response)
    )
    respx.get("http://technitium.local:5380/api/dhcp/scopes/get").mock(
        return_value=Response(200, json=mock_scope_detail_response)
    )

    reservations = client.get_dhcp_scope_reservations()
    assert len(reservations) == 1
    assert reservations[0] == DHCPLease(
        name="MacBookAir_guest",
        ip="10.50.1.4",
        mac="AA-BB-CC-DD-EE-FF",
        is_reserved=True,
    )



