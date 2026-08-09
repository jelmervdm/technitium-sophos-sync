"""Unit tests for Sophos Firewall API client."""

from urllib.parse import unquote

import pytest
import respx
from httpx import Response

from technitium_sophos_sync.sophos import SophosClient, SophosClientError


@respx.mock
def test_get_existing_clientless_users_success() -> None:
    """Test retrieving existing Clientless Users from Sophos XML API."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        port=4444,
        username="admin",
        password="secretpassword",
        verify_ssl=False,
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <ClientlessUser>
        <UserName>desktop_pc</UserName>
        <IPAddress>192.168.1.50</IPAddress>
    </ClientlessUser>
    <ClientlessUser>
        <UserName>printer_office</UserName>
        <IPAddress>192.168.1.200</IPAddress>
    </ClientlessUser>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    users = client.get_existing_clientless_users()
    assert len(users) == 2
    assert users["desktop_pc"] == "192.168.1.50"
    assert users["printer_office"] == "192.168.1.200"


@respx.mock
def test_get_existing_clientless_users_auth_failure() -> None:
    """Test handling authentication failure from Sophos Firewall."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="wrong_password",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Failure</status>
    </Login>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    with pytest.raises(SophosClientError, match="authentication failed"):
        client.get_existing_clientless_users()


@respx.mock
def test_upsert_clientless_user_auth_failure() -> None:
    """Test handling authentication failure during upsert."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="wrong_password",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Failure</status>
    </Login>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    with pytest.raises(SophosClientError, match="authentication failed"):
        client.upsert_clientless_user("test_user", "192.168.1.50")



@respx.mock
def test_upsert_clientless_user_success() -> None:
    """Test upserting a Clientless User."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="secretpassword",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <ClientlessUser transactionid="">
        <Status>200</Status>
    </ClientlessUser>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    result = client.upsert_clientless_user(name="new_device", ip="192.168.1.80")
    assert result is True


@respx.mock
def test_sophos_custom_api_version() -> None:
    """Test custom API version parameter in XML payload."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="secretpassword",
        api_version="2100.1",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2100.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
</Response>"""

    route = respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    client.get_existing_clientless_users()
    assert route.called
    req_body = unquote(route.calls.last.request.content.decode("utf-8"))
    assert 'APIVersion="2100.1"' in req_body

