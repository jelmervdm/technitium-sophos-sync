"""Unit tests for Sophos Firewall API client."""

from urllib.parse import unquote, unquote_plus

import pytest
import respx
from httpx import Response

from technitium_sophos_sync.sophos import SophosAuthError, SophosClient, SophosClientError


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

    with pytest.raises(SophosAuthError, match="authentication failed"):
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

    with pytest.raises(SophosAuthError, match="authentication failed"):
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
def test_upsert_clientless_user_email_payload() -> None:
    """Test that upsert includes Email tag with configured email domain."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="secretpassword",
        email_domain="custom.domain",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <ClientlessUser>
        <Status>200</Status>
    </ClientlessUser>
</Response>"""

    route = respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    client.upsert_clientless_user(name="myhost", ip="10.0.0.5")
    assert route.called
    req_body = unquote_plus(route.calls.last.request.content.decode("utf-8"))
    assert "<Email>myhost@custom.domain</Email>" in req_body
    assert '<Set operation="add">' in req_body


@respx.mock
def test_upsert_clientless_user_update_operation() -> None:
    """Test that upsert with operation='update' generates operation="update" XML tag."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="secretpassword",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <ClientlessUser>
        <Status code="200">Configuration applied successfully.</Status>
    </ClientlessUser>
</Response>"""

    route = respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    result = client.upsert_clientless_user(name="myhost", ip="10.0.0.5", operation="update")
    assert result is True
    assert route.called
    req_body = unquote_plus(route.calls.last.request.content.decode("utf-8"))
    assert '<Set operation="update">' in req_body


@respx.mock
def test_upsert_clientless_user_entity_exists_503() -> None:
    """Test that 503 'Entity already exists' error is correctly recognized as failure."""
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
        <Status code="503">
            Operation failed. Entity having same parameter details already exists.
        </Status>
    </ClientlessUser>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    result = client.upsert_clientless_user(name="existing_user", ip="192.168.1.50", operation="add")
    assert result is False


@respx.mock
def test_parse_response_duplicate_attributes() -> None:
    """Test that responses with duplicate XML attributes from Sophos Firewall are sanitized."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="secretpassword",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status>Authentication Successful</status>
    </Login>
    <ClientlessUser transactionid="" transactionid="">
        <UserName>device1</UserName>
        <IPAddress>192.168.1.10</IPAddress>
    </ClientlessUser>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    users = client.get_existing_clientless_users()
    assert users == {"device1": "192.168.1.10"}


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


def test_sophos_whitespace_stripping() -> None:
    """Test that leading/trailing whitespace is stripped from credentials and host parameters."""
    client = SophosClient(
        firewall_ip=" 192.168.1.1 \n",
        username=" admin\n ",
        password=" secretpassword\r\n ",
    )
    assert client.username == "admin"
    assert client.password == "secretpassword"
    assert client.url == "https://192.168.1.1:4444/webconsole/APIController"


def test_mask_xml_password() -> None:
    """Test that _mask_xml replaces sensitive password values."""
    raw_xml = (
        "<Request><Login><Username>admin</Username>"
        "<Password>supersecret</Password></Login></Request>"
    )
    masked = SophosClient._mask_xml(raw_xml)
    assert "supersecret" not in masked
    assert "<Password>********</Password>" in masked


@respx.mock
def test_parse_response_status_code_attribute() -> None:
    """Test handling status responses with code attribute and non-success."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="wrong_password",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Login>
        <status code="529">Authentication Failed</status>
    </Login>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    with pytest.raises(SophosClientError, match="code: 529"):
        client.get_existing_clientless_users()


@respx.mock
def test_parse_response_top_level_status_error() -> None:
    """Test handling top-level status errors such as IP restrictions."""
    client = SophosClient(
        firewall_ip="192.168.1.1",
        password="secretpassword",
    )

    xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<Response APIVersion="2200.1">
    <Status code="500">API Access is not allowed from this IP</Status>
</Response>"""

    respx.post("https://192.168.1.1:4444/webconsole/APIController").mock(
        return_value=Response(200, text=xml_response)
    )

    with pytest.raises(SophosClientError, match="API Access is not allowed"):
        client.get_existing_clientless_users()
