"""Sophos Firewall API client for Clientless User management."""

import logging
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import httpx
import urllib3

logger = logging.getLogger(__name__)


class SophosClientError(Exception):
    """Exception raised for errors during Sophos Firewall API interaction."""


class SophosClient:
    """Client for interacting with Sophos Firewall APIController."""

    def __init__(
        self,
        firewall_ip: str,
        port: int = 4444,
        username: str = "admin",
        password: str = "",
        clientless_group: str = "Clientless Open Group",
        verify_ssl: bool = False,
        timeout: float = 15.0,
        api_version: str = "2200.1",
    ) -> None:
        """Initialize Sophos Firewall API client.

        Args:
            firewall_ip: Management IP address or hostname.
            port: Admin console API port.
            username: Admin username.
            password: Admin password.
            clientless_group: Sophos Clientless Group Name.
            verify_ssl: Whether to verify SSL certificate.
            timeout: HTTP timeout in seconds.
            api_version: Sophos API version string.
        """
        self.url = f"https://{firewall_ip}:{port}/webconsole/APIController"
        self.username = username
        self.password = password
        self.clientless_group = clientless_group
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.api_version = api_version

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get_existing_clientless_users(self) -> dict[str, str]:
        """Query existing Clientless Users from Sophos Firewall.

        Returns:
            Dictionary mapping UserName -> IPAddress for existing clientless users.

        Raises:
            SophosClientError: On connection errors or authentication failures.
        """
        xml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="{escape(self.api_version)}">
    <Login>
        <Username>{escape(self.username)}</Username>
        <Password>{escape(self.password)}</Password>
    </Login>
    <Get>
        <ClientlessUser/>
    </Get>
</Request>"""

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                response = client.post(self.url, data={"reqxml": xml_request})
                response.raise_for_status()
        except httpx.HTTPError as err:
            logger.error("HTTP error while querying Sophos API: %s", err)
            raise SophosClientError(f"HTTP error contacting Sophos Firewall: {err}") from err

        existing: dict[str, str] = {}
        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as err:
            logger.error("Failed to parse Sophos API XML response: %s", err)
            raise SophosClientError(f"Invalid XML returned by Sophos Firewall: {err}") from err

        # Check authentication/status
        status_node = root.find(".//Status")
        if status_node is not None and "Authentication Failed" in (status_node.text or ""):
            raise SophosClientError("Sophos Firewall authentication failed")

        for user in root.findall(".//ClientlessUser"):
            user_name = user.findtext("UserName")
            ip = user.findtext("IPAddress")
            if user_name and ip:
                existing[user_name] = ip

        logger.debug("Retrieved %d clientless users from Sophos Firewall", len(existing))
        return existing

    def upsert_clientless_user(self, name: str, ip: str) -> bool:
        """Add or update a Clientless User on Sophos Firewall.

        Args:
            name: User/Device name.
            ip: Assigned IP address.

        Returns:
            True if operation succeeded, False otherwise.

        Raises:
            SophosClientError: On connection errors.
        """
        xml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<Request APIVersion="{escape(self.api_version)}">
    <Login>
        <Username>{escape(self.username)}</Username>
        <Password>{escape(self.password)}</Password>
    </Login>
    <Set operation="add">
        <ClientlessUser>
            <UserName>{escape(name)}</UserName>
            <Name>{escape(name)}</Name>
            <IPAddress>{escape(ip)}</IPAddress>
            <ClientLessGroup>{escape(self.clientless_group)}</ClientLessGroup>
            <Status>Active</Status>
            <QuarantineDigest>Disable</QuarantineDigest>
        </ClientlessUser>
    </Set>
</Request>"""

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                response = client.post(self.url, data={"reqxml": xml_request})
                response.raise_for_status()
        except httpx.HTTPError as err:
            logger.error("HTTP error upserting Clientless User '%s': %s", name, err)
            raise SophosClientError(f"HTTP error during upsert of '{name}': {err}") from err

        text = response.text
        success = (
            "Authentication Successful" in text
            or "<Status>200</Status>" in text
            or "Configuration updated" in text
            or "User added successfully" in text
        )
        if not success:
            logger.warning(
                "Sophos API response for user '%s' did not indicate clear success: %s",
                name,
                text[:300],
            )

        return success
