"""Sophos Firewall API client for Clientless User management."""

import logging
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import httpx
import urllib3

logger = logging.getLogger(__name__)


class SophosClientError(Exception):
    """Exception raised for errors during Sophos Firewall API interaction."""


class SophosAuthError(SophosClientError):
    """Exception raised when Sophos Firewall authentication fails."""


class SophosClient:
    """Client for interacting with Sophos Firewall APIController."""

    def __init__(
        self,
        firewall_ip: str,
        port: int = 4444,
        username: str = "admin",
        password: str = "",
        clientless_group: str = "Clientless Open Group",
        email_domain: str = "dhcp.local",
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
            email_domain: Domain suffix used for clientless user emails.
            verify_ssl: Whether to verify SSL certificate.
            timeout: HTTP timeout in seconds.
            api_version: Sophos API version string.
        """
        self.url = f"https://{firewall_ip.strip()}:{port}/webconsole/APIController"
        self.username = username.strip()
        self.password = password.strip()
        self.clientless_group = clientless_group.strip()
        self.email_domain = email_domain.strip().lstrip("@")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.api_version = api_version.strip()

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def _mask_xml(xml_str: str) -> str:
        """Mask sensitive values (like Password) in XML string for safe logging.

        Args:
            xml_str: Raw XML request string.

        Returns:
            XML string with Password content replaced by asterisks.
        """
        return re.sub(
            r"(<Password>)[^<]*(</Password>)",
            r"\1********\2",
            xml_str,
            flags=re.IGNORECASE,
        )

    def _parse_and_verify_response(self, xml_text: str) -> ET.Element:
        """Parse XML response from Sophos Firewall and verify authentication status.

        Args:
            xml_text: Raw XML response body.

        Returns:
            Parsed ElementTree root element.

        Raises:
            SophosClientError: If XML is invalid or authentication failed.
        """
        # Sanitize duplicate XML attributes (e.g. transactionid="" transactionid="")
        sanitized_xml = re.sub(
            r'(\b[a-zA-Z_:][\w:.-]*\s*=\s*["\'][^"\']*["\'])\s+\1', r"\1", xml_text
        )

        try:
            root = ET.fromstring(sanitized_xml)
        except ET.ParseError as err:
            logger.error("Failed to parse Sophos API XML response: %s. Raw XML:\n%s", err, xml_text)
            raise SophosClientError(f"Invalid XML returned by Sophos Firewall: {err}") from err

        # Sophos places login status in <Login><status> or <Login><Status>
        login_status_node = root.find(".//Login/status")
        if login_status_node is None:
            login_status_node = root.find(".//Login/Status")

        if login_status_node is not None:
            status_text = (login_status_node.text or "").strip()
            status_code = login_status_node.get("code", "").strip()
            is_success = (
                status_text == "Authentication Successful"
                or status_code == "200"
                or "Successful" in status_text
            )
            if not is_success:
                msg_parts = []
                if status_text:
                    msg_parts.append(status_text)
                if status_code:
                    msg_parts.append(f"code: {status_code}")
                if not msg_parts:
                    msg_parts.append(f"Raw response: {sanitized_xml[:300]}")

                err_msg = ", ".join(msg_parts)
                logger.error(
                    "Sophos API authentication error: %s. Raw XML response:\n%s",
                    err_msg,
                    xml_text,
                )
                raise SophosAuthError(f"Sophos Firewall authentication failed: {err_msg}")

        # Also check root level <Status> or <status> for legacy or top-level error messages
        top_status_node = root.find("./Status")
        if top_status_node is None:
            top_status_node = root.find("./status")

        if top_status_node is not None:
            top_text = (top_status_node.text or "").strip()
            top_code = top_status_node.get("code", "").strip()
            if (
                "Failed" in top_text
                or "Failure" in top_text
                or "not allowed" in top_text.lower()
                or (top_code and top_code != "200" and top_code != "")
            ):
                msg_parts = []
                if top_text:
                    msg_parts.append(top_text)
                if top_code:
                    msg_parts.append(f"code: {top_code}")
                err_msg = ", ".join(msg_parts) or f"Raw response: {sanitized_xml[:300]}"
                logger.error(
                    "Sophos API top-level status error: %s. Raw XML response:\n%s",
                    err_msg,
                    xml_text,
                )
                raise SophosClientError(f"Sophos Firewall API error: {err_msg}")

        return root

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

        logger.debug(
            "Sending Sophos API Request [Get ClientlessUser]:\n%s", self._mask_xml(xml_request)
        )

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                response = client.post(self.url, data={"reqxml": xml_request})
                response.raise_for_status()
        except httpx.HTTPError as err:
            logger.error("HTTP error while querying Sophos API (%s): %s", self.url, err)
            raise SophosClientError(f"HTTP error contacting Sophos Firewall: {err}") from err

        logger.debug(
            "Sophos API Response [Get ClientlessUser - Status %d]:\n%s",
            response.status_code,
            response.text,
        )
        root = self._parse_and_verify_response(response.text)
        existing: dict[str, str] = {}

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
            SophosClientError: On connection errors or authentication failures.
        """
        email = f"{name}@{self.email_domain}"
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
            <Email>{escape(email)}</Email>
            <IPAddress>{escape(ip)}</IPAddress>
            <ClientLessGroup>{escape(self.clientless_group)}</ClientLessGroup>
            <Status>Active</Status>
            <QuarantineDigest>Disable</QuarantineDigest>
        </ClientlessUser>
    </Set>
</Request>"""

        logger.debug(
            "Sending Sophos API Request [Set ClientlessUser '%s']:\n%s",
            name,
            self._mask_xml(xml_request),
        )

        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout) as client:
                response = client.post(self.url, data={"reqxml": xml_request})
                response.raise_for_status()
        except httpx.HTTPError as err:
            logger.error("HTTP error upserting Clientless User '%s' (%s): %s", name, self.url, err)
            raise SophosClientError(f"HTTP error during upsert of '{name}': {err}") from err

        logger.debug(
            "Sophos API Response [Set ClientlessUser '%s' - Status %d]:\n%s",
            name,
            response.status_code,
            response.text,
        )
        root = self._parse_and_verify_response(response.text)

        text = response.text
        user_status_node = root.find(".//ClientlessUser/status")
        if user_status_node is None:
            user_status_node = root.find(".//ClientlessUser/Status")

        user_status_text = (
            (user_status_node.text or "").strip() if user_status_node is not None else ""
        )
        user_status_code = (
            user_status_node.get("code", "").strip() if user_status_node is not None else ""
        )

        success = (
            "Authentication Successful" in text
            or "<Status>200</Status>" in text
            or 'code="200"' in text
            or "Configuration updated" in text
            or "User added successfully" in text
            or "User updated successfully" in text
            or user_status_code == "200"
        )

        if success:
            logger.info(
                "Successfully synced Clientless User '%s' -> %s on Sophos Firewall.", name, ip
            )
        else:
            logger.error(
                "Sophos API response for user '%s' did not indicate success. "
                "Status text: '%s', code: '%s'. Full response XML:\n%s",
                name,
                user_status_text or "N/A",
                user_status_code or "N/A",
                text,
            )

        return success
