"""Technitium DNS/DHCP API client."""

import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DHCPLease:
    """Dataclass representing a parsed Technitium DHCP lease."""

    name: str
    ip: str
    mac: str
    is_reserved: bool


class TechnitiumClientError(Exception):
    """Exception raised for errors during Technitium API interaction."""


class TechnitiumClient:
    """Client for interacting with Technitium DNS/DHCP Server API."""

    def __init__(self, base_url: str, token: str, timeout: float = 10.0) -> None:
        """Initialize Technitium API client.

        Args:
            base_url: Base URL of Technitium server web interface.
            token: API token for authentication.
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    @staticmethod
    def sanitize_hostname(hostname: str | None, mac_address: str | None) -> str:
        """Sanitize hostname for Sophos XML compatibility.

        Args:
            hostname: Raw hostname from DHCP lease.
            mac_address: MAC address of device as fallback.

        Returns:
            Sanitized hostname compliant with Sophos naming rules
            (alphanumeric/underscores/hyphens, max 60 chars).
        """
        if not hostname:
            clean_mac = (mac_address or "").replace("-", "").replace(":", "")
            hostname = f"Device_{clean_mac}" if clean_mac else "Device_Unknown"

        clean_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", hostname)[:60]
        return clean_name or "Device_Unknown"

    def get_dhcp_leases(self, static_leases_only: bool = False) -> list[DHCPLease]:
        """Fetch active DHCP leases from Technitium server.

        Args:
            static_leases_only: If True, filter out dynamic/unreserved leases.

        Returns:
            List of parsed DHCPLease instances.

        Raises:
            TechnitiumClientError: On network, HTTP, or API status errors.
        """
        url = f"{self.base_url}/api/dhcp/scopes/leases/list"
        params = {"token": self.token}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except httpx.HTTPError as err:
            logger.error("HTTP error while querying Technitium API: %s", err)
            raise TechnitiumClientError(f"HTTP error contacting Technitium: {err}") from err
        except ValueError as err:
            logger.error("Failed to parse JSON response from Technitium API: %s", err)
            raise TechnitiumClientError("Invalid JSON returned by Technitium API") from err

        if data.get("status") != "ok":
            error_msg = data.get("errorMessage", "Unknown error")
            logger.error("Technitium API returned error status: %s", error_msg)
            raise TechnitiumClientError(f"Technitium API error: {error_msg}")

        raw_leases = data.get("response", {}).get("leases", [])
        leases: list[DHCPLease] = []

        for lease in raw_leases:
            is_reserved = bool(lease.get("isReserved", False))
            if static_leases_only and not is_reserved:
                continue

            raw_hostname = lease.get("hostName")
            raw_mac = lease.get("macAddress")
            ip_address = lease.get("ipAddress")

            if not ip_address:
                logger.warning("Skipping lease record without IP address: %s", lease)
                continue

            clean_name = self.sanitize_hostname(raw_hostname, raw_mac)
            leases.append(
                DHCPLease(
                    name=clean_name,
                    ip=ip_address,
                    mac=raw_mac or "",
                    is_reserved=is_reserved,
                )
            )

        logger.debug("Fetched %d leases from Technitium server", len(leases))
        return leases
