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
        self.base_url = base_url.strip().rstrip("/")
        self.token = token.strip()
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

    def get_dhcp_scope_reservations(self) -> list[DHCPLease]:
        """Fetch configured static reservations from Technitium DHCP scopes.

        Returns:
            List of parsed DHCPLease instances representing scope reservations.
        """
        url = f"{self.base_url}/api/dhcp/scopes/list"
        params = {"token": self.token}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                data: dict[str, Any] = response.json()
        except httpx.HTTPError as err:
            logger.warning("HTTP error fetching Technitium DHCP scopes: %s", err)
            return []
        except ValueError as err:
            logger.warning("Failed to parse JSON response for Technitium DHCP scopes: %s", err)
            return []

        if data.get("status") != "ok":
            error_msg = data.get("errorMessage", "Unknown error")
            logger.warning("Technitium scopes API returned error status: %s", error_msg)
            return []

        scopes = data.get("response", {}).get("scopes", [])
        reservations: list[DHCPLease] = []

        for scope in scopes:
            reserved_list = (
                scope.get("reservedLeases")
                or scope.get("staticLeases")
                or scope.get("reservations")
                or []
            )
            for item in reserved_list:
                raw_hostname = item.get("hostName") or item.get("hostname") or item.get("name")
                raw_mac = item.get("macAddress") or item.get("hardwareAddress") or item.get("mac")
                ip_address = item.get("ipAddress") or item.get("address") or item.get("ip")

                if not ip_address:
                    continue

                clean_name = self.sanitize_hostname(raw_hostname, raw_mac)
                reservations.append(
                    DHCPLease(
                        name=clean_name,
                        ip=ip_address,
                        mac=raw_mac or "",
                        is_reserved=True,
                    )
                )

        logger.debug("Fetched %d scope reservations from Technitium server", len(reservations))
        return reservations

    def get_dhcp_leases(self, static_leases_only: bool = False) -> list[DHCPLease]:
        """Fetch DHCP leases (active leases and scope static reservations) from Technitium server.

        Args:
            static_leases_only: If True, filter out dynamic/unreserved leases.

        Returns:
            List of parsed DHCPLease instances.

        Raises:
            TechnitiumClientError: On network, HTTP, or API status errors.
        """
        url = f"{self.base_url}/api/dhcp/leases/list"
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
        leases_by_ip: dict[str, DHCPLease] = {}

        for lease in raw_leases:
            is_reserved = bool(
                lease.get("isReserved", False)
                or lease.get("isStatic", False)
                or lease.get("type") == "Reserved"
            )

            raw_hostname = lease.get("hostName") or lease.get("hostname") or lease.get("name")
            raw_mac = lease.get("macAddress") or lease.get("hardwareAddress") or lease.get("mac")
            ip_address = lease.get("ipAddress") or lease.get("address") or lease.get("ip")

            if not ip_address:
                logger.warning("Skipping lease record without IP address: %s", lease)
                continue

            clean_name = self.sanitize_hostname(raw_hostname, raw_mac)
            leases_by_ip[ip_address] = DHCPLease(
                name=clean_name,
                ip=ip_address,
                mac=raw_mac or "",
                is_reserved=is_reserved,
            )

        # Also fetch static reservations defined in DHCP scopes
        scope_reservations = self.get_dhcp_scope_reservations()
        for res in scope_reservations:
            if res.ip not in leases_by_ip:
                leases_by_ip[res.ip] = res
            else:
                # Upgrade existing lease record to is_reserved if scope defines a reservation
                existing = leases_by_ip[res.ip]
                if not existing.is_reserved:
                    leases_by_ip[res.ip] = DHCPLease(
                        name=existing.name,
                        ip=existing.ip,
                        mac=existing.mac or res.mac,
                        is_reserved=True,
                    )

        final_leases = list(leases_by_ip.values())
        if static_leases_only:
            final_leases = [lease for lease in final_leases if lease.is_reserved]

        logger.debug("Fetched %d total leases from Technitium server", len(final_leases))
        return final_leases

