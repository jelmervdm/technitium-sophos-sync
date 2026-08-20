"""Sync engine for reconciling Technitium leases with Sophos Firewall Clientless Users."""

import logging
import re
from collections import Counter
from dataclasses import dataclass

from technitium_sophos_sync.config import Settings
from technitium_sophos_sync.sophos import SophosAuthError, SophosClient, SophosUsersState
from technitium_sophos_sync.technitium import DHCPLease, TechnitiumClient

logger = logging.getLogger(__name__)


def format_disambiguated_name(name: str, mac: str) -> str:
    """Format hostname by inserting a MAC suffix to differentiate duplicate names.

    Args:
        name: Hostname string.
        mac: Hardware MAC address string.

    Returns:
        Disambiguated hostname string (max 60 chars).
    """
    if name.startswith("Device_"):
        return name

    clean_mac = re.sub(r"[^a-zA-Z0-9]", "", mac)
    mac_suffix = clean_mac[-4:].upper() if len(clean_mac) >= 4 else "0000"

    if "_" in name:
        parts = name.split("_", 1)
        disambiguated = f"{parts[0]}_{mac_suffix}_{parts[1]}"
    else:
        disambiguated = f"{name}_{mac_suffix}"

    return disambiguated[:60]


def prepare_lease_names(
    leases: list[DHCPLease], mode: str = "duplicates_only"
) -> list[tuple[DHCPLease, str]]:
    """Process leases and assign final target Sophos user names based on disambiguation mode.

    Args:
        leases: List of parsed DHCPLease instances.
        mode: Disambiguation mode ('duplicates_only', 'always', or 'off').

    Returns:
        List of tuples (DHCPLease, final_user_name).
    """
    if mode == "off":
        return [(lease, lease.name) for lease in leases]

    name_counts = Counter(lease.name for lease in leases)
    result: list[tuple[DHCPLease, str]] = []

    for lease in leases:
        if mode == "always" or (mode == "duplicates_only" and name_counts[lease.name] > 1):
            final_name = format_disambiguated_name(lease.name, lease.mac)
        else:
            final_name = lease.name
        result.append((lease, final_name))

    return result


@dataclass
class SyncResult:
    """Summary of synchronization results."""

    total_leases: int = 0
    created: int = 0
    updated: int = 0
    deleted: int = 0
    unchanged: int = 0
    errors: int = 0


class SyncEngine:
    """Orchestrates DHCP lease sync between Technitium DNS and Sophos Firewall."""

    def __init__(
        self,
        settings: Settings,
        technitium_client: TechnitiumClient | None = None,
        sophos_client: SophosClient | None = None,
    ) -> None:
        """Initialize sync engine with settings and clients.

        Args:
            settings: Configured application settings.
            technitium_client: Optional TechnitiumClient instance (creates default if None).
            sophos_client: Optional SophosClient instance (creates default if None).
        """
        self.settings = settings
        self.technitium = technitium_client or TechnitiumClient(
            base_url=settings.technitium_url,
            token=settings.technitium_token.get_secret_value(),
            timeout=settings.technitium_timeout,
        )
        self.sophos = sophos_client or SophosClient(
            firewall_ip=settings.sophos_firewall_ip,
            port=settings.sophos_firewall_port,
            username=settings.sophos_user,
            password=settings.sophos_pass.get_secret_value(),
            clientless_group=settings.sophos_clientless_group,
            email_domain=settings.sophos_email_domain,
            verify_ssl=settings.sophos_verify_ssl,
            timeout=settings.sophos_timeout,
            api_version=settings.sophos_api_version,
        )

    def run_sync(self) -> SyncResult:
        """Execute full synchronization cycle.

        Returns:
            SyncResult dataclass with counts of operations performed.
        """
        result = SyncResult()

        logger.info("Fetching DHCP leases from Technitium DNS/DHCP server...")
        leases = self.technitium.get_dhcp_leases(
            static_leases_only=self.settings.static_leases_only
        )
        result.total_leases = len(leases)
        logger.info("Retrieved %d active lease records.", result.total_leases)

        logger.info("Fetching existing Clientless Users from Sophos Firewall...")
        sophos_state = self.sophos.get_existing_clientless_users_state()
        if isinstance(sophos_state, SophosUsersState):
            existing_by_name = sophos_state.by_name
            existing_by_ip = sophos_state.by_ip
        else:
            existing_by_name = self.sophos.get_existing_clientless_users()
            existing_by_ip = {ip: name for name, ip in existing_by_name.items()}

        prepared_leases = prepare_lease_names(
            leases, mode=self.settings.mac_disambiguation
        )

        for lease, name in prepared_leases:
            ip = lease.ip

            existing_ip = existing_by_name.get(name) or existing_by_name.get(name.lower())

            if existing_ip is None:
                # Check if IP is already claimed by a different Sophos user (IP conflict)
                existing_owner = existing_by_ip.get(ip)
                if existing_owner and existing_owner.lower() != name.lower():
                    if self.settings.resolve_ip_conflicts:
                        if self.settings.dry_run:
                            logger.info(
                                "[DRY-RUN] IP conflict on %s: Would DELETE conflicting Sophos user '%s' to create '%s'",
                                ip,
                                existing_owner,
                                name,
                            )
                            result.deleted += 1
                        else:
                            logger.info(
                                "[- REMOVE] IP conflict on %s: Deleting conflicting Sophos user '%s' to assign IP to '%s'",
                                ip,
                                existing_owner,
                                name,
                            )
                            try:
                                self.sophos.delete_clientless_user(existing_owner)
                                result.deleted += 1
                                existing_by_ip.pop(ip, None)
                                existing_by_name.pop(existing_owner, None)
                                existing_by_name.pop(existing_owner.lower(), None)
                            except SophosAuthError:
                                raise
                            except Exception as err:
                                logger.error(
                                    "Failed to delete conflicting Sophos user '%s' for IP %s: %s",
                                    existing_owner,
                                    ip,
                                    err,
                                )
                                result.errors += 1
                                continue
                    else:
                        logger.info(
                            "[= SKIP] IP %s is already assigned to existing Sophos user '%s'; "
                            "skipping creation of '%s'",
                            ip,
                            existing_owner,
                            name,
                        )
                        result.unchanged += 1
                        continue

                if self.settings.dry_run:
                    logger.info("[DRY-RUN] Would CREATE Clientless User: %s -> %s", name, ip)
                    result.created += 1
                else:
                    logger.info("[+ CREATE] Adding Clientless User: %s -> %s", name, ip)
                    try:
                        if self.sophos.upsert_clientless_user(name, ip, operation="add"):
                            result.created += 1
                        else:
                            logger.error(
                                "Failed to create Clientless User '%s' -> %s (Sophos API error)",
                                name,
                                ip,
                            )
                            result.errors += 1
                    except SophosAuthError:
                        raise
                    except Exception as err:
                        logger.error(
                            "Error creating Clientless User '%s' -> %s: %s",
                            name,
                            ip,
                            err,
                            exc_info=True,
                        )
                        result.errors += 1

            elif existing_ip != ip:
                old_ip = existing_ip
                # Check if new target IP is claimed by another user
                existing_owner = existing_by_ip.get(ip)
                if existing_owner and existing_owner.lower() != name.lower():
                    if self.settings.resolve_ip_conflicts:
                        if self.settings.dry_run:
                            logger.info(
                                "[DRY-RUN] IP conflict on %s: Would DELETE conflicting Sophos user '%s' to update '%s'",
                                ip,
                                existing_owner,
                                name,
                            )
                            result.deleted += 1
                        else:
                            logger.info(
                                "[- REMOVE] IP conflict on %s: Deleting conflicting Sophos user '%s' to update '%s'",
                                ip,
                                existing_owner,
                                name,
                            )
                            try:
                                self.sophos.delete_clientless_user(existing_owner)
                                result.deleted += 1
                                existing_by_ip.pop(ip, None)
                                existing_by_name.pop(existing_owner, None)
                                existing_by_name.pop(existing_owner.lower(), None)
                            except SophosAuthError:
                                raise
                            except Exception as err:
                                logger.error(
                                    "Failed to delete conflicting Sophos user '%s' for IP %s: %s",
                                    existing_owner,
                                    ip,
                                    err,
                                )
                                result.errors += 1
                                continue
                    else:
                        logger.info(
                            "[= SKIP] IP %s is already assigned to existing Sophos user '%s'; "
                            "skipping update of '%s'",
                            ip,
                            existing_owner,
                            name,
                        )
                        result.unchanged += 1
                        continue

                if self.settings.dry_run:
                    logger.info("[DRY-RUN] Would UPDATE IP for %s: %s -> %s", name, old_ip, ip)
                    result.updated += 1
                else:
                    logger.info("[~ UPDATE] Updating IP for %s: %s -> %s", name, old_ip, ip)
                    try:
                        if self.sophos.upsert_clientless_user(name, ip, operation="update"):
                            result.updated += 1
                        else:
                            logger.error(
                                "Failed to update Clientless User '%s': %s -> %s (API error)",
                                name,
                                old_ip,
                                ip,
                            )
                            result.errors += 1
                    except SophosAuthError:
                        raise
                    except Exception as err:
                        logger.error(
                            "Error updating Clientless User '%s': %s -> %s: %s",
                            name,
                            old_ip,
                            ip,
                            err,
                            exc_info=True,
                        )
                        result.errors += 1

            else:
                logger.debug("[= MATCH] %s -> %s already up to date", name, ip)
                result.unchanged += 1

        logger.info(
            "Sync Cycle Finished. Summary: Total=%d, Created=%d, Updated=%d, "
            "Deleted=%d, Unchanged=%d, Errors=%d",
            result.total_leases,
            result.created,
            result.updated,
            result.deleted,
            result.unchanged,
            result.errors,
        )
        return result
