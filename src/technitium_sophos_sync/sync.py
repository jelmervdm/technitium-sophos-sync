"""Sync engine for reconciling Technitium leases with Sophos Firewall Clientless Users."""

import logging
from dataclasses import dataclass

from technitium_sophos_sync.config import Settings
from technitium_sophos_sync.sophos import SophosAuthError, SophosClient
from technitium_sophos_sync.technitium import TechnitiumClient

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Summary of synchronization results."""

    total_leases: int = 0
    created: int = 0
    updated: int = 0
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
        existing_users = self.sophos.get_existing_clientless_users()

        for lease in leases:
            name = lease.name
            ip = lease.ip

            if name not in existing_users:
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

            elif existing_users[name] != ip:
                old_ip = existing_users[name]
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
            "Unchanged=%d, Errors=%d",
            result.total_leases,
            result.created,
            result.updated,
            result.unchanged,
            result.errors,
        )
        return result
