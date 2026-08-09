"""Command-line interface for technitium-sophos-sync."""

import logging
import sys
import time

import click
from pydantic import SecretStr

from technitium_sophos_sync import __version__
from technitium_sophos_sync.config import Settings
from technitium_sophos_sync.sync import SyncEngine

logger = logging.getLogger("technitium_sophos_sync")


def setup_logging(level_name: str) -> None:
    """Configure structured logging output.

    Args:
        level_name: Logging verbosity level (DEBUG, INFO, etc.)
    """
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="technitium-sophos-sync")
@click.option(
    "--technitium-url",
    envvar="TECHNITIUM_URL",
    help="Technitium Web Interface URL (default: http://192.168.1.10:5380)",
)
@click.option(
    "--technitium-token",
    envvar="TECHNITIUM_TOKEN",
    help="Technitium API Token",
)
@click.option(
    "--sophos-ip",
    "sophos_firewall_ip",
    envvar="SOPHOS_FIREWALL_IP",
    help="Sophos Firewall Management IP Address",
)
@click.option(
    "--sophos-port",
    "sophos_firewall_port",
    type=int,
    envvar="SOPHOS_FIREWALL_PORT",
    help="Sophos Admin Web Console Port (default: 4444)",
)
@click.option(
    "--sophos-user",
    envvar="SOPHOS_USER",
    help="Sophos Firewall API Admin Username (default: admin)",
)
@click.option(
    "--sophos-pass",
    envvar="SOPHOS_PASS",
    help="Sophos Firewall API Admin Password",
)
@click.option(
    "--sophos-api-version",
    envvar="SOPHOS_API_VERSION",
    help="Sophos API Version (default: 2200.1)",
)
@click.option(
    "--clientless-group",
    "sophos_clientless_group",
    envvar="SOPHOS_CLIENTLESS_GROUP",
    help="Sophos Clientless User Group Name",
)
@click.option(
    "--static-leases-only/--all-leases",
    "static_leases_only",
    default=None,
    envvar="STATIC_LEASES_ONLY",
    help="Sync reserved/static leases only",
)
@click.option(
    "--dry-run/--no-dry-run",
    "dry_run",
    default=None,
    envvar="DRY_RUN",
    help="Log changes without executing API calls against Sophos Firewall",
)
@click.option(
    "--verify-ssl/--no-verify-ssl",
    "sophos_verify_ssl",
    default=None,
    envvar="SOPHOS_VERIFY_SSL",
    help="Verify SSL certificate when connecting to Sophos Firewall API",
)
@click.option(
    "-i",
    "--interval",
    "sync_interval",
    type=int,
    envvar="SYNC_INTERVAL",
    help="Continuous sync interval in seconds (default: 0 for single-run mode)",
)
@click.option(
    "--once",
    is_flag=True,
    help="Force execution to run once and exit regardless of sync_interval",
)
@click.option(
    "-l",
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False),
    envvar="LOG_LEVEL",
    help="Set logging verbosity level (default: INFO)",
)
def main(
    technitium_url: str | None,
    technitium_token: str | None,
    sophos_firewall_ip: str | None,
    sophos_firewall_port: int | None,
    sophos_user: str | None,
    sophos_pass: str | None,
    sophos_api_version: str | None,
    sophos_clientless_group: str | None,
    static_leases_only: bool | None,
    dry_run: bool | None,
    sophos_verify_ssl: bool | None,
    sync_interval: int | None,
    once: bool,
    log_level: str | None,
) -> None:
    """Technitium DHCP to Sophos Firewall Clientless User Sync utility."""
    # Load settings from environment/.env
    settings = Settings()

    # Apply CLI overrides if specified
    if technitium_url is not None:
        settings.technitium_url = technitium_url
    if technitium_token is not None:
        settings.technitium_token = SecretStr(technitium_token)
    if sophos_firewall_ip is not None:
        settings.sophos_firewall_ip = sophos_firewall_ip
    if sophos_firewall_port is not None:
        settings.sophos_firewall_port = sophos_firewall_port
    if sophos_user is not None:
        settings.sophos_user = sophos_user
    if sophos_pass is not None:
        settings.sophos_pass = SecretStr(sophos_pass)
    if sophos_api_version is not None:
        settings.sophos_api_version = sophos_api_version
    if sophos_clientless_group is not None:
        settings.sophos_clientless_group = sophos_clientless_group
    if static_leases_only is not None:
        settings.static_leases_only = static_leases_only
    if dry_run is not None:
        settings.dry_run = dry_run
    if sophos_verify_ssl is not None:
        settings.sophos_verify_ssl = sophos_verify_ssl
    if sync_interval is not None:
        settings.sync_interval = sync_interval
    if log_level is not None:
        settings.log_level = log_level.upper()  # type: ignore[assignment]

    setup_logging(settings.log_level)

    logger.info("Starting technitium-sophos-sync v%s", __version__)
    if settings.dry_run:
        logger.warning("DRY RUN MODE ENABLED - No changes will be written to Sophos Firewall.")

    engine = SyncEngine(settings=settings)

    if once or settings.sync_interval <= 0:
        logger.info("Running single sync pass...")
        res = engine.run_sync()
        if res.errors > 0:
            logger.error("Sync completed with %d error(s).", res.errors)
            sys.exit(1)
        sys.exit(0)
    else:
        logger.info(
            "Starting continuous sync daemon mode (interval: %d seconds)...",
            settings.sync_interval,
        )
        try:
            while True:
                try:
                    engine.run_sync()
                except Exception as err:
                    logger.error("Error during sync cycle: %s", err)

                logger.info(
                    "Sleeping for %d seconds before next sync cycle...",
                    settings.sync_interval,
                )
                time.sleep(settings.sync_interval)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal. Exiting daemon mode cleanly.")
            sys.exit(0)


if __name__ == "__main__":
    main()
