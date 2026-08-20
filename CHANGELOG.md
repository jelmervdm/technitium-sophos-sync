# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3-dev.3] - 2026-08-20

### Added
- Added `deleted` metric to `SyncResult` and included `Deleted` count in the sync finish summary log output (e.g. `Summary: Total=88, Created=4, Updated=3, Deleted=5, Unchanged=81, Errors=0`).
- Added automatic resolution for IP address conflicts between Technitium DHCP leases/reservations and existing Sophos Firewall Clientless Users (`resolve_ip_conflicts`).
- Added `delete_clientless_user` method to `SophosClient`.
- Added `RESOLVE_IP_CONFLICTS` environment variable setting and `--resolve-ip-conflicts / --no-resolve-ip-conflicts` CLI option.

## [0.2.3] - 2026-08-20

### Added
- Added support for fetching static DHCP scope reservations (`/api/dhcp/scopes/list`) in addition to active leases (`/api/dhcp/leases/list`).
- Integrated static scope reservations into `TechnitiumClient.get_dhcp_leases()` with IP-based deduplication, enabling synchronization for offline devices and statically configured machines.

## [0.2.2] - 2026-08-10

### Fixed
- Fixed repeated creation attempts of existing clientless users by indexing both `UserName` and `Name` fields (including lowercased variants) in `get_existing_clientless_users`.
- Updated `SyncEngine` to perform case-insensitive lookups when comparing DHCP leases against Sophos clientless users.
- Implemented automatic retry fallback in `upsert_clientless_user` to retry with `operation="update"` when an `add` call fails due to a `503` "Entity already exists" conflict.

## [0.2.1] - 2026-08-10

### Fixed
- Fixed Sophos Firewall clientless user creation logic by differentiating between `add` and `update` API operations in `upsert_clientless_user`.
- Improved response status parsing to accurately handle 503 entity conflict errors and return specific status codes/messages rather than relying solely on authentication status.

### Added
- Added dedicated `SophosAuthError` exception class to specifically capture Sophos Firewall XML API authentication failures.
- Added `MAX_CONSECUTIVE_FAILURES` (default `3`) and `EXIT_ON_AUTH_FAILURE` / `EXIT_ON_AUTH_ERROR` (default `True`) environment variables and settings.

### Changed
- Updated CLI daemon loop to fail fast and exit immediately upon authentication failure or after reaching maximum consecutive sync failures.
- Re-raised `SophosAuthError` from sync engine to ensure authentication errors correctly trigger daemon exit logic.

## [0.1.7] - 2026-08-10

### Fixed
- Added regex sanitization for Sophos Firewall XML API responses to automatically clean duplicate attributes (e.g. `transactionid="" transactionid=""`) that cause XML parsing errors.
- Added mandatory `<Email>` element to Sophos `ClientlessUser` upsert payload to prevent "Configuration parameters validation failed" errors.

### Added
- Added `SOPHOS_EMAIL_DOMAIN` environment variable (default `dhcp.local`) and setting for configuring generated email addresses (`hostname@domain`).
- Added `SOPHOS_FIREWALL_USER` and `SOPHOS_FIREWALL_PASSWORD` environment variable aliases to `config.py`.

## [0.1.6] - 2026-08-09

### Fixed
- Added automatic leading/trailing whitespace and newline trimming (`.strip()`) for passwords, usernames, tokens, and host parameters. This prevents authentication failures when passwords contain hidden trailing newlines from Kubernetes Secrets or `.env` files.

## [0.1.5] - 2026-08-09

### Fixed
- Fixed Ruff code formatting and unused variable warnings in `sophos.py` to ensure CI linting check passes.

## [0.1.4] - 2026-08-09

### Changed
- Increased default `sophos_timeout` from `15.0` to `30.0` seconds to prevent timeouts when querying large Clientless User tables from Sophos Firewall.

### Added
- Added `--sophos-timeout` and `--technitium-timeout` options to CLI and environment configuration.

## [0.1.3] - 2026-08-09

### Fixed
- Added exception handling to continuous daemon loop so transient sync or authentication errors are logged and retried at the next interval instead of exiting the daemon.

## [0.1.2] - 2026-08-09

### Fixed
- Fixed Sophos Firewall XML response parsing to inspect `<Login><status>` nodes for `Authentication Failure` and fail fast with explicit error instead of silently returning empty results and repeating failed API calls.

## [0.1.1] - 2026-08-09

### Fixed
- Fixed Technitium API DHCP leases endpoint URL path from `/api/dhcp/scopes/leases/list` to `/api/dhcp/leases/list` to resolve HTTP 404 error.
- Expanded field name fallbacks for Technitium lease response parsing (`ipAddress`/`address`, `hostName`/`hostname`, `macAddress`/`hardwareAddress`, `isReserved`/`isStatic`).

## [0.1.0] - 2026-08-09

### Added
- Initial release of `technitium-sophos-sync`.
- Full synchronization between Technitium DNS/DHCP leases and Sophos Firewall Clientless Users.
- Support for environment variables, `.env` files, and CLI flag overrides.
- Dry-run mode (`--dry-run`) for inspecting changes before committing.
- Single-pass (`--once`) and daemon polling mode (`--interval`).
- Static/reserved DHCP lease filtering support (`--static-leases-only`).
- Multi-stage Docker container build and `docker-compose.yml`.
- GitHub Actions workflows for continuous integration and automated releases.
