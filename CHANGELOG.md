# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
