# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
