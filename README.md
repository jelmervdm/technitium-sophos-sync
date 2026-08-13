# Technitium to Sophos Firewall Clientless Sync

[![CI](https://github.com/jelmervdm/technitium-sophos-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/jelmervdm/technitium-sophos-sync/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

An automated utility that synchronizes active DHCP leases from a **Technitium DNS/DHCP Server** to **Sophos Firewall Clientless Users** (SFOS XML APIController).

This allows Sophos Firewall security policies, web filtering, and user-based reporting to automatically map IP addresses to hostnames retrieved dynamically from Technitium DHCP.

---

## About

`technitium-sophos-sync` bridges the gap between **Technitium DNS/DHCP Server** lease management and **Sophos Firewall (SFOS)** identity-aware security policies.

### Problem Statement

In modern network environments, Technitium handles dynamic and static DHCP lease allocations for devices across various subnets. However, Sophos Firewall relies on **Clientless Users** (IP-to-identity mappings) to enforce user-level firewall rules, web filtering, quota management, and detailed traffic reporting.

Without automated synchronization:
- Administrators must manually register and maintain Clientless User entries in Sophos Firewall whenever devices join, renew, or change IP addresses.
- Firewall logs and reports display raw IP addresses rather than human-readable device hostnames, complicating security monitoring and incident response.

### How It Works

```text
┌─────────────────────────────────┐                 ┌──────────────────────────────────┐
│  Technitium DNS / DHCP Server   │                 │   Sophos Firewall (SFOS API)     │
│  - Active & Reserved Leases     │                 │   - Clientless Users             │
│  - Hostnames & IP Assignments   │                 │   - User Groups & Security Rules │
└────────────────┬────────────────┘                 └────────────────▲─────────────────┘
                 │                                                   │
                 │ 1. Fetch Leases (dhcp/leases/get)                 │ 2. Upsert Clientless Users
                 └──────────────────►  technitium-sophos-sync  ──────┘
                                        - Hostname Sanitization
                                        - Disambiguation & Conflict Checks
                                        - Dry-Run & Safety Validation
```

1. **Lease Extraction**: Queries Technitium's REST API (`/api/dhcp/leases/get`) to retrieve active and static DHCP lease records.
2. **Sanitization & Resolution**:
   - Sanitizes hostnames to comply with Sophos Firewall naming rules (handling special characters, spaces, and length restrictions).
   - Resolves MAC and hostname collisions with automatic suffixing and conflict checks.
3. **Sophos Synchronization**:
   - Interacts with Sophos Firewall via its XML API (`APIController`).
   - Automatically creates or updates Clientless User records and assigns them to configured Sophos User Groups.

---

## Features

- **Automated Synchronization**: Fetches DHCP active leases from Technitium API and maps them to Clientless Users in Sophos Firewall.
- **Dry-Run Mode**: Inspect changes that would be made before committing any changes to Sophos Firewall.
- **Daemon / One-Shot Modes**: Run as a one-time cron job or a background daemon with configurable polling intervals.
- **Static Lease Filtering**: Option to restrict synchronization exclusively to reserved/static DHCP leases.
- **Robust Sanitize Engine**: Automatically formats device hostnames to conform to Sophos Firewall naming constraints.
- **Container Ready**: Includes lightweight Docker image and `docker-compose.yml` for effortless deployment.

---

## Requirements & Recommended Account Setup

- **Python**: 3.11 or higher
- **Technitium DNS Server**: API Token generated from Technitium Web Console (**Administration -> API Tokens**).
- **Sophos Firewall (SFOS)**: Administrator account with API Access enabled (**System -> Administration -> API**).

### Sophos Firewall (SFOS) Recommendations
- **Dedicated Service Account**: Create a dedicated administrator account (e.g. `sync-api-user`) rather than using the default `admin` super-administrator account.
- **Role Permissions**: Assign an Administrator Profile limited to **Clientless Users** and **User Management** permissions.
- **API Access Restrictions**: Enable API Access in **System -> Administration -> API** and restrict allowed IP addresses exclusively to the IP or subnet running `technitium-sophos-sync`.

### Technitium DNS Server Recommendations
- **Dedicated API Token**: Generate a dedicated API token under **Administration -> API Tokens** named `technitium-sophos-sync`.
- **Token Scope**: Restrict token permissions to DHCP lease read access (`dhcp/leases/get`).

---

## Quick Start

### Installation

#### Option 1: Direct via Git (Pip / Pipx / uv)

```bash
# Install directly from GitHub via pip
pip install git+https://github.com/jelmervdm/technitium-sophos-sync.git

# Or install as an isolated CLI tool with pipx or uv
pipx install git+https://github.com/jelmervdm/technitium-sophos-sync.git
# or
uv tool install git+https://github.com/jelmervdm/technitium-sophos-sync.git
```

#### Option 2: From Source

```bash
git clone https://github.com/jelmervdm/technitium-sophos-sync.git
cd technitium-sophos-sync
pip install .
```

### Environment Configuration

Create a `.env` file or export environment variables:

```bash
# Technitium DNS/DHCP Server Settings
TECHNITIUM_URL=http://192.168.1.10:5380
TECHNITIUM_TOKEN=your_technitium_api_token

# Sophos Firewall Settings
SOPHOS_FIREWALL_IP=192.168.1.1
SOPHOS_FIREWALL_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASS=your_sophos_admin_password
SOPHOS_CLIENTLESS_GROUP=Clientless Open Group
```

### Execution

Run a single synchronization pass in dry-run mode:

```bash
technitium-sophos-sync --dry-run --once
```

Execute a live sync:

```bash
technitium-sophos-sync --once
```

Run in continuous daemon mode (re-syncing every 5 minutes):

```bash
technitium-sophos-sync --interval 300
```

---

## Command-Line Interface

```text
Usage: technitium-sophos-sync [OPTIONS]

  Technitium DHCP to Sophos Firewall Clientless User Sync utility.

Options:
  --technitium-url TEXT       Technitium Web Interface URL (default:
                              http://192.168.1.10:5380)
  --technitium-token TEXT     Technitium API Token
  --sophos-ip TEXT            Sophos Firewall Management IP Address
  --sophos-port INTEGER       Sophos Admin Web Console Port (default: 4444)
  --sophos-user TEXT          Sophos Firewall API Admin Username (default: admin)
  --sophos-pass TEXT          Sophos Firewall API Admin Password
  --clientless-group TEXT     Sophos Clientless User Group Name
  --static-leases-only / --all-leases
                              Sync reserved/static leases only
  --dry-run / --no-dry-run    Log changes without executing API calls against Sophos
  --verify-ssl / --no-verify-ssl
                              Verify SSL certificate when connecting to Sophos Firewall API
  -i, --interval INTEGER      Continuous sync interval in seconds (default: 0)
  --once                      Force execution to run once and exit
  -l, --log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]
                              Set logging verbosity level (default: INFO)
  -h, --help                  Show this message and exit.
```

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `TECHNITIUM_URL` | `http://192.168.1.10:5380` | Technitium server web console URL |
| `TECHNITIUM_TOKEN` | *Required* | Technitium API authentication token |
| `TECHNITIUM_TIMEOUT` | `10.0` | HTTP request timeout for Technitium API (seconds) |
| `SOPHOS_FIREWALL_IP` | `192.168.1.1` | Sophos Firewall IP address or hostname |
| `SOPHOS_FIREWALL_PORT` | `4444` | Sophos Firewall API port |
| `SOPHOS_USER` | `admin` | Sophos Firewall API username |
| `SOPHOS_PASS` | *Required* | Sophos Firewall API password |
| `SOPHOS_CLIENTLESS_GROUP` | `Clientless Open Group` | Sophos Group to assign created users |
| `SOPHOS_VERIFY_SSL` | `false` | Enable/disable SSL certificate validation |
| `SOPHOS_TIMEOUT` | `15.0` | HTTP request timeout for Sophos API (seconds) |
| `STATIC_LEASES_ONLY` | `false` | Sync only reserved/static DHCP leases |
| `SYNC_INTERVAL` | `0` | Daemon mode polling interval in seconds (`0` for single-pass) |
| `DRY_RUN` | `false` | Test sync logic without modifying Sophos Firewall |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## Docker & Kubernetes Deployment

### Docker Compose

The included [`docker-compose.yml`](docker-compose.yml) contains all environment variables with defaults:

```yaml
version: '3.8'

services:
  technitium-sophos-sync:
    image: ghcr.io/jelmervdm/technitium-sophos-sync:latest
    container_name: technitium-sophos-sync
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - TECHNITIUM_URL=${TECHNITIUM_URL:-http://192.168.1.10:5380}
      - TECHNITIUM_TOKEN=${TECHNITIUM_TOKEN:-}
      - SOPHOS_FIREWALL_IP=${SOPHOS_FIREWALL_IP:-192.168.1.1}
      - SOPHOS_USER=${SOPHOS_USER:-admin}
      - SOPHOS_PASS=${SOPHOS_PASS:-}
      - SYNC_INTERVAL=${SYNC_INTERVAL:-300}
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
```

Run container:

```bash
docker compose up -d
```

### Kubernetes

A base Kubernetes deployment manifest is provided in [`kubernetes.yaml`](kubernetes.yaml), including a `ConfigMap`, `Secret`, and `Deployment`:

```bash
kubectl apply -f kubernetes.yaml
```

---

## Development & Testing

Clone the repository and set up a local development environment with `uv` or `pip`:

```bash
git clone https://github.com/jelmervdm/technitium-sophos-sync.git
cd technitium-sophos-sync
pip install -e ".[dev]"
```

Run test suite:

```bash
pytest
```

Run type checking and linting:

```bash
mypy src tests
ruff check src tests
```

---

## License

Distributed under the [MIT License](LICENSE).
