# Security Policy

## Reporting a Vulnerability

If you discover a potential security vulnerability within `technitium-sophos-sync`, please report it by opening a private GitHub Security Advisory or contacting the maintainer directly.

Please do not disclose security vulnerabilities publicly until they have been addressed.

## Security Best Practices

- **API Credentials**: Never commit passwords or API tokens to source control. Use environment variables or `.env` files (which are ignored by `.gitignore`).
- **SSL Certificates**: While `--no-verify-ssl` is available for self-signed certificates on internal networks, we recommend installing valid certificates or internal CA root certificates on your firewall management interface.
