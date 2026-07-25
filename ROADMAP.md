# Roadmap

The roadmap describes direction rather than a release commitment. Priorities may change as the
beta is tested in real networks.

## Completed in v0.2.0-beta.1

- Encrypted, authenticated appliance backup
- Strictly validated root-only restore with session revocation
- Explicit monotonic database schema versioning
- Locked alpha-to-beta upgrade with a pre-upgrade recovery snapshot
- Automatic data, code, configuration, and systemd-unit rollback on installer failure
- Internal security-assurance matrix for lifecycle and existing application boundaries

## Completed in v0.2.0-alpha.1

- Authentication with local administrator sessions
- Dashboard 2.0 with consolidated operational status
- Application and dashboard settings
- Central frontend application state
- Explicit startup lifecycle and first-run routing
- Test-LXC deployment and smoke-test workflow
- Frontend unit tests
- English and Dutch internationalization (i18n)
- NordVPN CLI management
- WireGuard ingress configuration
- First-run wizard
- Generic webhook notifications
- Structured application Activity log
- Security-hardening and repeatable security-assurance baseline
- Self-service administrator password, NordVPN-token, and WireGuard management
- TOTP MFA and one-time recovery codes
- Active administrator session management
- Trusted reverse-proxy support and HTTPS awareness

## Next

- Provider abstraction hardening
- Additional VPN providers
- Better notification management
- Extended system logs and diagnostics
- Appliance and installation polish

## Later

- Independent security review and penetration test
- WebAuthn/passkeys
- High availability
- Metrics and monitoring integrations
- API tokens
- Supported public REST API
- Plugin architecture
