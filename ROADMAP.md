# Roadmap

The roadmap describes direction rather than a release commitment. Priorities may change as the
release candidates are tested in real networks.

## Included in 0.3.0-rc.2

- Clear provider selection and keyboard-accessible configuration tabs in the setup wizard.
- Reliable NordVPN installation after switching providers.
- NordVPN administrator documentation in the repository and integrated Help.
- Mobile Help layout corrections.

## Included in 0.3.0-rc.1

- Direct Mullvad WireGuard egress alongside NordVPN, with one active provider at a time.
- Explicit ownership of the registered Mullvad device, encrypted credentials and provider keys.
- Protected connect, relay switching, tunnel loss and restored or interrupted provider generations.
- Protection for locally generated traffic using the exact provider-assigned source address.
- Recovery that restores routing before ingress, revokes sessions and preserves the device identity.
- Installer rollback that preserves original executable and systemd-unit permissions.
- An AnyIO security minimum enforced for appliance upgrades as well as locked development installs.
- Operator guides for Mullvad onboarding, deployment, backup, migration and upgrade from `v0.2.0`.

These are implementation scope, not a statement that a preparation branch has been released.
Publication and qualification receipts belong to the tagged release and its
[release notes](docs/release-notes/0.3.0-rc.1.md).

## Completed in v0.2.0-beta.5

- Restored the complete pre-merge review and final-main release-assurance chain.
- Required the existing CI, CodeQL, supply-chain and ZAP checks for `main`.
- Added automatic CodeQL validation on pushes to `main` and policy-level Action SHA enforcement.
- Added clean-install qualification for the supported Debian 13 `amd64` appliance baseline.

Beta.5 inherits the beta.4 UX, accessibility, design-system and integrated-documentation baseline.

## Completed in v0.2.0-beta.4

- Cobalt / Slate design-system adoption and bounded UX/accessibility polish.
- Integrated authenticated documentation and contextual help links.

## Completed in v0.2.0-beta.1

- Encrypted, authenticated appliance backup
- Strictly validated root-only restore with session revocation
- Explicit monotonic database schema versioning
- Locked alpha-to-beta upgrade with a pre-upgrade recovery snapshot
- Automatic data, code, configuration, and systemd-unit rollback on installer failure
- Internal security-assurance matrix for lifecycle and existing application boundaries

## Completed foundations in v0.2.0-beta.2 and beta.3

- Provider-neutral VPN registry, navigation, status and capability boundaries
- Connection diagnostics with the Device -> ExitLane -> VPN -> Internet flow
- Explicit ping, DNS, external-IP and Speedtest actions
- Managed, digest-pinned Ookla Speedtest CLI installation with separate legal and package-change
  confirmations
- Protected restart, reboot and shutdown actions

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

- UX and visual consistency polish
- Provider abstraction hardening
- Further VPN providers and broader relay-availability testing
- IPv6 egress support for Mullvad
- Notification management improvements
- Appliance and installation polish
- Extended operational logging and diagnostic depth

## Later

- Independent security review and penetration test
- WebAuthn/passkeys
- High availability
- Metrics and monitoring integrations
- API tokens
- Supported public REST API
- Plugin architecture
- Qualification of additional architectures and container configurations
