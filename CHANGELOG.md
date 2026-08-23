# Changelog

## [0.2.0-beta.3] - 2026-08-23

### Added

- Managed, explicitly confirmed installation of the digest-pinned official Ookla Speedtest CLI on
  Debian 13 `amd64`, with package ownership validation, status polling, and no retained repository
  or signing key.
- Separate, explicitly confirmed Speedtest measurements with visible bandwidth and terms notices.

### Security

- Serialize Speedtest measurements, share the package-operation lock with provider installation,
  redact installer output to stable allowlisted status/error codes, and use the Packagecloud Debian
  artifact endpoint rather than its HTML package page.

### Release notes and follow-up

- Reviewed release notes live at `docs/release-notes/0.2.0-beta.3.md`.
- Integrated, versioned in-app documentation and error-to-document deep links remain a follow-up.

## [0.2.0-beta.2] - 2026-07-27

### Fixed

- Automatically load and incrementally display quick-choice latency measurements when the NordVPN page opens.
- Report the cached server-specific latency for the active VPN connection.
- Show a clear, localized message when a NordVPN access token is invalid or expired.
- Preserve stable provider error codes in the token form and never display raw provider output.

### Added

- Local password-recovery instructions on the login page.
- Protected restart, reboot, and shutdown actions under Settings > System.

### Changed

- Standardized Debian installer output and maintainer comments in English.

## [0.2.0-beta.1] - 2026-07-25

### Added

- Root-only encrypted appliance backup create, inspect, verify, and restore commands.
- Versioned authenticated backup envelope, logical manifest, checksums, and strict archive limits.
- Explicit monotonic SQLite schema version and fail-closed future-schema handling.
- Locked Debian alpha-to-beta upgrade with root-only pre-upgrade recovery snapshots.
- Automatic restoration of previous code, data, configuration, and systemd units after an
  installer failure.
- Traceable STRIDE/ASVS security-assurance matrix and lifecycle adversarial regressions.

### Changed

- Restore revokes all sessions, pending MFA enrollments, and outstanding MFA challenges.
- The installer now distinguishes clean install and upgrade, checks free space, preserves local
  operator defaults, refuses downgrades, and records the installed version after health succeeds.
- Security, hardening, deployment, roadmap, and recovery documentation now describe the beta
  lifecycle boundary.

### Security

- Backups use scrypt with unique salts and AES-256-GCM with unique nonces; the complete payload and
  bounded header are authenticated before archive parsing.
- Restore rejects untrusted paths, links, special files, duplicate names, unknown logical types,
  missing mandatory secrets, excessive sizes/counts/ratios, checksum failures, corrupt SQLite, and
  future schemas.

### Upgrade notes and known limitations

- Run `sudo ./installer/install-debian.sh` from a trusted beta checkout to upgrade
  `0.2.0-alpha.1`; create and verify an encrypted backup first.
- There is no signed automatic update channel. Local recovery snapshots contain plaintext secrets
  and must remain root-only. TLS termination remains external and direct Internet exposure is not
  supported.
- Independent security review, an independent penetration test, WebAuthn, high availability,
  public API, plugins, and additional providers remain future work.

## Unreleased

- Added optional TOTP MFA, encrypted secrets, one-time hashed recovery codes, replay protection,
  staged login challenges and root-only `exitlane-cli disable-mfa` recovery.
- Added idle plus absolute session expiry, safe active-session management and migration-driven
  logout for legacy sessions while retaining digest-only session-token storage.
- Added explicit trusted-proxy CIDRs, reliable client-IP/HTTPS awareness, automatic Secure cookies,
  conditional HSTS, deployment diagnostics and Caddy/Nginx/Traefik guidance.
- Introduced a central VPN provider registry, metadata and capability contract, generic provider
  API routes, and compatibility aliases for the existing NordVPN routes.
- Added provider-driven VPN navigation, Overview and management pages; removed provider credentials
  from general Settings and made the first-run provider step metadata-driven.
- Expanded VPN Overview with generic authentication and connection states, reliable operational
  details, provider-scoped latency, status timestamps, and view-scoped polling.
- Kept authenticated provider loaders and polling behind the administrator session lifecycle while
  preserving atomic VPN operation conflicts and independent WireGuard ingress.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Added documented threat/ASVS baselines, security regression and scanner CI, passive dynamic
  testing, HTTP security headers, service/filesystem hardening, and deployment/release guidance.

### Added

- Structured, persistent application events with bounded retention and privacy allowlists.
- Protected cursor-paginated events API and a translated, lifecycle-aware Activity view.
- Self-service administrator password changes with complete session revocation.
- Root-only interactive `exitlane-cli reset-password` recovery on the local host.
- Safe NordVPN token sign-in diagnostics, honest active-session handling, and a Settings link to
  existing WireGuard management.
- On-demand, authenticated WireGuard configuration QR codes generated with Segno.
- Explicit, confirmed NordVPN session ending followed by self-service token sign-in.

### Changed

- Split the frontend HTML into server-composed functional partials without changing runtime
  behavior.
- Extended Settings with Authentication, VPN, and WireGuard management sections.
- Kept protected provider data and polling inactive until administrator authentication succeeds.
- Added stable password-form layout and accessible live checks backed by the central policy.
- Separated provider installation, authentication, and tunnel states behind backend capabilities;
  killswitch management remains deliberately disabled and out of scope.

## [0.2.0-alpha.1] - 2026-07-22

### Added

- Local administrator authentication with login, logout, and session handling.
- Dashboard 2.0 for application, host, VPN provider, and WireGuard status.
- General settings and dashboard refresh preferences.
- English and Dutch interface translations.
- Light, dark, and system theme preferences.
- Test-LXC deployment and smoke-test tooling.

### Changed

- Reworked the frontend around central application state and explicit lifecycle phases.
- Made the first-run wizard transition into the authenticated application experience.
- Made dashboard polling lifecycle-aware and resilient to transient failures.
- Expanded the NordVPN and WireGuard management experience.

### Security

- Protected application API routes after initial setup.
- Added expiring, server-side sessions with hashed session tokens and HttpOnly cookies.
- Added same-origin validation for browser write requests.
- Used password hashing and generic authentication errors to reduce credential leakage.

### Developer experience

- Added frontend unit coverage for API, authentication, dashboard, i18n, lifecycle, navigation,
  polling, startup, and state behavior.
- Expanded backend tests for authentication, dashboard, providers, security, and settings.
- Added CI validation for Python, JavaScript, translations, JSON, shell scripts, and package builds.
