# Changelog

## Unreleased

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
