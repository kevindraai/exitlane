# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
