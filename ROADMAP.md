# Roadmap

The roadmap describes direction rather than a release commitment. Priorities may change as
operators use the stable release in different networks.

The [v1 release record](docs/release-notes/1.0.0.md) holds the completed release evidence;
the [readiness matrix](docs/release-checklist.md#canonical-v1-readiness-matrix) retains its
historical planning and qualification trail.

## Historical scope: 0.3.0-rc.4

rc.4 is now published and its actual public Proxmox path qualified; #87 is complete.
The original scope/status statements below are historical and superseded by the current v1
readiness matrix and release-policy decision.

- Guided public Proxmox bootstrap resolving one published tag for the helper and guest, with
  inspect-first trust guidance and compatible older-helper negotiation.
- PVE umask isolation, `_apt` resolver-readability checks, stable readiness rounds, fail-hard APT
  repository errors and frozen-resource revalidation.
- Proxmox installer access/output polish: optional masked console credentials, validated public
  keys, key-only SSH default, explicit password SSH and bounded root-only host logs.
- D1–D7 same-core Docker implementation: explicit runtime capabilities, guarded ingress and
  direct-provider dataplane, mutation leases/journalled recovery, a separate experimental
  image/Compose surface, historical D6 synthetic disposable-host acceptance and gated D7
  release infrastructure. Docker remains unsupported; no official production image exists.
- Supported Debian Trixie package refresh in appliance image builds; strict publication scanning
  still includes unfixed advisories with no waiver.
- Stock NordVPN Linux 5.4.0 container research decision: **NOT SUITABLE** under the retained
  minimal/read-only contract. Native NordVPN remains unchanged; container parity is not promised.
- Development dependency maintenance: urllib3 2.8.0, Ruff 0.16.9 and CodeQL Actions v4.38.2.

These are delivered implementation scope, not publication or completed rc.4 qualification.
Current checks, refreshed scans and exact-source appliance receipts belong in the
[rc.4 release notes](docs/release-notes/0.3.0-rc.4.md). PIA and imported Proton implementation is
inherited; synthetic/native-kernel qualification does not establish live provider proof.

## Historical scope: 0.3.0-rc.3

- Clear provider selection and keyboard-accessible configuration tabs in the setup wizard.
- Reliable NordVPN installation after switching providers.
- NordVPN administrator documentation in the repository and integrated Help.
- Mobile Help layout corrections.
- Tuned.pixel identity/token migration and appliance-focused Cobalt / Slate polish.
- Repository-owned Proxmox VE helper for a privileged Debian 13 LXC, with deterministic safety
  tests and dry-run support; live PVE creation remains unqualified.
- Docker appliance feasibility decision: `not yet suitable`; the image remains development-only.
- Daybreak Blue-assisted internal defensive assessment with remediations #81 through #84 and a
  final fresh-main challenge. This is not an independent penetration test.

## Historical scope: 0.3.0-rc.1

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

## Delivered in v1.0.0

The stable v1 scope is native Debian 13 amd64 with NordVPN, Mullvad, PIA and imported Proton,
and the Docker appliance with the three direct providers on rootful Linux amd64,
Engine >=28 and Compose v2. Stock container NordVPN and the separate NordVPN gateway are excluded.

- Guided public Proxmox installation, exact-tag/source binding and appliance lifecycle (#87).
- Native installation, upgrades from qualified rc.4/v1 RC and encrypted recovery.
- Versioned official Docker image, complete deployment Quick Start, explicit LAN bindings,
  durable state and backup/restore/upgrade/compatible rollback instructions (#90/#97).
- Full security evidence with reviewed Debian residual-risk dispositions; actionable findings
  remain release blockers. No scanner suppression, unsupported suite or package surgery.
- Source/image/digest binding, SBOM/provenance and published-image operator qualification.

The [published v1.0.0 release](https://github.com/kevindraai/exitlane/releases/tag/v1.0.0) records
immutable identities, qualification results and issue acceptance. Historical implementation
sections retain their original scope. Live PIA/Proton interoperability remains unqualified (#72);
it is claim-specific and does not change the accepted product scope. No Docker latest alias exists.

## After v1

- Evidence-backed additional providers and broader relay-availability research.
- General direct-provider IPv6 egress, including Mullvad.
- Broader notification features and operational diagnostics beyond concrete current release gaps.
- WebAuthn/passkeys, high availability and metrics integrations.
- Public API tokens, a supported public REST API and plugin architecture.
- Additional CPU architectures and wider Docker host/configuration matrices.

Investigate credible discoveries enough to establish a plausible integration or operator outcome,
deduplicate against open and closed issues, and retain decision-ready backlog issues. A newly
discovered opportunity is not a v1 blocker unless a concrete correctness/security dependency is
established. Optional Nord gateway work and future providers must not inflate the native v1 scope.
