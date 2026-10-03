# Roadmap

The roadmap describes direction rather than a release commitment. Priorities may change as the
release candidates are tested in real networks.

The [canonical v1 readiness matrix](docs/release-checklist.md#canonical-v1-readiness-matrix) owns blockers, dependencies, evidence and authorization boundaries.

## Included in 0.3.0-rc.4

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

## Included in 0.3.0-rc.3

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

## Current engineering and qualification

D1–D7 Docker implementation and the Proxmox public launcher are delivered. PIA and imported Proton
implementation is also delivered. Historical synthetic/native-kernel and D6 receipts retain their
original source/image scope. Current exact-source qualification and support claims remain separate.

- Complete/reconcile the rc.4 release boundary before preparing v1.0.0-rc.1. Qualify native clean
  installation, rc.3 upgrade, rollback/recovery and the actual public tagged Proxmox path; preserve
  existing supported upgrade paths. The v1 RC then upgrades from fully qualified rc.4.
- Delivered the container operator Help slice [#116](https://github.com/kevindraai/exitlane/pull/116):
  runtime-appropriate local guidance, packaged recovery instructions and truthful capability limits.
  Independent exact-head review, full regression and native deployment checks passed.
- Run fresh whole-product security/readiness checks and reconcile applicable findings against the
  actual native package inventory. Complete the bounded installation/diagnostics gap review; fix
  material failure-comprehension, recovery or security gaps rather than broad cosmetic polish.
- Managed Speedtest installation evidence is reconciled in
  [#117](https://github.com/kevindraai/exitlane/issues/117): the actual beta.3 appliance receipt
  proves the unchanged pinned installer, four confirmations, package/status checks and zero
  measurements. Current integration regressions and native candidate lifecycle gates remain;
  this historical acceptance requires no new installation or terms approval.
- Refresh exact-candidate Docker build/content/runtime, security and affected packet/recovery
  evidence. Review D6 reuse against precise source/image/package deltas or execute required fresh
  host proof; implementation delivery alone is not completed publication/support acceptance.
- The [separate-namespace NordVPN gateway decision](docs/nordvpn-gateway-decision.md) is **NO-GO**
  for the evaluated stock candidates. The reviewed startup protection gap is distinct from the
  settled same-container #98 result. No gateway implementation or provider parity is claimed;
  native NordVPN stays unchanged and Docker NordVPN unavailable.
- Give the complete native v1 blocker matrix and architecture delta to fresh Astra review before
  preparing the first full v1 RC. Qualify that exact candidate before stable preparation. Actual
  release publication remains a Product Owner action boundary.

## External evidence and publication boundaries

- [#72 — PIA and Proton](https://github.com/kevindraai/exitlane/issues/72): live commercial-provider
  egress/switch/recovery proof requires authorized credentials/profile material. Implementation
  and synthetic proof do not establish fully supported live interoperability.
- [#87 — public Proxmox launcher](https://github.com/kevindraai/exitlane/issues/87): actual public
  one-liner → exact published helper/application → fresh create/boot/install/access/readiness and
  stop/start proof needs an explicitly designated disposable PVE host/new CTID scope. Existing
  protected guests are not substitutes. Follow the existing rc.4 two-stage publication sequence.
- [#90 — Docker support](https://github.com/kevindraai/exitlane/issues/90) and
  [#97 — publication](https://github.com/kevindraai/exitlane/issues/97): strict HIGH/CRITICAL/secret
  gating, exact release source/tag, complete qualification and separately authorized first GHCR
  publication remain open. The start-source refresh measured 44 HIGH records across eight CVEs,
  zero CRITICAL/secrets/Python advisories; all eight Debian advisories were still open at query.
  Keep receipts source-bound, consume supported fixes and remeasure at candidate boundaries;
  never waive findings. The protected environment is configured, but does not authorize dispatch.
  Digest, SBOM/provenance, pull/health/rollback and anonymous-pull proof remain required.
- Docker remains experimental/unsupported and unpublished until its own gates pass. An unresolved
  Docker-only publication dependency does not block the supported native release. Native/shared
  applicable blocking findings still require resolution under the existing release policy.
- External independent security review/penetration testing is a transparent readiness decision;
  no existing mandatory v1 requirement was found. Internal model-assisted reviews are not an
  independent external assessment.

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
