# Daybreak Blue-assisted defensive assessment — 2026-09-30

## Status and provenance

This record describes an internal defensive adversarial assessment of ExitLane. Product Owner
explicitly selected Daybreak Blue through the Codex model selector before this assessment session.
It is not an independent penetration test, red-team exercise or external assurance opinion.

Source review began at `767823aed33bae3a72203f7277d76c0be6d75bc4`. Accepted fixes were reassessed
after merge at `c78bf8b3426d4f8963bc5cc377eebd44474c64b8`. The documentation commit that
contains this report is evidence-only and is recorded separately in issue #76.

## Scope

The review challenged authentication and setup state, sessions and MFA, CSRF/proxy/browser
boundaries, frontend DOM construction, privileged subprocesses, Proton profile import, PIA and
other provider parsers, provider switching, routing and killswitch state, management-route locking,
backup/restore/upgrade, the PVE helper, the development Docker surface, local static assets,
supply-chain policy, bounded availability and secret disclosure.

Dynamic work used local ephemeral application state, synthetic provider responses, inert hostile
configuration sentinels, isolated Linux network namespaces and the designated Debian 13 test-LXC
for non-destructive release-style checks. No real credentials or customer data were used.

Production systems, unknown third parties, the PVE management plane, VPN-provider infrastructure,
container or host escape research, exploit development and offensive validation were excluded.
No live PVE create/delete action was authorised. Potential impact steps outside the Blue scope were
not performed.

## Method

A private attack-hypothesis ledger recorded assets, trust boundaries, entry points, actors,
preconditions, suspected failures, current controls, gaps in existing tests, safe validation and
required evidence. Source and threat-model assumptions were treated as hypotheses. Phase 2 selected
bounded tests that exercised gaps rather than merely repeating scanners.

Confirmed findings were reproduced with inert or synthetic data, fixed one pull request at a time,
reviewed independently, tested on the exact PR head and re-challenged by the active Blue context
after remediation. Supporting reviewers did not make a separate Daybreak provenance claim. Sensitive
High-impact reproduction detail is retained in private draft security advisories.

## Sanitised findings and remediation

| Severity | Surface | Disposition | Remediation |
| --- | --- | --- | --- |
| High | Privileged network configuration input boundary | Fixed and retested; sensitive detail private | PR #81 |
| High | Privileged configuration restored from an authenticated backup | Fixed and retested; sensitive detail private | PR #84 |
| Medium | Streamed request body could exceed the configured bound when transport metadata was absent or understated | Fixed and retested | PR #82 |
| Medium | Provider-controlled catalog/JSON inputs lacked uniform size, shape or recursion bounds | Fixed and retested | PR #83 |
| Medium | Compressed tar metadata was outside the restore expansion-ratio accounting | Fixed and retested | PR #84 |
| Low | Latency targets, restored key length and future application-version compatibility had incomplete defensive validation | Fixed and retested | PRs #83 and #84 |

No Critical finding was confirmed. No unresolved Critical or High finding remains in the assessed
candidate. After the final fresh-main challenge, no additional confirmed vulnerability was
identified within the documented scope and evidence boundaries.

## Evidence

### Automated regression evidence

- All eleven required checks passed on the exact head of PRs #81 through #84.
- Fresh main `c78bf8b` passed 766 backend tests, 38 frontend suites and i18n parity.
- Post-merge CI, CodeQL, passive ZAP and supply-chain workflows passed on every remediation merge.
- Focused hostile-input regressions cover stream fragmentation, disconnects, JSON nesting,
  provider field types, archive expansion, corrupt gzip, key/version compatibility, raw-byte parser
  boundaries and rejection before restore mutation.

### Synthetic provider evidence

- PIA and Proton boundaries used fixtures and controlled synthetic peers only.
- NordVPN, Mullvad and PIA parser responses were treated as provider-controlled data.
- No provider infrastructure was used as a security test target.

### Native appliance evidence

- Each runtime remediation was deployed from its exact PR head to the Debian 13 test-LXC.
- Service, HTTP health and `/dev/net/tun` postconditions passed.
- A real loopback HTTP/1.1 chunked body exceeded the configured body cap and received `413` with
  the full response-security baseline.
- Existing native WireGuard state passed the restored-configuration validator read-only.
- Provider-egress and management-routing namespace tests passed, including the unavailable protected
  route, cleanup, provider preservation and idempotence cases.

### Daybreak Blue-assisted internal defensive assessment

The active Daybreak Blue context supplied the adversarial source review, hypothesis selection, safe
reproduction, remediation challenge and final fresh-main reassessment described here. Separate
supporting reviews challenged the diffs and evidence without being represented as Daybreak sessions.
This is internal assisted assurance.

### Independent external penetration test

None has been performed. A future independent external penetration test remains a separate
assurance layer.

## Paths not dynamically qualified in this assessment

- Live PIA account connectivity and live Proton provider connectivity remain unproven because no
  credentials were available.
- The PVE helper has no real create → boot → installer qualification because no disposable PVE
  mutation range was authorised.
- Docker remains `not yet suitable` as a supported appliance and was not upgraded by this review.
- Destructive guest reboot, interrupted upgrade and malicious-restore fault injection were not
  repeated on the shared native LXC. Existing automated and prior appliance evidence was reviewed;
  this session added non-destructive release-style checks.
- Restore validation proves privileged command-directive safety. It does not claim complete semantic
  validation of every non-command WireGuard field. Pre-mutation cryptographic pairing of a correctly
  sized restored master key with every encrypted database value remains unproven; HTTP health is not
  such a pairing proof.
- Transport inactivity timeouts do not establish a single total deadline for every provider response.

## Residual risk

ExitLane remains a root network appliance on a trusted management network. Root or hypervisor
compromise defeats application controls. Headerless non-browser writes remain an explicit trusted
network contract. Provider availability and schema behavior remain external dependencies. Release
source authenticity and independent external security assurance remain operator/project duties.

Within these limits, the assessment completed source review, bounded dynamic validation, finding
triage, fix/retest loops and a final fresh-main challenge. It does not support the claim that
“ExitLane is secure”; it records the evidence obtained and the boundaries left open.
