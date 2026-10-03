# Beta release checklist

This checklist is evidence-driven. An incomplete required pre-publication gate blocks tagging
and publishing the release. The narrowly defined rc.4 public-launcher stage below
is the only explicitly authorized post-publication gate. Evidence may be recorded in the release task, a
release pull request, or linked GitHub evidence.

Do not claim that a check is complete unless its evidence is included or linked.
Screenshots are optional when equivalent machine-verifiable appliance evidence
is available, such as command output, test logs, redacted journal output, API
responses, or a recorded verification checklist.

## Release identity and source

- [ ] The final implementation pull request is approved and merged, not merely
  closed. Record an independent pre-merge `APPROVE` on the exact final pull-request head.
- [ ] Local `main` is clean and exactly matches the current `origin/main`.
- [ ] The exact final `origin/main` release SHA is recorded as runtime release
  evidence: `<release-sha>`.
- [ ] The recorded release SHA contains every intended release change.
- [ ] Runtime, installer, package, changelog, and tag versions are mutually
  consistent.
- [ ] The intended tag and GitHub release do not already exist.
- [ ] The release is prepared from the exact recorded `origin/main` commit, not
  from a feature or release branch.
- [ ] No direct commit, reset, rebase, force-push, tag overwrite, or tag move is
  used to prepare the release.

A dedicated release branch is not required. If documentation or metadata must
change before release, update it through a normal pull request, merge it, and
repeat every final-main gate against the new `origin/main` commit. Codex must
not merge a release pull request unless explicitly instructed.

## Automated validation

- [ ] Backend tests, frontend tests, Ruff check and formatting check, Bandit,
  pip-audit, compile or configured type checks, JavaScript syntax, JSON and i18n
  validation, Bash syntax, ShellCheck, namespace and killswitch tests,
  wheel/sdist builds, package-content validation, and `git diff --check` pass
  from a clean checkout of the recorded release SHA.
- [ ] Gitleaks, CodeQL, dependency review, ZAP baseline, packaging,
  supply-chain checks, and every other applicable required GitHub check pass on the final
  `main` commit. Dependency review is PR-only: record its exact approved PR-head result
  separately, plus fresh final-main dependency auditing; never label a skipped job as a pass.
- [ ] Built package metadata reports the expected PEP 440 version.
- [ ] Final package contents and generated artifacts contain no secrets,
  sessions, private keys, backups, logs, databases, or unexpected files.
- [ ] No blocking critical or high finding affects the application packages or supported native
  release. Classify findings by affected artifact and native/shared applicability. Docker-only
  base/OS findings remain blockers for the separate image publication, with complete evidence
  retained and no waiver. Any shared/native applicable HIGH/CRITICAL still blocks the application
  release. Review medium findings with linked disposition; do not suppress scanner evidence.
- [ ] Commands, counts, results, and links for final validation are recorded as
  release evidence.

## Appliance lifecycle

- [ ] Clean installation on every supported Debian release succeeds.
- [ ] Upgrade from the supported previous release succeeds and creates the
  documented protected pre-upgrade snapshot.
- [ ] Settings, MFA, recovery codes, sessions, Activity, reverse proxy, trusted
  proxies, WireGuard, provider authentication, token renewal, and killswitch
  state are preserved as documented.
- [ ] Re-running the installer is idempotent.
- [ ] An injected upgrade failure restores code, database, configuration,
  units, version state, permissions, and a healthy service without leaking
  secrets.
- [ ] Encrypted backup creation, inspection, verification, restore, and
  old-session rejection succeed.
- [ ] Disaster restore onto a clean appliance succeeds.
- [ ] The malicious restore corpus leaves active data and service state intact
  and cleans staging plaintext.
- [ ] IPv4, IPv6, DNS UDP/TCP, and tunnel-present leak tests pass, including
  fail-closed tunnel-unavailable behavior, recovery, and preservation of
  non-ExitLane nftables tables.
- [ ] Release-specific appliance behavior is verified and linked on the exact merged-main SHA.
  Verify preservation of database, secret key, users, sessions, MFA, recovery codes, WireGuard,
  settings and contractually retained provider/cache state. Existing provider, killswitch,
  lifecycle, rollback and system-action evidence remains required unless the release record cites
  an explicit checklist allowance for unchanged code.
- [ ] Appliance evidence is included or linked; unchecked appliance
  verification remains a release blocker.

## Web and operational security

- [ ] A bounded read-only active scan targets only the designated test
  appliance, and the passive CI scan passes on the final candidate.
- [ ] Authenticated crawling and the unauthenticated route matrix pass, including
  authorization for documentation and OpenAPI routes.
- [ ] Login and MFA enumeration, replay, concurrency, rate limiting, expiry,
  rotation, revocation, password change, and local recovery are verified.
- [ ] Setup and access route variants, the CSRF origin/content-type matrix,
  trusted-proxy chain/IP/CIDR edges, Host/public-URL mismatch, cookie flags,
  cache headers, CSP, and HTTPS-context HSTS are verified.
- [ ] Provider hostile-output and input-validation tests pass, including bounded
  availability behavior and confirmation that secrets and raw provider output
  are not exposed.
- [ ] Filesystem owners and modes, systemd state and hardening, logs,
  diagnostics, and health checks are verified.

## Documentation and handoff

- [ ] Backup and restore, upgrade and recovery, threat model, assurance matrix,
  ASVS, hardening, changelog, roadmap, security policy, and beta limitations
  are current and written in English.
- [ ] Deployment and appliance evidence reflect the exact recorded release SHA.
- [ ] Release evidence records the implementation PR, original and final SHAs,
  commands, test counts, findings, residual risks, appliance results, and
  branch-protection confirmations.
- [ ] Every checked item has included or linked evidence; the release
  description does not claim completion based only on unchecked or unlinked
  assertions.
- [ ] A maintainer or explicitly authorized release agent has performed the merge only after the
  independent pre-merge approval and every required gate passed on the final pull-request head.

## Tag and release-candidate publication

- [ ] Every preceding pre-publication gate is complete before creating a tag.
- [ ] An annotated version tag is created at the recorded release SHA and pushed
  without force.
- [ ] The GitHub release targets that exact tag and SHA, uses reviewed English
  release notes and follows the current release channel policy. For rc.4, the Product Owner
  explicitly requires consistency with rc.3: `prerelease=false`, `make_latest=true`. The rc tag,
  runtime/package versions and prose still identify a release candidate; these GitHub channel
  flags do not assert stable maturity.
- [ ] Attached artifacts, when required by the established workflow, are built
  from the recorded release SHA and published with verified SHA-256 checksums.
- [ ] The published tag resolves to the recorded SHA, release notes render
  correctly, downloadable artifacts match their checksums, and no unrelated
  branch or repository file was modified.

## rc.4 public Proxmox stage (explicit Product Owner sequencing exception)

All normal final-main, native lifecycle, security, package and candidate gates must pass before
tagging. The moving public launcher cannot resolve rc.4 until the actual GitHub release exists.
The work order therefore authorizes a two-stage sequence, solely for this public-resolution gate:

- [ ] Before publication, qualify exact candidate helper/install behavior on a designated fresh
  disposable native Debian 13 amd64 privileged LXC and qualify rc.3 → rc.4 upgrade.
- [ ] Immediately after publication, run the ordinary public main one-liner on the authorized PVE
  host. Prove resolution of the actual rc.4 release, exact helper integrity, new-container creation
  and same-tag installation, networking, access/log controls, service/UI/API and stop/start.
- [ ] Preserve the guest and secret-free receipts; CT100 and CT123 are excluded from fresh-create
  proof. Do not auto-destroy guests. Record the final SHA and artifact digests outside that source
  commit, in the release body and qualification receipt.
- [ ] Mark the release fully qualified only after this second stage passes. A public-path failure
  is an rc.4 defect: retain evidence, diagnose and use a bounded reviewed follow-up release. Never
  move the rc.4 tag or claim #87 completed without proof.

No Docker publication, support declaration, container aliases or production rollout is authorized.

## Canonical v1 readiness matrix

This section owns the v1 blocker classification. The preceding checklist remains the qualification
contract; the roadmap links here rather than maintaining a second acceptance matrix. Source-bound
receipts, hashes and hosted run results belong in linked issue/release records. A historical receipt
is not a fresh candidate result. Reconcile this matrix after each accepted merge and before RC
preparation. Independent Astra review is engineering evidence, not release authorization or an
external penetration test.

The authorized release ladder is **complete/reconcile 0.3.0-rc.4 → qualify v1.0.0-rc.1 → prepare
v1.0.0**. Native Debian 13 amd64 remains the reference runtime. Docker support/publication and the
optional separate NordVPN gateway have independent gates; neither may indefinitely delay native
v1 solely because its optional capability or image publication remains unavailable.

Engineering began at `03f8de679975d59b8bd6125a66cc99b5682e2ff9`. The runtime Help
outcome [PR #116](https://github.com/kevindraai/exitlane/pull/116) merged as
`c870527b15248e28b4df5100153c10b8a5257e15` after independent immutable-head APPROVE,
2,137 backend tests, native Help/health/auth checks and all required hosted gates. These are
engineering receipts, not full native release or Docker support qualification.

“Claim-specific” means the missing evidence prevents that feature's full support claim, not the
supported native product with its existing explicit capability limitations. It grants no authority
to weaken an existing gate or silently change a product contract.

| Item | User/operator outcome | Current state | Dependency | Required evidence / receipt | Blocks native v1 | Independently blocks Docker support | External authorization/dependency and next action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Exact-source checks and security readiness | Trustworthy installable candidate without unresolved release-blocking regressions | Fresh engineering checks in progress; historical assurance retained | Accepted implementation main and immutable review | Complete checklist above: backend/frontend, i18n, package, static/CodeQL, dependencies/secrets, ZAP, auth/MFA/session/CSRF/proxy, hostile provider/config/archive inputs, backup abuse cases, route/DNS/IPv6 and install/rollback evidence; [assurance matrix](security/security-assurance-matrix.md) | Yes | Yes for shared/affected surface | Execute all credential-free gates; scoped appliance checks require the established authorized target |
| Native package/advisory applicability | Accurate native security decision without hiding OS risk | Fresh Docker findings measured; native applicability remains an evidence task | Actual candidate-appliance package inventory, package source/version and advisory assessment | Retain exact installed native packages, applicable advisory/package relationships, supported update availability and shared application dependency findings; unresolved applicable blocking HIGH/CRITICAL prevents release | Yes where applicable | Docker uses its separate strict image gate | Obtain native inventory on authorized appliance and classify findings; do not infer applicability or exemption from container counts alone |
| Native lifecycle and recovery | Safe clean installation, preserved state and usable rollback/recovery | Current release-level clean-install/upgrade/disaster-recovery receipts outstanding | Exact source, compatible previous release and disposable native scope | Fresh rc.3 → rc.4 qualification first; then fully qualified rc.4 → v1 RC upgrade, idempotence, injected rollback, encrypted backup/restore, session revocation, private modes, management and protected dataplane; [rc.4 contract](qualification/0.3.0-rc.4.md) | Yes | Shared changes must retain native regressions; separate container proof also required | Designated disposable native appliance for mutation/fault cases; preserve existing supported v0.2/RC upgrade paths with proportionate regression evidence |
| Public Proxmox launcher / rc.4 completion | Public one-liner creates the correct accessible appliance from one published tag | Implementation delivered; fresh authorized public-path proof incomplete | Pre-publication candidate/native gates, published rc.4 and fresh disposable PVE scope | Actual one-liner → tagged helper → fresh create/boot/install → access/log/readiness → stop/start; [#87](https://github.com/kevindraai/exitlane/issues/87) | Yes through the mandated rc.4 release ladder | No separate Docker runtime dependency | PO designates disposable host/new CTID scope and execution route; after separately authorized rc.4 publication run actual public path. CT100 untouched; CT123 is not fresh-create proof; no guest destruction |
| Managed Speedtest installation evidence | Proven bounded privileged installer without accidental measurement | Historical gate satisfied by the actual beta.3 appliance receipt; stale blocker reconciled | Unchanged pinned installer/helper/service and current integration regressions | [Security evidence decision](security/security-assurance-matrix.md#managed-speedtest-installation-evidence-decision), [actual installation receipt](https://github.com/kevindraai/exitlane/pull/55#issuecomment-5389355442), [#117](https://github.com/kevindraai/exitlane/issues/117); missing-tool, four confirmations, one installation, exact package/ownership/status and zero measurement actions | No outstanding historical installation blocker; current regression gates remain | No; capability unavailable | No new installation, terms acceptance or measurement is needed to reconcile this receipt. Candidate native lifecycle qualification remains separate |
| PIA and Proton live interoperability | Honest support for existing direct WireGuard providers | Implemented and synthetic/native-kernel qualified; live qualification outstanding | Authorized PIA account and Proton profiles | Existing manual DoD: live egress, region/profile switch, reconnect, service/reboot recovery, management, DNS/no-plaintext and provider switching; [#72](https://github.com/kevindraai/exitlane/issues/72) | Claim-specific; retain explicit unproven-live limits | Claim-specific for each advertised provider | PO authorizes actual credentials/profile material; complete all credential-free checks now, leave issue open until its own acceptance passes |
| Docker operator Help and capability truth | Container installation has relevant local guidance and no unusable native actions | Delivered in PR #116; native behavior and installed guide verified | Accepted PR #116 | Runtime catalog/direct-route/auth tests, packaged offline guide, native behavior preservation, UI/i18n and deployment evidence; [PR #116](https://github.com/kevindraai/exitlane/pull/116) | Shared/native regression gate only | Yes for complete operator outcome | No outstanding implementation; retain final candidate regression evidence |
| D1–D7 direct-provider runtime | Safe supervised same-core container appliance | Implementation delivered; historical D6 accepted, current candidate refresh in progress | Exact image/source and declared host/state contract | Installed content, capabilities, health/auth/MFA/proxy, persistence, backup/restore/schema compatibility, lifecycle and packet/DNS/IPv6/switch/rollback evidence; [#90](https://github.com/kevindraai/exitlane/issues/90), [D6](qualification/docker-host.md) | No, except shared regression defects | Yes | Execute local/credential-free harnesses. Whole-host restart/fault proof needs explicitly disposable authorized hosts; retain pending rows until proved or justified by reviewed evidence reuse |
| Docker security publication gate | Reproducible image with no blocking findings | Start-source refresh: 44 HIGH records / eight CVEs, zero CRITICAL, secrets and Python advisories; all eight Debian findings still open at query | Exact candidate build, supported Debian security fixes and fresh scanner data | Complete Trivy/secret/Python reports, SPDX, installed package inventory, exact image/source/base identities and current Debian status; [#97](https://github.com/kevindraai/exitlane/issues/97) | No for Docker-only findings; native/shared applicability assessed above | Yes | Consume supported fixes normally, rerun affected qualification; retain strict failure when unfixed. No suppressions, severity changes, package surgery or unsupported suites |
| First GHCR publication and support acceptance | Verifiable versioned image, safe replacement and public pull | D7 machinery delivered; no official image published | Clean image gate, qualified published source/tag, complete qualification and support review | Exact tag/SHA, registry digest, SPDX/provenance identity, pull/health/rollback and anonymous pull; [#97](https://github.com/kevindraai/exitlane/issues/97), [#90](https://github.com/kevindraai/exitlane/issues/90) | No | Yes | `ghcr-production` verified: kevindraai reviewer, prevent self-review, no admin bypass, main only. First production dispatch/push and visibility change still require explicit PO authority; environment presence is not approval |
| Separate NordVPN gateway decision | Optional isolated Nord egress with precise ownership and truthful capabilities | Reviewed NO-GO for evaluated stock candidates; [decision and evidence](nordvpn-gateway-decision.md) | Current primary evidence and fresh Astra ownership/security challenge | Reviewed explicit GO/NO-GO, candidate/license/supply-chain evidence and failure-state model proof; existing [#98](https://github.com/kevindraai/exitlane/issues/98) applies only to stock client inside ExitLane | No | No for direct-provider Docker; yes for any gateway support claim | Decision complete; no gateway implementation selected. Reopen only on material supported upstream architecture evidence; #98 remains settled |
| Bounded appliance/diagnostic polish | Operators understand installation failures, blocked traffic and safe recovery | Help gap addressed in PR #116; no additional generic enhancement assumed mandatory | Concrete reproduced supportability/correctness gaps | Existing install failure/log/readiness, diagnostics and recovery tests; accepted fixes linked to their issue/PR | Only identified material correctness/security gaps | Same, within Docker boundary | Capture larger enhancements as deduplicated backlog; do not turn broad polish into unbounded v1 work |
| External independent security assessment | Clear independent-assurance limits | No existing PO decision establishing external pentest as a v1 blocker found | External scope, assessor and PO readiness decision | Optional scoped assessment package; actual independent report if commissioned | No established blocker; unresolved internal blocking findings still block | No established blocker | Present decision transparently; internal Sol/Astra/Daybreak evidence is not an external penetration test |
| v1 RC scope and publication | First full v1 candidate from reviewed, checked main | Not ready to cut; preceding native blockers remain | Fully reconciled rc.4, stable support matrix, fresh pre-RC Astra challenge and exact-source candidate qualification | Full readiness matrix, architecture delta and reconciled findings; immutable review, native lifecycle/security/package receipts and all applicable checks | Yes | Docker remains independently gated | Prepare v1.0.0-rc.1 only after prerequisites; actual release/tag publication needs PO authorization |
| Stable v1.0.0 | Supported native release with accurate optional-runtime claims | Not ready; requires qualified v1 RC and no unresolved release-blocking regression | Accepted v1 RC evidence and final release review | Complete exact-source release checks and evidence for every support claim | Yes | Docker support only if its own gates pass | Prepare stable release after candidate acceptance; actual publication and stable channel selection require PO authority |

### Evidence reuse and sequencing

The dependency graph is: accepted functional slices → fresh main/checks and scoped security
reconciliation → rc.4 native pre-publication qualification → separately authorized rc.4 publication
→ real public PVE proof → complete rc.4 → stable v1 support matrix and fresh Astra pre-RC challenge
→ exact-source v1.0.0-rc.1 qualification → separately authorized candidate publication → resolve
candidate regressions and prepare v1.0.0. No stable claim follows directly from incomplete rc.4.
The latest qualified rc.4 is the immediate v1 RC upgrade baseline; existing supported historical
upgrade paths remain regression obligations rather than silently removed support.

Docker and optional Nord gateway engineering proceed independently wherever dependencies permit.
Native v1 may describe Docker as experimental/unpublished when Docker's unchanged gates remain
open. PIA/Proton live claims remain explicitly limited until their evidence exists. Outstanding
commercial credentials, disposable infrastructure, supported-base fixes and publication authority
are recorded separately from unfinished internal engineering.

D6 is not automatically invalidated by every SHA change, nor automatically inherited by a rebuilt
image. A reuse decision must identify the previously qualified source/image/host/package inventory,
compare exact candidate source and image/package deltas, map them to affected failure-matrix rows
and independently review which receipts remain applicable. Repeat affected cases and close every
required row; until then, fresh whole-host proof or justified reuse remains pending. A docs-only
change may justify substantial reuse; a changed network/runtime/toolchain/package boundary needs
concrete analysis. No receipt is relabelled as evidence for a source it did not test.

The rc.4 GitHub `prerelease=false` / `make_latest=true` exception is specific to that release.
For the v1 RC, prepare `prerelease=true` with no latest promotion; confirm these flags with the
actual publication authorization. Stable latest designation requires the actual authorized stable
release decision. GitHub release flags do not authorize a Docker `latest` alias; retain the
separate container channel policy and publication gate.

Additional providers, general direct-provider IPv6 egress, broad notifications, passkeys, high
availability, metrics, public API tokens/REST API, plugins, additional architectures and broader
Docker matrices are post-v1 unless evidence establishes a specific correctness/security dependency.
Credible discoveries become decision-ready issues; they do not silently expand this blocker matrix.
