# Disposable native lifecycle qualification

This is executable preparation for the [rc.4 qualification contract](0.3.0-rc.4.md),
not a receipt claiming that a native release passed. The scripts live in
`scripts/qualification/`; they are not installed into the product or exposed by its API.
CI exercises their state comparisons and actual application API/crypto with synthetic
fixtures. Only separately authorized disposable Debian 13 amd64 guests may run their
`--execute` stages. An authorization reference records the operator's existing scope;
it does not grant authority. No script creates, destroys or selects a PVE guest.

## Scope and prerequisites

Designate two disposable native guests: one for the previous-release upgrade and
rollback sequence, another for clean installation and disaster recovery. Record their
exact hostnames and `/etc/machine-id` values in private configuration. Do not use
CT100 or treat the existing CT123/reference appliance as fresh-create evidence. Keep
management reachability outside protected VPN routing. Do not attach real protected
clients to synthetic ingress or introduce commercial credentials. The isolated source
must not remain reachable when a second guest activates its restored WireGuard identity.

The runner supports the standard native paths and service configuration. It refuses
container execution, custom runtime/data paths, modified installed application content,
service overrides, untrusted files and a mismatched guest. Custom layouts require their
own reviewed qualification rather than modifying this tool to accept a false match.
The guest needs systemd, TUN, the ordinary supported installer prerequisites and access
to supported package repositories. Installation invokes the real installer and can
install/update packages, change services and configure forwarding on that guest.

Place clean, root-owned Git checkouts of the exact baseline and candidate on each
authorized guest. Resolve the actual published `v0.3.0-rc.3` commit for the baseline;
record the full SHA, not a moving branch. The candidate is the accepted release source.
Do not substitute source archives without the Git identity required by preflight.
Run the harness from that exact clean candidate checkout. Its own files are hashed into
the private run identity; changing the harness requires a new run, not receipt reuse.

Create a root-only configuration file (`0600`, single regular file, trusted parent
path) with exactly these fields. Replace every example value with the authorized
identities; the all-zero SHA values below are placeholders, not executable release
identities. Generate a fresh 32-character lowercase hexadecimal run ID, for example
with `python3 -c 'import secrets; print(secrets.token_hex(16))'`.

```json
{
  "run_id": "0123456789abcdef0123456789abcdef",
  "hostname": "designated-disposable-native",
  "machine_id": "0123456789abcdef0123456789abcdef",
  "authorization_reference": "Exact existing authorization and disposable target scope",
  "source": "/root/exitlane-candidate",
  "source_sha": "0000000000000000000000000000000000000000",
  "baseline": "/root/exitlane-baseline",
  "baseline_sha": "0000000000000000000000000000000000000000",
  "role": "upgrade"
}
```

## One explicit stage at a time

The default invocation only prints a plan. It does not establish guest compatibility,
installation success or authorization:

```bash
python3 /root/exitlane-candidate/scripts/qualification/native_lifecycle.py \
  --config /root/native-qualification.json --stage baseline-install
```

After verifying the designated target and existing authority, add `--execute` to run
one chosen stage. A stage lock prevents concurrent harness writers. Successful
prerequisites and their immutable artifacts are checked before dependent stages;
failed or incomplete attempts cannot be replayed or silently adopted. Preserve such a
run for diagnosis. Do not remove its started marker to force continuation.

For the upgrade guest (`role: upgrade`), execute in this order:

1. `baseline-install`: install the exact previous release into an empty native layout.
2. `seed`: use the real first-run API to create a synthetic administrator, MFA/recovery
   codes, settings, WireGuard ingress and an inactive imported Proton profile. The
   profile uses locally generated keys and `qa.invalid`; no provider connection occurs.
3. `rollback`: while the baseline remains installed, invoke the candidate installer
   with a qualification-only Bash wrapper that fails at entry to `commit_upgrade`,
   after service startup and before commit. The wrapper verifies that the installer
   created its recovery snapshot. The installer's own error trap performs rollback.
4. `upgrade`: run the ordinary candidate installer without fault injection.
5. `idempotence`: run that same installer again and verify retained state.
6. `backup`: create, inspect and verify a real encrypted synthetic backup using a
   root-only passphrase file.
7. `restore`: change a setting as a canary; reject wrong-passphrase and damaged-envelope
   restores without data/service/routing changes; restore the valid backup; verify
   retained state, revoked sessions, MFA recovery login and actual provider decryption.

For independent clean installation (`role: clean`), use `candidate-install`, `seed`,
`idempotence`, `backup`, `restore`. A disaster-recovery target instead stops after
`candidate-install` before importing the isolated source's synthetic backup, as described
below. Never simulate clean installation by deleting an existing appliance's state.

The fault wrapper sources the unmodified installer and invokes `main` directly with
its normal error handling. It neither patches production source nor supplies a runtime
fault flag. A rollback log line is insufficient: independently compare installed
content, database state, key, configuration, unit/helper files and private modes, then
wait for bounded HTTP readiness within one stable service invocation, then check
API/decryption. Rejected restores compare native nftables rules as well as compatibility
iptables rules, service identity, routes and staging; volatile handles/counters are
excluded from semantic nftables comparison. A failed rollback remains a failure even if
its installer trap suppresses a restart error.

## Disaster recovery on the second guest

On the source guest after a successful `backup` stage, export only the synthetic
portable bundle. Omitting `--execute` produces a plan for these commands too:

```bash
python3 /root/exitlane-candidate/scripts/qualification/native_disaster.py \
  --config /root/native-qualification.json --action export \
  --bundle /root/disaster-bundle --execute
```

The bundle contains seven private files: backup, passphrase, synthetic fixture,
source snapshot, source identity, backup receipt and manifest. Export validates the
source run's recursive receipt chain; import checks the portable artifacts and their
source/harness binding. These are root-operator evidence, not signed attestation.
Transfer the complete directory through the already authorized private operator route,
preserving directory `0700` and file `0600` ownership/modes. Do not use a public upload,
CI artifact or secret in command arguments. Preserve the original source evidence.

On the second designated guest, use a separate configuration with `role: clean`,
a fresh run ID, its own hostname/machine ID and the same candidate source SHA.
Run only `candidate-install` before disaster restore. The target must have no configured
users, ingress or provider state, and its initially generated master key must differ
from the source key. A copied live appliance or a previously seeded target is refused.

Isolate the source using the separately authorized infrastructure procedure **before**
restoring its ingress identity. Record the observed isolation outside the guest; the
following text reference is an operator assertion, not a network-isolation test:

```bash
python3 /root/exitlane-candidate/scripts/qualification/native_disaster.py \
  --config /root/native-qualification-target.json --action restore \
  --bundle /root/disaster-bundle \
  --source-isolation-reference 'Exact retained source-isolation evidence reference' \
  --execute
```

The target checks identity, installed source, prior clean-install receipt, different key,
backup integrity, actual restore, source state retention, target defaults, staging cleanup,
health and fresh MFA/provider decryption. Its empty initial browser jar makes this a
fresh-login and database-session-revocation check; old-cookie rejection is proved by the
source runner's separate `restore` stage. No source cookies are copied to the target.
Do not continue ordinary seed/upgrade stages in a disaster run. Preserve both guests and
all private evidence; neither tool performs cleanup or destruction of the appliances.

## Private evidence and claim boundaries

Each run lives under `/root/exitlane-native-qualification/<run_id>` (`0700`). Its
configuration binding, harness hashes, stage receipts, coherent SQLite fingerprints,
file inventories and child logs remain private. The fixture contains synthetic
passwords, MFA/recovery material and private WireGuard keys; the backup and passphrase
must never be attached to CI, issues or release artifacts. Public evidence should
contain only reviewed source identities, stage outcomes and explicit scope limits.

Snapshots include every actual SQLite table/column and compare retained rows, key,
WireGuard files, settings, application files, helpers, units, modes and ownership.
Only documented session-access bookkeeping and appended Activity events are allowed
through preservation comparisons. Restore requires sessions, MFA challenges and pending
enrollments to be cleared; it preserves target host defaults separately because portable
backups exclude `/etc/default/exitlane`. Take snapshots before authentication probes,
which legitimately update session timestamps or consume an MFA factor. Fingerprints
alone do not prove decryption; separate API/crypto checks provide that evidence.

This synthetic inactive profile proves encrypted-state preservation, not active-provider
generation recovery, token renewal, live PIA/Proton interoperability, management-plane
access from the LAN, or protected packet behavior during an actual upgrade. Empty cache
rows are not populated-cache preservation evidence. The existing namespace packet tests
remain complementary evidence, not a substitute for exact-source appliance dataplane
checks. Record these remaining rows explicitly in the release receipt and canonical
readiness matrix; do not convert a fixture PASS into a native release PASS.

Retain supported-package/advisory inventory and actual resolver configuration for the
same native guest and source. In particular, the existing glibc resolver availability
finding remains open until its own advisory and environment disposition changes.
Native package findings and Docker's strict publication scan are separate gates.
