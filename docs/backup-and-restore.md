# Backup and restore

ExitLane 0.3.0-rc.2 uses a local, root-only appliance backup. Restore is intentionally
not exposed through the web interface.

## Scope

The encrypted backup contains:

- a consistent SQLite snapshot made with SQLite's backup API;
- the explicit database schema version;
- the ExitLane application version;
- `/etc/exitlane/secret.key`, which decrypts MFA and ExitLane-owned provider state;
- encrypted Mullvad account, registered-device and WireGuard key state stored in SQLite;
- regular WireGuard configuration files owned by ExitLane;
- a versioned manifest with logical file types, sizes, modes, and SHA-256
  checksums.

It excludes sessions as useful recovery credentials (all restored sessions are
revoked), filesystem caches, logs, sockets, PID files, temporary state, provider output,
NordVPN host-wide state, and provider credentials that ExitLane does not own. Application packages,
OS packages, `/etc/default/exitlane`, custom systemd overrides and router-side policies are also
outside this backup. Record their required configuration separately. The active Mullvad egress
configuration is recreated from the restored encrypted provider state during explicit reconnect.
The SQLite snapshot includes database cache rows, such as VPN latency results.
It also contains session rows while it is being created,
but restore deletes every session, pending MFA enrollment, and MFA challenge
before the service becomes available.

## Format and cryptography

The `.elb` envelope starts with the fixed `EXITLANE-BACKUP` magic and a bounded
JSON header. Format version 1 uses scrypt (`N=32768`, `r=8`, `p=1`) with a unique
128-bit salt to derive an AES-256-GCM key. A unique 96-bit nonce is used for each
backup. The header is authenticated as associated data and the complete
compressed payload is authenticated before archive parsing.

Archive entries never select restore paths. Only the fixed logical types
`database`, `master_key`, and `wireguard_config` are accepted. Restore rejects
links, devices, sockets, FIFOs, duplicate or nested names, traversal, unexpected
files, missing required files, excessive sizes, excessive file counts, and
excessive compression ratios. It verifies the manifest, every checksum, the
database schema, and SQLite integrity before replacing active data.

## Commands

Create a backup to a root-only destination:

```bash
sudo exitlane-cli backup create /var/lib/exitlane/backups/appliance.elb
```

Inspect metadata or perform full authentication and integrity verification:

```bash
sudo exitlane-cli backup inspect /var/lib/exitlane/backups/appliance.elb
sudo exitlane-cli backup verify /var/lib/exitlane/backups/appliance.elb
```

Restore after verifying that the target appliance runs the same or a newer
compatible ExitLane release:

```bash
sudo exitlane-cli backup restore /var/lib/exitlane/backups/appliance.elb
```

The command asks for the passphrase and the exact confirmation `RESTORE EXITLANE`. Schedule an
interruption of client traffic and keep local console access available while it runs.

The passphrase is read without echo. Automation may use `--passphrase-file`
with a regular, single-link file whose mode grants no group or other access.
Never pass the passphrase as a command-line argument.

Restore holds protected forwarding, stops the service, creates a root-only pre-restore
database/key/WireGuard snapshot, and replaces validated data. It reapplies mode `0600`, revokes security state, starts
the service, and performs a database integrity check. A failed replacement or
health validation restores the pre-restore database, key and WireGuard files. Operators must
retain the encrypted source backup until application login, MFA, WireGuard,
killswitch, and provider integration have also been checked.

## Compatibility

Format version 1 and database schema version 1 are supported. Unknown backup
formats and future database schemas fail closed. A newer application backup must
not be restored onto an older package; install the matching or newer supported
ExitLane release first. Missing WireGuard data is allowed. The database and MFA
master key are mandatory and restored as one recovery unit. Backups from the historical `v0.2.0`
release may report `0.2.0-rc.1`; that tag shipped Python package version `0.2.0rc1`.

Backups contain highly sensitive appliance data even though they are encrypted.
Use a strong unique passphrase, keep multiple offline copies, restrict access,
and test restore regularly.

## Mullvad identity and appliance migration

For direct Mullvad egress, the encrypted database and master key preserve the registered device and
WireGuard keypair. Restore does not register another device. A temporary forwarding guard covers
both the old and restored protected interfaces while services and files are replaced. Provider
routing and the configured killswitch are restored before ingress becomes available; this also
applies when the backup records the optional killswitch as disabled. Reconnect explicitly after
restore. If network recovery fails, the temporary guard and root-only recovery snapshot remain for
local recovery rather than releasing unverified traffic.

For recovery onto another appliance:

1. Create and verify an encrypted backup while the original device identity is still registered.
   Store the backup and its passphrase securely; the passphrase is not recoverable from ExitLane.
2. Shut down or otherwise isolate the original gateway. Do not sign out of Mullvad on it: sign-out
   revokes the remote device also referenced by the backup. Never run both copies with that identity.
3. Install the same or a newer compatible ExitLane release on a clean supported appliance. Restore
   required host defaults, networking and trusted-proxy configuration separately.
4. Place the encrypted backup on the replacement with restricted access, verify it there, then run
   the restore command from its local console. A newly generated installation key is replaced by
   the original key from the authenticated backup.
5. Sign in again with the restored administrator account and complete MFA. Previous browser
   sessions and pending MFA challenges/enrollments are revoked.
6. Confirm the expected ingress interface and client profile, the provider's signed-in state and
   killswitch policy. Reconnect Mullvad explicitly; check internet access, DNS and the public exit
   from an actual routed client before redirecting production traffic.
7. Confirm management access from its trusted network and retain the encrypted backup until the
   replacement has passed those checks. Keep the original gateway isolated.

Restore disables the previous configured ingress and establishes the restored one under a
temporary forwarding guard. It recreates required WireGuard service links and installs provider
protection before starting ingress. If recovery fails, inspect the local CLI result and service
journal, preserve the recovery snapshot and keep client traffic blocked until recovery is verified.

A revoked Mullvad device remains revoked after restore. The account and appliance data can still
be recovered, but reconnect requires deliberate provider account/device recovery. NordVPN state
outside ExitLane's database must be restored or signed in separately.
