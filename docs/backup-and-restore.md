# Backup and restore

ExitLane beta uses a local, root-only appliance backup. Restore is intentionally
not exposed through the web interface.

## Scope

The encrypted backup contains:

- a consistent SQLite snapshot made with SQLite's backup API;
- the explicit database schema version;
- the ExitLane application version;
- `/etc/exitlane/secret.key`, which is required to decrypt MFA material;
- regular WireGuard configuration files owned by ExitLane;
- a versioned manifest with logical file types, sizes, modes, and SHA-256
  checksums.

It excludes sessions as useful recovery credentials (all restored sessions are
revoked), caches, logs, sockets, PID files, temporary state, provider output,
NordVPN host-wide state, and provider credentials that ExitLane does not own.
The SQLite snapshot necessarily contains session rows while it is being created,
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

The passphrase is read without echo. Automation may use `--passphrase-file`
with a regular, single-link file whose mode grants no group or other access.
Never pass the passphrase as a command-line argument.

Restore creates a root-only pre-restore database/key snapshot, stops the service,
replaces validated data, reapplies mode `0600`, revokes security state, starts
the service, and performs a database integrity check. A failed replacement or
health validation restores the pre-restore database and key. Operators must
retain the encrypted source backup until application login, MFA, WireGuard,
killswitch, and provider integration have also been checked.

## Compatibility

Format version 1 and database schema version 1 are supported. Unknown backup
formats and future database schemas fail closed. A newer application backup must
not be restored onto an older package; install the matching or newer supported
ExitLane release first. Missing WireGuard data is allowed. The database and MFA
master key are mandatory and restored as one recovery unit.

Backups contain highly sensitive appliance data even though they are encrypted.
Use a strong unique passphrase, keep multiple offline copies, restrict access,
and test restore regularly.
