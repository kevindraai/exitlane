# Experimental container state and recovery

D4 adds durable state and recovery mechanisms to the same ExitLane core. Docker
is still unsupported. Full application composition, image/Compose deployment,
disposable-host restart qualification and publication remain D5–D7 gates under
[#90](https://github.com/kevindraai/exitlane/issues/90). Native Debian/LXC remains
the reference implementation.

## Durable contract

One private `/data` volume contains:

| Path | Contract |
| --- | --- |
| `layout.json` | Layout version 1, schema read/write interval `[1,1]`, SHA-256 binding to the master key. Root-only integrity bookkeeping, not external authenticity. |
| `config/secret.key` | Exactly 32 bytes; co-persisted with the database. |
| `state/exitlane.db` | SQLite settings, Activity, authentication/MFA and encrypted provider state. WAL/SHM/journal sidecars belong to the same volume. |
| `state/wireguard/` | Validated ingress configuration; no arbitrary executable hooks. |
| `state/provider-egress/` | Reconstructible direct-provider projections; persisted but not authoritative proof of connectivity. |
| `recovery/` | Bounded transaction journal, staged candidate and coherent previous snapshot. Never included recursively in portable backups. |
| `backups/` | Optional encrypted native-format backups. |

Directories are root-owned mode 0700; files are root-owned mode 0600, regular,
bounded and not hard-linked or symlinked. An empty private volume initializes a
complete staged database/key/manifest pair through the durable journal. Existing
unmanifested development state is refused; it is not automatically adopted.
Missing components, incorrect key binding, incompatible schema and unreadable
provider/MFA ciphertexts refuse startup before networking is enabled. A matching
key digest does not replace authentication of the encrypted rows.
An otherwise valid private pair can carry a hot SQLite rollback journal after
abrupt process/container loss. The read-only inspector specifically reports
`SQLITE_READONLY_ROLLBACK` (776). Startup blocks forwarding, quiesces writers and
lets SQLite recover its own journal through `mode=rw` (which cannot create a
missing DB), then repeats full validation. It never deletes a hot journal by hand
or regenerates a key. Unknown errors remain refusals. Wrong key/manifest binding
is checked before this recovery can mutate networking or database state.
An interruption while creating the initial empty directory skeleton, before the
first durable journal receipt, likewise refuses unmanifested state. That interval
contains no published database/key; it requires operator inspection rather than
automatic adoption or deletion. Recorded initialization phases are recoverable.

All Mullvad, PIA and imported Proton state, including inactive credentials,
profile keys and active/pending generations, is validated with the shared
provider parsers. Ambiguous recovery markers remain blocked. Reconstructing a
pending projection never commits it or registers a replacement provider key.
NordVPN cannot become the selected container provider. Projected files never
serve as a persisted dataplane proof; a restarted runtime requires fresh D3
observations before protected forwarding can open.

## Mutation ownership

The supervisor owns the exclusive mutation authority. The order is lifecycle
lease → provider claim → network lock. Requests that can update sessions,
Activity or settings participate, including authenticated GET requests; monitors
participate too. Native mutation contexts remain no-ops and retain existing
native locking and behavior.

A private `/run/exitlane/control.sock` (0700 directory, 0600 socket) authenticates
root peers through `SO_PEERCRED`. A held socket connection carries one bounded,
nonrenewable application lease. Backup/restore callbacks already own this lease
and do not acquire it again. CLI recovery is a supervisor request, never a second
process writing the database independently. Passphrases use a masked prompt or a
bounded stdin line and the local socket body, never argv or environment variables.
Readonly status exposes only fixed recovery/worker booleans and states.

Loss or expiration of the lease first guards networking and stops/reaps the known
owned writer. A failed quiesce permanently poisons the authority; another writer
is not granted access. A disconnected restore caller does not release an active
commit/rollback. Quiesce must not wait on the control callback that is awaiting
quiesce. Worker process groups must be created as owned sessions, stopped and
reaped; a crashed parent alone is insufficient proof that child writers stopped.

The application startup boundary remains explicitly fail-closed for a container
worker until D5 supplies the supervisor-held bootstrap handoff. This avoids a
nested lease deadlock while restore validates a newly started worker. D4 does not
silently enable the full application runtime.

## Backup, restore and interrupted recovery

Portable encryption, archive grammar, limits, WireGuard-hook validation and
SQLite inspection are shared with native backup format 1. The portable inventory
contains database, master key and ingress files; provider generations are in the
encrypted database. Container-local journal metadata is not a new portable format.

Restore requires `RESTORE EXITLANE`. Before networking changes, the candidate is
decrypted, staged and validated with its own key and schema. The temporary
`inet exitlane_recovery_guard` drops traffic from both old and restored ingress
interfaces/subnets while the permanent D3 guard preserves provider source
protection. ExitLane touches only its exact owned namespace policy.
Before selectors are available during startup recovery, the temporary table
instead drops all namespace forwarding; management/control-plane access remains
separate. A successful guard hook means actual protection/readback, never a no-op.

After ingress/writers are quiesced, the previous database is snapshotted through
SQLite backup (including WAL content), together with its key, ingress,
provider-egress projections and manifest. The journal and directory entries are
fsynced before publication. Known SQLite sidecars are removed only while writers
are stopped. Restored sessions, MFA challenges and enrollments are revoked.
Reconciliation reconstructs validated provider projections under observed guards;
health/network postconditions precede reopening ingress.

Interrupted publication restores the coherent previous pair, or completes a
journalled fresh initialization. Committed candidates are revalidated. Future or
corrupt journals are refused, not guessed or deleted. Failed rollback retains the
journal/snapshot and keeps forwarding blocked for operator recovery.

## Qualification boundary

Deterministic tests exercise missing/wrong keys, complete provider inventory,
unsafe files, lease concurrency/disconnect/expiry, session revocation, journal
phases and individual publication replacements with different old/new master
keys. The owned-volume Docker harness adds real namespace/ingress protection,
recreation and killed-process recovery. It complements D3's connected-provider
packet matrix; it does not claim host reboot or Docker-daemon restart evidence.
Those operations require D6's independently disposable Docker host.

Image replacement must satisfy schema `[1,1]` before a worker can start. An older
image tag alone is not a rollback guarantee; retain a compatible encrypted backup
and the exact previous image identity. Future schema migrations must define their
pre-migration recovery boundary before widening this interval.
