# Upgrade and recovery

ExitLane supports an in-place Debian appliance upgrade from `0.2.0-beta.5` to
`0.2.0-rc.1`. Run the installer from a trusted, reviewed checkout
of the target release:

```bash
cd /path/to/exitlane
sudo ./installer/install-debian.sh
```

Do not run backup, restore, or a second installer concurrently. All lifecycle
commands use `/run/lock/exitlane-lifecycle.lock`; a conflicting operation fails
without changing the installation.

## Upgrade transaction

The installer:

1. verifies root, the supported Debian 13 `amd64` baseline, systemd, source layout, TUN, network
   administration, connectivity, and at least 512 MiB free space;
2. distinguishes a clean install from an existing database or package;
3. detects the installed and target versions and rejects a downgrade;
4. takes the exclusive lifecycle lock;
5. creates a root-only recovery directory below
   `/var/lib/exitlane/recovery`;
6. snapshots SQLite with its backup API and preserves the previous application,
   config, defaults, ExitLane systemd units, fixed provider-install helpers/units, and the validated
   Debian system timezone;
7. stops the application, installs the candidate, preserves operator defaults,
   reapplies permissions and units, and reloads systemd;
8. starts the service and checks that systemd reports it active;
9. records the installed version only after success.

The snapshot is deliberately local and mode `0700`; it is not a portable backup
and may contain plaintext secrets. Use `exitlane-cli backup create` for encrypted
off-appliance recovery.

Re-running the same installer is supported and preserves `/etc/default/exitlane`,
the application master key, SQLite data, and operator settings.

## Automatic rollback

An error after the recovery snapshot stops the candidate, restores the previous
code, database, configuration, defaults, systemd units, and provider-install helper/unit files,
removes candidate-only managed files, reloads systemd, and
attempts to restart the previous service. The snapshot is retained and its path
is printed. Provider packages and host-wide provider state are outside the
ExitLane ownership boundary and are not rolled back.
The Debian timezone is the exception: it is part of the ExitLane settings contract and is restored
from the root-only recovery snapshot before the previous service starts. A failed timezone restore
is reported as requiring manual recovery rather than being hidden.

The Mullvad daemon and early-boot drop-ins are exact recovery-snapshot paths as well. This preserves
or removes ExitLane's package-time firewall suppression together with the candidate. The Mullvad
package and provider-owned settings remain outside application rollback, but an ExitLane-managed
package transaction is offline with respect to PID 1 and cannot write the durable daemon completion
marker until the disconnected network baseline is proven.

If automatic service recovery cannot complete, inspect:

```bash
sudo systemctl status exitlane.service --no-pager --full
sudo journalctl -u exitlane.service -n 100 --no-pager
sudo ls -ld /var/lib/exitlane/recovery/pre-upgrade.*
```

Do not delete the most recent recovery directory until login, MFA, WireGuard,
reverse proxy, killswitch, Activity, and provider status have been validated.
The recovery directory is host-bound; for disaster recovery use an encrypted
`.elb` backup on a clean supported installation.

## Schema compatibility

Schema versions are monotonic and stored in the singleton `schema_version`
table. Alpha databases without that table are assigned schema version 1 during
the idempotent migration. An unknown or future schema causes startup and restore
to stop. Schema migrations must be transactional and accompanied by a
pre-upgrade recovery snapshot.
