# Upgrade and recovery

The 0.3.0-rc.1 release line provides an in-place upgrade path from the published `v0.2.0` tag on
Debian 13 `amd64`. That historical tag reports runtime version `0.2.0-rc.1` and Python package
version `0.2.0rc1`; this is expected metadata, not evidence that another installation was selected.
The new runtime version is `0.3.0-rc.1` and its Python package version is `0.3.0rc1`.

## Before upgrading

Create and verify a portable encrypted backup, keep the local console available and schedule a
client-traffic interruption. Record any custom `/etc/default/exitlane`, systemd, host-network and
router settings separately. Do not change settings in the browser during the upgrade.

```bash
sudo exitlane-cli backup create /var/lib/exitlane/backups/pre-0.3.0-rc.1.elb
sudo exitlane-cli backup verify /var/lib/exitlane/backups/pre-0.3.0-rc.1.elb
```

Keep a protected copy outside the appliance. Once the target tag is published, use a separate
release checkout so the installer source is never the live `/opt/exitlane` directory:

```bash
git clone --branch v0.3.0-rc.1 --depth 1 https://github.com/kevindraai/exitlane.git exitlane-0.3.0-rc.1
cd exitlane-0.3.0-rc.1
sudo ./installer/install-debian.sh
```

Do not run backup, restore, or a second installer concurrently. All lifecycle
commands use `/run/lock/exitlane-lifecycle.lock`; a conflicting operation fails
without changing the installation.

## Upgrade transaction

The installer:

1. verifies root and takes the exclusive lifecycle lock;
2. checks the supported Debian 13 `amd64` baseline, systemd, source layout and TUN, installs required
   system packages, then checks connectivity and network-administration capability;
3. distinguishes a clean install from an existing database or package, rejects a downgrade and
   verifies at least 512 MiB free space;
4. prepares the application, configuration and private service-home directories while preserving
   the existing master key;
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

The package now requires AnyIO `>=4.14.2,<5`, so the installer's normal pip upgrade also replaces
older vulnerable AnyIO versions. Updating the development lockfile alone would not protect an
existing appliance installation.

## Mullvad and WireGuard changes

The direct Mullvad integration owns `wg-mullvad` and policy table `51820`. It does not install the
Mullvad app. Retire any existing app daemon or conflicting provider firewall state deliberately
before activation; follow the [Mullvad conflict procedure](mullvad.md#legacy-mullvad-app-conflict).

On startup, an older ingress profile with fixed NordVPN forwarding rules is migrated to
provider-neutral forwarding. Its existing keys, peer configuration and client profile remain
unchanged. Changing VPN providers does not require replacing the router's ingress profile.

Choose a new ingress name only during initial provisioning. Renaming an already configured
interface is rejected; profile regeneration keeps its name. With a stored active or pending Mullvad
generation, reboot and restore establish the mandatory routing guard before ingress starts.
Reconnect explicitly after recovery and verify the client path.

## After upgrading

```bash
sudo systemctl status exitlane.service --no-pager
curl --fail http://127.0.0.1:8787/api/health
sudo cat /etc/exitlane/installed-version
```

Confirm the new version, sign in with the existing account and MFA, check saved settings and the
ingress profile, then connect the intended provider. From a routed client, verify DNS, the public
exit and the configured disconnect/killswitch behavior. Check management and reverse-proxy access
from their normal networks and inspect Activity for failed operations. An active service alone is
not proof that the router's traffic uses the VPN.

After a planned reboot, also check the routing services and the configured ingress unit. Replace
`wg0` below with the ingress interface shown in WireGuard settings:

```bash
sudo systemctl status exitlane-provider-egress.service exitlane-management-routing.service \
  wg-quick@wg0.service --no-pager
sudo journalctl -b -u exitlane-provider-egress.service -u exitlane-management-routing.service \
  -u wg-quick@wg0.service --no-pager
```

WireGuard startup waits for routing preparation, and route updates from separate processes are
serialized. A failed routing or ingress unit requires investigation even when the API health check
passes or the interface exists. Keep the failed-boot journal for diagnosis and verify management
access and the routed client path after recovery.

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

Legacy Mullvad helper and daemon-drop-in paths remain in the exact recovery snapshot allowlist so a
failed upgrade can restore the previous candidate losslessly. The direct integration does not
install or activate those artifacts. Existing Mullvad packages and provider-owned firewall state
remain outside automatic rollback and are surfaced as a conflict for deliberate operator cleanup.

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

Recovery directories are root-owned and mode `0700`. Copied application files and systemd units
retain their original modes inside that private boundary so rollback restores executable and unit
permissions exactly. Newly written snapshot metadata and database/key material remain private.
