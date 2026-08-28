# Mullvad VPN provider

ExitLane supports Mullvad VPN as an optional commercial egress provider alongside NordVPN. Both
clients may be installed and signed in, but only the provider marked **Active** can connect through
ExitLane. Selecting no provider remains valid and routes WireGuard clients through the appliance's
normal internet route.

## Installation and onboarding

The supported target is Debian 13 `amd64`. In first-run step 3, select Mullvad VPN alone or together
with NordVPN. ExitLane's protected installer configures Mullvad's official stable HTTPS APT
repository with a dedicated `signed-by` keyring, verifies primary fingerprint
`A119 8702 FC3E 0A09 A9AE 5B75 D5A1 D4F2 66DE 8DDF`, installs `mullvad-vpn`, and starts
`mullvad-daemon`. It does not use the beta repository, `apt-key`, `trusted=yes`, or a remote shell
installer. The managed helper is idempotent and its progress can resume after a browser refresh.
The helper resumes an interrupted `dpkg` configuration and runs the complete package transaction
with `SYSTEMD_OFFLINE=1`. On the supported Debian
13 systemd baseline this keeps package-time `start` and `restart` operations from communicating with
PID 1 while client-side unit enablement still succeeds. ExitLane-owned systemd drop-ins are present
before APT runs: the Mullvad early-boot firewall initializer has a permanently absent condition,
and the normal daemon can start only with a short-lived controlled-start marker or a durable marker
written after successful gateway validation. The helper then starts the daemon itself and always
applies and verifies LAN sharing, Lockdown, auto-connect, and disconnected state. Mullvad 2026.4
does not expose tunnel and split-tunnel readback before an account is present, so IPv6-off and an
empty split-tunnel list are additionally applied and verified when an existing account is detected
or immediately after a new stdin-only account login, before that login is reported as successful.
Debian's `gpgv` package is installed explicitly for repository metadata verification.

The package-time boundary is validated against Mullvad 2026.4 and Debian 13 systemd 257. systemd's
[environment-variable reference](https://systemd.io/ENVIRONMENT/) documents `SYSTEMD_OFFLINE`, but
does not promise the same stability as a normal command-line interface. Both the package scripts
and this behavior must therefore be revalidated before a newer Mullvad or systemd release becomes
the supported baseline.

The official package requires its root-owned `/usr/bin/mullvad-exclude` helper to have a setuid bit.
The fixed Mullvad package-installer unit permits that one upstream package step; the ordinary
ExitLane service retains `RestrictSUIDSGID=true`, and ExitLane clears all split-tunnel exclusions in
its gateway baseline.

The validated client baseline for this integration is Mullvad VPN 2026.4. Current upstream usage
and installation documentation is available in Mullvad's official
[CLI guide](https://mullvad.net/en/help/how-use-mullvad-cli) and
[Linux installation guide](https://mullvad.net/en/help/install-mullvad-app-linux).

## Authentication and management

Mullvad authentication uses the 16-digit account number. Spaces in the UI are accepted and removed
before validation. The masked field is cleared immediately after submit. ExitLane passes the number
to the fixed local `mullvad account login` process over stdin and never stores, logs, displays, or
adds it to process arguments. Mullvad supports at most five registered devices per account; remove
an old device in [Mullvad account management](https://mullvad.net/account/) if ExitLane reports
`too_many_devices`.

After sign-in, choose a country from the same provider-neutral country and latency interface used
by NordVPN. Relay catalog output is parsed and validated inside the Mullvad provider. Missing
latency does not block connection. To change providers, open VPN Overview and choose **Make active**.
ExitLane disconnects and verifies the old active provider before persisting the new selection. A
disconnect failure leaves the old provider active.

ExitLane applies the unauthenticated appliance baseline during installation: auto-connect off, LAN
sharing on, Lockdown Mode off, and disconnected. Once an account is present it also verifies empty
split-tunnel exclusions, WireGuard egress, and IPv6 off before activation. Mullvad's normal
connection kill switch remains client-owned. Lockdown Mode is different and stays off so an
intentional disconnect does not take over appliance connectivity. The ExitLane killswitch remains
the policy for forwarded WireGuard/LAN traffic.

## Package lifecycle invariants

- Installing or upgrading Mullvad cannot independently activate a firewall policy that removes
  ExitLane management connectivity.
- `mullvad-early-boot-blocking.service` cannot apply appliance policy for an inactive or
  disconnected provider, even when an upstream package enables it again.
- A disconnected Mullvad provider must not leave `table inet mullvad` behind.
- Before the first controlled daemon start, interruption or reboot leaves both Mullvad services
  inactive. The durable daemon-start marker is created only after settings, firewall state, the
  management/default route, and disconnected state have all been verified.
- ExitLane never deletes or flushes Mullvad's nftables table during normal installation. An
  unexpected table is a fail-closed installation error.

## Troubleshooting without credentials

Run these read-only checks locally:

```console
sudo systemctl status mullvad-daemon.service --no-pager --full
sudo mullvad version
sudo mullvad status --json
sudo journalctl -u exitlane-provider-install-mullvad.service -n 100 --no-pager
sudo journalctl -u exitlane.service -n 100 --no-pager
```

Do not paste an account number into a shell command, issue tracker, journal query, or support log.
Installation errors exposed in the WebUI are stable ExitLane codes; raw Mullvad output is not
returned. `account_expired` means the account needs time; `too_many_devices` requires removing a
device; `provider_lockdown_enabled` requires disabling Mullvad Lockdown Mode before ExitLane can
safely manage the gateway.

An appliance upgraded from the pre-fix integration can contain the stale provider-owned firewall
table described by the 2026.4 early-boot incident. Recovery is an explicit console-only operator
procedure, not part of the managed installer:

```console
sudo systemctl stop mullvad-daemon.service mullvad-early-boot-blocking.service
sudo nft list table inet mullvad
sudo nft delete table inet mullvad
```

Delete only the exact inspected `table inet mullvad`; never flush the ruleset. Re-run the managed
installation immediately afterward so the ExitLane drop-ins and validated completion marker own
future startup behavior.

## Later live-account validation

Use only an authorized disposable Debian 13 appliance and an existing funded test account. Do not
record the account number in notes or shell history.

1. Confirm ExitLane is healthy, `mullvad-daemon` is active, auto-connect is off, Lockdown Mode is
   off, and Mullvad is disconnected.
2. Enter the account number only in ExitLane's masked WebUI field. Confirm it disappears immediately
   and inspect Activity plus the ExitLane journal for safe codes only.
3. Choose a country, connect, and confirm the WebUI's country/relay/interface and external IP agree
   with sanitized `mullvad status --json` observations.
4. Disconnect. Confirm normal host internet, local management, and WireGuard management remain
   reachable and no stale ExitLane firewall rule remains.
5. With both providers signed in, activate NordVPN and then Mullvad. Verify each switch disconnects
   the old tunnel before the new provider can connect.
6. Enable the ExitLane killswitch, repeat Mullvad up/down and reconnect, and confirm forwarded IPv4
   and DNS fail closed while local recovery remains reachable. Reboot and confirm neither provider
   connects unexpectedly.
7. End the Mullvad session from ExitLane, confirm the account number never appears in API responses,
   Activity, application logs, process argv, or temporary files, and remove the disposable Mullvad
   device from account management if required.

Never create or purchase an account as part of automated validation. Live authentication and
connectivity require a separately authorized test credential; all automated fixtures remain fake
and sanitized.
