# ExitLane

**Smart egress for every network.**

ExitLane is a self-hosted VPN gateway for selected routers, devices and containers. Give each
consumer its own named WireGuard peer. ExitLane manages one shared outbound connection, so you can
change the active VPN provider or location without replacing every consumer's configuration.

![ExitLane dashboard showing appliance health, VPN exit and WireGuard ingress](docs/images/promo/exitlane-dashboard-hero.png)

## Why ExitLane?

Most routers can connect to commercial VPN providers by importing WireGuard or OpenVPN configuration files. That works, but changing countries or servers often means replacing those configurations in the router.

ExitLane separates the two responsibilities:

```text
Router ────────────┐
Host or container ─┼── WireGuard ingress ── ExitLane ── shared egress ── Internet
Other device ──────┘
```

Your router remains provider-agnostic. It uses one peer for all clients it forwards through the
tunnel. A host or container that connects directly gets another peer. ExitLane handles the VPN
provider and protects traffic according to one shared policy.

ExitLane works alongside UniFi, OPNsense, pfSense and OpenWrt, with the router still selecting
which traffic uses the gateway.

## Installation

This README follows the current `main` branch. **v1.0.0** is the latest published release;
features added since that tag are on `main` and will ship in a later release. Install the tag
for a released appliance. Native support is Debian 13 `amd64`; the Docker appliance runs on
rootful Linux `amd64`. The [release page](https://github.com/kevindraai/exitlane/releases/tag/v1.0.0)
has the published files and image details.

Keep the management interface on a trusted network; see the
[hardening guide](docs/security/hardening-guide.md) for firewall and reverse-proxy settings.

For Proxmox VE, run the interactive launcher as root on the host. It creates a new privileged
Debian 13 `amd64` LXC with the network permissions ExitLane needs:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/kevindraai/exitlane/main/installer/proxmox.sh)"
```

Choose Recommended or Advanced settings and confirm the container plan. The launcher selects a
published release and uses its tag for both the helper and guest installation. The
[Proxmox guide](docs/proxmox-lxc.md) covers defaults, trust and manual creation.

For a native Debian host or manually created LXC, install the published release tag:

```bash
git clone --branch v1.0.0 --depth 1 https://github.com/kevindraai/exitlane.git
cd exitlane
sudo ./installer/install-debian.sh
```

For an existing appliance, [back up and verify its state before upgrading](docs/upgrade-and-recovery.md).
For Docker, follow the [Docker Quick Start](docs/docker-deployment.md#quick-start), which covers
the published image, host requirements and persistent state. Native installs open the first-run
wizard at `http://<host>:8787`. Docker binds management to loopback by default; follow its guide
to select an explicit LAN bind or trusted HTTPS proxy before opening the wizard from another
machine. ExitLane does not terminate TLS; use the
[reverse-proxy guide](docs/deployment/reverse-proxy.md) for HTTPS.

## Providers

Native installations support NordVPN, Mullvad, PIA and imported Proton WireGuard profiles. Docker
supports Mullvad, PIA and imported Proton profiles. Connect one active provider at a time; a native
appliance can also use direct internet egress. Direct WireGuard providers currently carry IPv4
traffic and block protected IPv6. PIA and Proton are implemented, but live commercial-provider
interoperability remains unqualified. Start with the
[provider guides](docs/architecture/providers.md) for setup.

## Interface

The WebUI puts provider control, device management, diagnostics and version-matched Help in one
place.

<details>
<summary>Explore the application screens</summary>

### Appliance dashboard

The compact dashboard brings the active VPN exit, WireGuard ingress, protection and system health
into one overview.

![ExitLane dashboard with the active VPN, ingress and system status](docs/images/exitlane-dashboard.png)

### VPN provider control

Configure a provider, choose a location and reconnect without replacing consumer profiles.

![ExitLane VPN page with provider status and location selection](docs/images/exitlane-vpn-selection.png)

### Connection diagnostics

Trace the live path from the client through ExitLane and the VPN to the internet. Individual ping,
DNS, external-IP, and bandwidth-aware Speedtest actions remain explicit administrator choices.

![ExitLane connection diagnostics showing the client-to-internet path](docs/images/exitlane-diagnostics.png)

### WireGuard ingress devices

Manage multiple named devices on one WireGuard ingress interface. Each has its own keypair and
tunnel IP. The device list shows its last handshake, endpoint and traffic; each device's menu
offers its configuration and individual rename, regeneration and revocation actions.

Use a separate peer for each consumer. Sharing a profile can cause endpoint flapping and prevents
accurate traffic attribution or independent revocation. See
[WireGuard device management](docs/wireguard-configuration.md) for host and container setup.

![ExitLane WireGuard page listing named peers and their connection status](docs/images/exitlane-wireguard.png)

### Integrated documentation

Open version-matched administrator guides in the WebUI and follow contextual links directly from
the relevant operational screen.

![ExitLane Help page with local administrator guides](docs/images/exitlane-documentation.png)

</details>

## More capabilities

- Local administrator sessions, password recovery, TOTP MFA and one-time recovery codes.
- Passphrase-encrypted appliance backups, staged restore and rollback on failed native upgrades.
- English and Dutch interface, appearance and refresh settings, webhook notifications and an
  Activity log.
- Existing single-client installations migrate to a named peer while preserving their keys and
  router configuration.

## Architecture

ExitLane serves its WebUI and API from one FastAPI application and stores durable appliance state
in SQLite. WireGuard ingress gives each consumer an independent identity; one active provider and
shared protection policy control egress. Native installations can also use direct internet egress.

See [Architecture](docs/architecture.md), [WireGuard device management](docs/wireguard-configuration.md)
and [Diagnostics](docs/diagnostics.md) for the design details.

## Security posture

Keep the optional native killswitch enabled if routed clients must remain blocked after an
explicit VPN disconnect. Docker always blocks protected clients without an active provider.
See the [security policy](SECURITY.md) and [hardening guide](docs/security/hardening-guide.md).

## Docker appliance

The Docker appliance runs on Linux `amd64` with rootful Docker Engine 28 or newer and Compose v2.
It supports Mullvad, PIA and imported Proton WireGuard profiles. It requires TUN, `NET_ADMIN`, a
read-only root filesystem and durable state, and keeps protected clients blocked until a provider
is connected. Follow the [Docker Quick Start](docs/docker-deployment.md#quick-start) for the
versioned image, host networking, backups and upgrades. There is no `latest` image alias.

## Development

See [Development](docs/development.md) and [Contributing](CONTRIBUTING.md) for the project workflow.
AI assists with implementation, tests and documentation; people own product decisions, review and
release approval.

## Roadmap

Planned work is tracked in the [roadmap](ROADMAP.md).

## License

ExitLane is licensed under the [GNU General Public License v3.0](LICENSE).
