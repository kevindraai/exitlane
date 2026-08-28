# ExitLane

**Smart egress for every network.**

ExitLane is a self-hosted egress appliance for routers, VLANs, and selected devices. Your router maintains one permanent WireGuard tunnel to ExitLane, while ExitLane manages the outbound connection through the official NordVPN or Mullvad VPN Linux client.

The result is an experience closer to a native VPN app, but for an entire network: switch countries, reconnect, use the fastest available server, and keep provider-specific configuration away from your router.

![ExitLane appliance dashboard](docs/images/promo/exitlane-dashboard-hero.png)

> [!WARNING]
> The management interface is intended for a trusted network and must not be exposed directly to the internet.

The trusted management network is a deployment assumption, not a substitute for application security. See the [hardening guide](docs/security/hardening-guide.md), [threat model](docs/security/threat-model.md), and [security policy](SECURITY.md).

## Why ExitLane?

Most routers can connect to commercial VPN providers by importing WireGuard or OpenVPN configuration files. That works, but changing countries or servers often means replacing those configurations in the router.

ExitLane separates the two responsibilities:

```text
Selected clients or VLANs
          |
        Router
          |
   permanent WireGuard tunnel
          |
       ExitLane
          |
 active commercial VPN provider
          |
       Internet
```

Your router remains provider-agnostic. It only knows about the WireGuard peer. ExitLane handles provider authentication, server selection, reconnects, tunnel monitoring, and killswitch protection.

ExitLane does not replace UniFi, OPNsense, pfSense, or OpenWrt. It complements them by moving VPN-provider management into a dedicated appliance.

## Interface

### Appliance dashboard

Monitor appliance health, the active VPN exit, WireGuard ingress, killswitch protection, and system
resources from one overview.

![ExitLane dashboard](docs/images/exitlane-dashboard.png)

### VPN provider control

Install and sign in to NordVPN, Mullvad VPN, or both. Choose one active provider, select a country, compare measured latency, and reconnect without importing new provider configuration into the router.

![ExitLane NordVPN country selection](docs/images/exitlane-vpn-selection.png)

### Connection diagnostics

Trace the live path from the client through ExitLane and the VPN to the internet. Individual ping,
DNS, external-IP, and bandwidth-aware Speedtest actions remain explicit administrator choices.

![ExitLane connection diagnostics](docs/images/exitlane-diagnostics.png)

### WireGuard router tunnel

View the connected router peer and manage the current client configuration. The configuration can be viewed, copied, downloaded, shown as a QR code, or regenerated.

![ExitLane WireGuard configuration management](docs/images/exitlane-wireguard.png)

### Integrated documentation

Open version-matched administrator guides in the WebUI and follow contextual links directly from
the relevant operational screen.

![ExitLane integrated documentation](docs/images/exitlane-documentation.png)

## Features

### VPN management

- Install, authenticate, configure, connect, and disconnect the official NordVPN and Mullvad VPN Linux clients.
- Keep multiple providers installed and signed in while enforcing exactly one active egress provider.
- Switch VPN countries from the WebUI and compare measured latency for quick choices.
- Discover registered VPN providers and view provider authentication and tunnel status separately.
- Protect routed client traffic with a configurable killswitch when no usable VPN tunnel is active.

### WireGuard ingress

- Generate a WireGuard ingress interface and router client configuration.
- Monitor the connected router tunnel and transferred traffic.
- View, copy, download, display as QR code, or regenerate the current configuration.

### Authentication and security

- Create the first local administrator account during setup.
- Protect the application and API with expiring server-side sessions.
- Change the administrator password in Settings and revoke existing sessions.
- Recover a forgotten password locally with `sudo exitlane-cli reset-password`.
- Under **Settings > System**, an authenticated administrator can restart only
  `exitlane.service`, reboot the instance, or shut it down. Shutdown cannot be
  reversed from ExitLane; host, hypervisor, or physical access is required.
- Enable TOTP multifactor authentication, use one-time recovery codes, and manage active sessions.
- Run behind an explicitly trusted HTTPS reverse proxy.

### Appliance lifecycle

- Create passphrase-encrypted, authenticated appliance backups from the root-only CLI.
- Inspect and verify backups before a strictly staged local restore.
- Upgrade with an exclusive lifecycle lock, recovery snapshot, schema compatibility checks, and automatic rollback after installer failure.

### Operations

- Configure the Debian appliance timezone, dashboard refresh interval, language, and light, dark,
  or system appearance.
- Configure generic webhook notifications.
- Keep structured activity events for up to 90 days and 5,000 records by default.
- Use the interface in English or Dutch.
- Integrate through the REST API.
- Trace Device -> ExitLane -> VPN -> Internet with structured connection diagnostics and explicit
  ping, DNS, external-IP, and speed-test actions.
- Open version-matched administrator documentation inside the WebUI and follow contextual guide
  links from the relevant operational screens.

## Architecture

ExitLane uses a FastAPI backend that serves both its API and a single-page frontend. The frontend coordinates shared data through central application state, while SQLite stores durable settings, users, sessions, and generated configuration metadata.

The VPN core is provider-neutral. NordVPN and Mullvad VPN are the shipped commercial-provider implementations, and WireGuard provides independent ingress from routers and other clients. A provider is optional; direct internet egress remains a supported setup choice.

See [Architecture](docs/architecture.md), [Authentication](docs/authentication.md), [WireGuard configuration management](docs/wireguard-configuration.md), [Connection diagnostics](docs/diagnostics.md), [Application state](docs/application-state.md), and [Startup lifecycle](docs/startup-lifecycle.md) for the design rationale.

The WebUI's semantic theme adoption is recorded in the
[ExitLane design-system mapping](docs/design-system.md).

## Installation

The supported appliance baseline is Debian 13 on `amd64`. ExitLane is tested primarily in a
Debian 13 Proxmox LXC. Other Debian releases and architectures are not supported release targets.
An LXC must have `/dev/net/tun` and permission to create WireGuard interfaces.

```bash
git clone https://github.com/kevindraai/exitlane.git
cd exitlane
sudo ./installer/install-debian.sh
```

Open `http://<host>:8787` and complete the first-run wizard.

Read the [deployment guide](docs/deployment.md), [Mullvad provider guide](docs/mullvad.md), [backup and restore guide](docs/backup-and-restore.md), [upgrade and recovery guide](docs/upgrade-and-recovery.md), and [Proxmox LXC notes](docs/proxmox-lxc.md) before using ExitLane outside a development environment.

Direct HTTP remains available on a trusted local network. For HTTPS termination, follow the [reverse-proxy guide](docs/deployment/reverse-proxy.md); ExitLane does not terminate TLS itself.

Docker is not currently a supported deployment method.

## Development

Work takes place on feature branches and reaches `main` through a pull request after CI passes. CI checks shell scripts, Python linting and tests, frontend syntax and tests, translations, JSON, security scanning, and package builds. Before merge, deploy the candidate to the test LXC and run its smoke test.

See [Development](docs/development.md) and [Contributing](CONTRIBUTING.md) for commands and the full workflow.

## Roadmap

Planned work, including further VPN-provider implementations and deployment options, is tracked in the [roadmap](ROADMAP.md).

## AI involvement

ExitLane has been developed with extensive AI assistance. The project architecture, feature decisions, review, testing, and final technical decisions remain human-controlled. AI is used to accelerate implementation, tests, documentation, and iteration.

## License

ExitLane is licensed under the [GNU General Public License v3.0](LICENSE).
