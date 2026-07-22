# Exitlane

**Smart egress for every network.**

Exitlane is a self-hosted egress gateway for routers, VLANs, and applications. It provides a
browser-based control plane for routing traffic through a VPN without coupling the core to a
specific router platform.

The current alpha release integrates with NordVPN and accepts traffic through WireGuard.
Exitlane is intended for a trusted management network and is currently tested primarily on a
Debian-based Proxmox LXC.

> [!WARNING]
> Exitlane is alpha software. Do not expose the management interface directly to the internet.

## Features

### VPN management

- Install, authenticate, configure, connect, and disconnect the NordVPN CLI.
- View provider and tunnel status from one interface.

### WireGuard ingress

- Generate a WireGuard ingress interface and client configuration.
- Use the generated configuration with a router or another WireGuard client.

### Dashboard

- Monitor VPN, WireGuard, host, and application health.
- Refresh status without overlapping background requests.

### Authentication

- Create the first local administrator account during setup.
- Protect the application and API with expiring server-side sessions.

### Settings

- Configure timezone and dashboard refresh interval in the WebUI.
- Choose the interface language and light, dark, or system appearance.

### Notifications

- Configure generic webhook notifications.

### Activity log

- Review important authentication, setup, VPN, WireGuard, settings, notification, and system
  events in a translated, filterable Activity view.
- Keep structured application events for up to 90 days and 5,000 records by default.

### First-run wizard

- Complete system checks, administrator setup, provider setup, and WireGuard setup in a guided
  flow.

### Multi-language

- Use the interface in English or Dutch.

### Dark/light theme

- Select a light or dark appearance, or follow the operating-system preference.

## Screenshots

Screenshots will be added as the v0.2 interface stabilizes.

<!-- Placeholder: dashboard screenshot -->
<!-- Placeholder: first-run wizard screenshot -->

## Architecture

Exitlane uses a FastAPI backend that serves both its API and a single-page frontend. The
frontend coordinates shared data through central application state, while SQLite stores durable
settings, users, sessions, and generated configuration metadata. NordVPN CLI is the first VPN
provider integration; WireGuard provides ingress from routers and other clients.

See [Architecture](docs/architecture.md), [Authentication](docs/authentication.md),
[Application state](docs/application-state.md), and
[Startup lifecycle](docs/startup-lifecycle.md) for the design rationale.

## Installation

The installer supports Debian 12 and 13. A Proxmox LXC must have `/dev/net/tun` and permission to
create WireGuard interfaces.

```bash
git clone https://github.com/kevindraai/exitlane.git
cd exitlane
sudo ./installer/install-debian.sh
```

Open `http://<host>:8787` and complete the first-run wizard. Read the
[deployment guide](docs/deployment.md) and [Proxmox LXC notes](docs/proxmox-lxc.md) before using
Exitlane outside a development environment.

## Development

Work takes place on feature branches and reaches `main` through a pull request after CI passes.
CI checks shell scripts, Python linting and tests, frontend syntax and tests, translations, JSON,
and package builds. Before merge, deploy the candidate to the test LXC and run its smoke test.

See [Development](docs/development.md) and [Contributing](CONTRIBUTING.md) for commands and the
full workflow.

## Roadmap

Planned work is tracked in the [roadmap](ROADMAP.md).

## License

Exitlane is licensed under the [GNU General Public License v3.0](LICENSE).
