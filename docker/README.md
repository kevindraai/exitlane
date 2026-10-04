# ExitLane Docker appliance

The v1 appliance supports **Linux amd64, rootful Docker Engine >=28 and Compose v2**, with
`NET_ADMIN`, `/dev/net/tun`, a read-only root filesystem and durable ExitLane state. Docker v1
providers are Mullvad, PIA and imported Proton WireGuard. Native Debian additionally supports
NordVPN; NordVPN is unavailable inside Docker. Live commercial PIA/Proton interoperability
has not been qualified.

Follow the complete [Docker deployment Quick Start](../docs/docker-deployment.md#quick-start)
for versioned files, the official `ghcr.io/kevindraai/exitlane:v1.0.0` image, verified digest
pinning, explicit trusted-LAN bindings, preflight, first-run setup and health checks. Its
[lifecycle instructions](../docs/docker-deployment.md#lifecycle-and-state) cover restart,
volume ownership, encrypted backup/export/verification/restore, upgrades and compatible rollback.
Stable source/image publication and final digest evidence are pending until recorded in the
[v1.0.0 release](https://github.com/kevindraai/exitlane/releases/tag/v1.0.0).

Use `compose.appliance.yml` for the appliance. It gives ExitLane its own nftables/routing namespace
while Docker owns host bridge/NAT. Keep the minimum privilege contract: no privileged container,
host network/PID, Docker socket or `SYS_ADMIN`. Protected clients remain provider-or-block.

`Dockerfile` and `docker-compose.yml` remain development-only UI/API surfaces; they cannot route
protected clients. Appliance build/release details are in the
[appliance contract](../docs/docker-appliance-candidate.md) and
[runtime architecture](../docs/docker-runtime-architecture.md).
