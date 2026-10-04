# Docker appliance feasibility — issue #76

> Historical implementation/qualification record. Older unsupported/publication-hold
> and all-HIGH scanner policy statements describe the original delivery boundary.
> The executive order fixes v1 support and authorizes publication under the residual-risk
> policy. Use [Docker deployment](docker-deployment.md) and [SECURITY](../SECURITY.md)
> for the current operator/support contract. Exact stable-image delivery remains pending.

- Assessment date: 2026-09-30
- Baseline: `main` at `55cc970` (after the Proxmox helper)
- Decision: **Not yet suitable as an ExitLane VPN appliance**
- Current image status: UI/API development only

The subsequent [Docker runtime architecture and implementation program](docker-runtime-architecture.md)
supersedes the open-ended design next steps with source-derived adapters, a state contract, network
and recovery ordering, an exact packet harness and sequential D1–D7 delivery gates. Its decision is
**feasible subject to implementation and qualification**; Docker remains **not yet suitable** today.
This assessment preserves the historical development-image evidence below. No production image
or supported runtime is introduced by the planning work.

The current image builds and serves the management API. That proves the control-plane process
can start in a container; it does **not** prove routed client traffic, fail-closed protection,
recovery, or appliance lifecycle. No production Docker deployment is shipped by this assessment.
Native Debian 13 amd64, including the qualified privileged LXC, remains the supported gateway.

## Capability matrix

“Supported unchanged” refers to application behavior inside the present development image.
“Needs adapter” means an explicit container implementation and qualification are required
before support may be claimed. “Unresolved” means that even the required design or proof is
incomplete. “Unsupported by design” describes the proposed bounded Docker v1 behavior,
not a limitation of native ExitLane.

| Capability | Classification | Evidence and required action |
| --- | --- | --- |
| FastAPI and WebUI | Supported unchanged | Built image returned `/api/health` in a network-isolated container with no Linux capabilities. |
| Persistent database and settings | Needs container adapter | `core.DATA` follows `EXITLANE_DATA_DIR`; the old Compose volume covered the database only. The development image now puts both data and config in `/data`, and a temporary volume survived container recreation. Appliance schema/upgrade proof remains. |
| Master key and encrypted provider state | Needs container adapter | Before this assessment, `auth_security.master_key_path()` resolved to `/etc/exitlane/secret.key`, outside the sole Compose volume. Development config now shares `/data`; the same key survived container recreation. Backup, restore, ownership and image-replacement proof remain. |
| WireGuard ingress | Needs container adapter | `main.py` writes under `/etc/wireguard` and controls `wg-quick@*.service` with `systemctl`; the image has no service manager. No UDP ingress or routed client proof exists. |
| Direct provider egress | Needs container adapter | Mullvad, PIA and imported Proton use ExitLane-owned `wg-quick` and policy routes. Namespace behavior, exact-peer proof, startup guard and teardown must be qualified with synthetic peers. |
| nftables | Needs container adapter | The current image lacks `nft`. ExitLane calls it for its own firewall tables. Future rules must remain within the container network namespace and never claim Docker-owned host tables. |
| Policy routing | Unresolved | Source/interface rules and unreachable provider defaults are designed for a native appliance. Docker bridge/NAT, marks, conntrack, restart and namespace lifetime need packet-level proof. |
| DNS capture/protection | Unresolved | Docker DNS and ExitLane's client DNS path have not been tested for UDP/TCP leakage or provider failure. |
| Killswitch | Unresolved | Native boot restores guards before networking through systemd. No equivalent guard-before-ingress order or no-plaintext-fallback proof exists for container/daemon/host restarts. |
| Provider switching | Unresolved | Native direct-to-direct and managed-to-direct transactions have tests; container namespace failure, rollback and stale-generation behavior have no dynamic evidence. |
| Restart and recovery | Needs container adapter | Native service restarts, early boot oneshots and systemd status do not map directly to image replacement or Docker restart policy. |
| Backup | Needs container adapter | CLI inventory includes the database, `CONFIG_DIR/secret.key` and WireGuard config. Container volume layout and complete backup verification need a separate contract. |
| Restore | Needs container adapter | Restore invokes service/network guards and systemd WireGuard lifecycle. A safe container restore transaction has not been designed or tested. |
| Upgrade | Unsupported by design | Native in-place installer/git upgrade does not apply. Docker would use versioned image replacement with state-compatible rollback. |
| System power actions | Unsupported by design | `main.py` maps restart/reboot/shutdown to host `systemctl`; a container must never advertise host reboot or poweroff as available. |
| Speedtest | Needs container adapter | Measurement may be usable, but managed package installation is a systemd host operation and cannot be exposed as working in Docker v1. |
| NordVPN | Unsupported by design for Docker v1 | Current adapter expects a local NordVPN client/daemon and systemd; the development image has neither. [Nord publishes a separate NET_ADMIN container example](https://support.nordvpn.com/hc/en-us/articles/20465811527057-How-to-build-the-NordVPN-Docker-image), but integrating that daemon and its firewall/DNS ownership with ExitLane requires its own security decision. |
| Mullvad | Needs container adapter | Direct WireGuard architecture fits a private namespace conceptually; no Docker route/failure evidence exists. |
| PIA | Needs container adapter | Same direct egress boundary; only synthetic native qualification exists, with no live account. |
| Proton imported profiles | Needs container adapter | Same direct egress boundary; no live account and no Docker namespace qualification. |
| Reverse proxy awareness | Needs container adapter | Trusted peers/forwarded headers exist in the app; bridge proxy IP, published management address and `PUBLIC_URL` need explicit configuration and tests. |
| Logging and diagnostics | Needs container adapter | Uvicorn can log to stdout; systemd journal, host metrics, service state and privileged diagnostic tools cannot be presented as native facts. |

## Bounded evidence from the existing image

On a shared development Docker daemon (Engine 26.1.5), the current Dockerfile built as an isolated
feasibility image. A temporary container ran with `--network none --cap-drop ALL`, no published
ports and one temporary `/data` volume. `/api/health` responded successfully. The database
was in `/data`; the master key was in `/etc/exitlane`, outside the volume. The image contained
`wg` and `ip`, but no `nft` or `systemctl`. The temporary container and volume were removed.
The Compose file also published management TCP on every host interface and UDP 51820 before
this assessment. The development defaults now bind TCP 8787 to loopback, publish no UDP port,
drop all capabilities and persist the development master key with the database.
An isolated no-network recreation probe confirmed the database and master key persisted in the
same temporary volume. Image inspection also found that `COPY backend` had included the local
virtual environment, tests, caches and build output. A root `.dockerignore` now excludes those
artifacts plus common local secret/state files. A rebuild with harmless `.env`, database,
key and PEM sentinels confirmed that none reached the image while the public PIA CA PEM
remained. This is a development-image build-context control, not a production supply-chain
qualification.

This probe made no claim about a VPN dataplane. It did not publish ingress, change host firewall
rules, contact VPN providers, or exercise the Docker host's routed traffic. The shared daemon
is not a designated disposable qualification host.

## Production boundary and next proof

A candidate Docker appliance should start rootful in its own network namespace, with only
`NET_ADMIN` if proven necessary, `/dev/net/tun`, namespaced forwarding sysctls, explicit durable
volumes and explicit management/UDP bindings. It must use neither `--privileged`, a Docker
socket, host PID/network namespaces, broad host mounts nor `SYS_ADMIN`. If an essential
security invariant needs any of those, stop the production design. Docker's firewall/NAT rules
remain Docker-owned on the host; ExitLane may own only its own rules in its container namespace.
Docker documents that bridge firewall rules run on the host and must not be modified directly
([Docker nftables guide](https://docs.docker.com/engine/network/firewall-nftables/)).
Docker also documents `NET_ADMIN` as a narrower network capability than
`--privileged` ([container run guide](https://docs.docker.com/engine/containers/run/)).

The smallest credible code change would be a deployment-capability boundary for service manager,
power actions, package installation, provider availability, update mechanism and status reporting.
It should make unsupported actions absent or explicitly unavailable in both API and UI. It must
also define an immutable image, healthcheck, complete state volume layout, backup/restore
transaction and versioned-image rollback. A Debian 13 / Python 3.13 base should be evaluated
against the native baseline before release.

Only a dedicated disposable Docker host or isolated test host can qualify the appliance. The
gate requires synthetic WireGuard ingress and direct provider peers, host and container packet
capture/counters, DNS UDP/TCP, IPv4 and IPv6 blocking, exact peer, tunnel loss, failed connect,
provider switch/rollback, container and Docker daemon restart, host reboot, backup/recreation,
image replacement and no plaintext fallback. Management exposure and trusted proxy origin must
be tested from the intended client networks. No PIA/Proton account or third-party provider
infrastructure is needed for that synthetic proof.

The conclusion will remain **not yet suitable** until those adapters and network/recovery
gates pass. A later working build with some missing gates may be called experimental, but
the current development image is not an appliance candidate.
