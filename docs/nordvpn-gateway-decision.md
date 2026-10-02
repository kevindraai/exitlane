# Separate NordVPN gateway: NO-GO for the evaluated stock candidates

- Decision date: 2026-10-02
- Status: **NO-GO for implementation selection in this wave**; no gateway support claim
- Scope: a separate helper namespace reached over private provider transit; not the settled same-container experiment in [#98](https://github.com/kevindraai/exitlane/issues/98) / [PR #113](https://github.com/kevindraai/exitlane/pull/113)
- Review: fresh-context Astra High architecture challenge, reconciled with pinned upstream source and the bounded synthetic model below
- Release relationship: optional research; does not block native v1 or Docker direct-provider engineering

The evaluated stock helpers do not establish a supported lifetime-long forwarding guard that covers a newly reachable helper namespace before its own firewall initialization, including recreation while ExitLane retains a previous routing/readiness decision. Gluetun additionally lacks a demonstrated supported routed L3 gateway contract. Therefore no implementation architecture is selected. Docker NordVPN remains unavailable; native NordVPN behavior remains unchanged.

This is a conservative architecture decision based on an unmet mandatory property, not a claim that an upstream production-image exploit was demonstrated. The synthetic experiment confirms the underlying permissive-namespace forwarding mechanism. Exact upstream-image exploitability and complete lifecycle qualification remain **INCONCLUSIVE**.

## Contract and threat boundary

The required topology was:

```text
protected client -> ExitLane WireGuard ingress
                 -> ExitLane policy routing / permanent guard
                 -> dedicated private provider transit
                 -> helper namespace / helper guard -> Nord tunnel -> Internet

management UI -> ExitLane management route (independent of helper)
```

For protected packets every reachable state must produce VPN egress or drop. ExitLane's existing direct-provider guard cannot simply allow any Ethernet transit interface and assume an independently restarting helper remains safe. Transit carries protected plaintext, expanding the data trust boundary from ExitLane's namespace to a Docker bridge and another namespace. Docker administrators are already trusted host administrators; other application containers and ordinary application/API users must not acquire access to this transit or its credentials. Transit must not include arbitrary workloads, management/control ports must not be published, and helper availability must not select ExitLane's ordinary default route.

No shared network namespace, Docker socket, privileged mode, host networking/PID, SYS_ADMIN, broad host mounts, arbitrary host-firewall mutation or weakened ExitLane protection is permitted. Source-derived startup weaknesses cannot be patched around with unreviewed host rules or an independent firewall owner inside either application namespace.

## Pinned candidate comparison

| Candidate | Evaluated identity | Integration evidence | Selection result |
| --- | --- | --- | --- |
| azinchen/nordvpn-wg | released `v2.2.0`, `b478d80dd96a6911d19a7ec76033374cc39238d1`; current inspected main `9156809b253a7ee349aa123949d8ef2e5f58cc96` | Explicit separate-namespace gateway using `FORWARD_FROM`, tunnel-only FORWARD and MASQUERADE; no HTTP lifecycle API established | Strongest functional fit, but startup guard lifetime not established |
| Gluetun | released `v3.41.3`, `3d1e20c5551e9cae1f9d938dc7b7214a6987f27e`; current inspected main `ded7fd059ca0150aec51f2baff2337133387204c` | Nord WireGuard, mounted secrets, authenticated bounded control server; stock VPN allowances concern OUTPUT | No supported routed L3 model demonstrated; firewall failure recovery also requires scrutiny |
| azinchen/nordvpn | released `v7.2.0`, `5195826c7d4d3c8643c155962341c1a39482614e`; current inspected main `182b679e75f35457d5dc6b6e4522be42e75311f8` | OpenVPN, explicit `FORWARD_FROM` gateway; environment credentials or token | Same delayed startup guard concern; no demonstrated advantage resolving WG blocker |
| Official Nord Docker recipe | [current official article](https://support.nordvpn.com/hc/en-us/articles/20465811527057-How-to-build-the-NordVPN-Docker-image) | Interactive official daemon/client recipe | Reference only; no bounded downstream routing/lifecycle contract or immutable image qualification |

### azinchen WireGuard and OpenVPN

The [WireGuard gateway documentation](https://github.com/azinchen/nordvpn-wg/blob/b478d80dd96a6911d19a7ec76033374cc39238d1/wiki/VPN-Gateway-Mode.md) describes downstream packets already SNATed into `FORWARD_FROM`; helper return routes therefore need not know protected client prefixes. The [firewall](https://github.com/azinchen/nordvpn-wg/blob/b478d80dd96a6911d19a7ec76033374cc39238d1/root/etc/s6-overlay/s6-rc.d/init-firewall/run) opens forwarding only toward `wg0`, with established returns from `wg0`. A future profile would restrict the source to ExitLane's explicit transit address, not authorize an arbitrary shared subnet.

Those rules protect traffic after initialization. In the released [WG entrypoint](https://github.com/azinchen/nordvpn-wg/blob/b478d80dd96a6911d19a7ec76033374cc39238d1/root/usr/local/bin/entrypoint), FORWARD DROP is installed only at line 210 after backend probing. The corresponding current-main relevant source is byte-identical. The released [OpenVPN entrypoint](https://github.com/azinchen/nordvpn/blob/5195826c7d4d3c8643c155962341c1a39482614e/root/usr/local/bin/entrypoint) installs FORWARD DROP at line 166. A forwarding-enabled fresh namespace can exist before these userspace operations. Restart/recreation can coincide with ExitLane still forwarding to a previously proven next hop. Polling health, a previous successful dataplane probe, or an expiring readiness lease cannot by themselves eliminate that interval.

The entrypoints also flush namespace filter/NAT tables and perform backend policy probes. Injecting a second firewall manager is not a supported solution. A permanent guard must have a demonstrable owner and survive every reachable lifecycle transition.

WG [backend-functions](https://github.com/azinchen/nordvpn-wg/blob/b478d80dd96a6911d19a7ec76033374cc39238d1/root/usr/local/bin/backend-functions) hardcodes `eth0` for ordinary uplink; initialization selects a default gateway. Two-network operation requires deterministic interface and default-gateway assignment, not Docker attachment order. IPv4 forwarding and `src_valid_mark` are namespaced prerequisites. Kernel WireGuard needs NET_ADMIN; userspace fallback additionally needs TUN. Upstream `cap_add` examples do not prove `cap_drop: ALL` compatibility. Exact least-capability and writable-path qualification was not completed.

`GATEWAY_DNS=forward` intentionally sends protected DNS to an ordinary-uplink resolver and is incompatible with this contract. `off` leaves DNS on the forwarded route; `redirect` needs interface-specific analysis. `NETWORK` introduces local bypass exceptions and must not be treated as a generic readiness workaround. IPv6 must remain independently denied even on IPv4-only bridges.

The WG image accepts TOKEN through its environment. [vpn-config](https://github.com/azinchen/nordvpn-wg/blob/b478d80dd96a6911d19a7ec76033374cc39238d1/root/usr/local/bin/vpn-config) uses a temporary curl configuration rather than token argv, writes private WG configuration with restrictive permissions, and the finish handler removes it. A native token-file mechanism was not established. Environment exposure to Docker administrators/process inspection is an explicit host-trust consideration; it is not alone a reason for this NO-GO. No token, private key or service credential was used in research.

No bounded network control API was established for either azinchen candidate. An externally configured gateway is an acceptable product model: ExitLane connect/disconnect would mean activate/deactivate protected routing, while the operator owns helper configuration and lifecycle. It must not imply native Nord country/server parity. Server-selection fallback and helper status must not be represented as a strict selected-country guarantee. HEALTHCHECK_ENABLED defaults false in WG, reporting success without testing the tunnel; even enabled health is not protected-client dataplane proof.

### Gluetun

Primary [Nord instructions](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/nordvpn.md) describe Nord WireGuard and server filters. Its [control server](https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/control-server.md) supports authenticated status, start/stop and public-IP operations with method/path roles. A future design would mount its auth configuration and expose it only internally; it would not authorize settings/credentials retrieval merely to read health. Supported runtime country/server mutation was not established.

Mounted WG secret/config input is available. The [official LAN attachment documentation](https://github.com/qdm12/gluetun-wiki/blob/main/setup/connect-a-lan-device-to-gluetun.md) documents proxies, not the required downstream L3 router. Released [firewall initialization](https://github.com/passteque/gluetun/blob/3d1e20c5551e9cae1f9d938dc7b7214a6987f27e/internal/firewall/enable.go) and VPN handling do not establish the required FORWARD/NAT contract. Review of the released failure path found disable/cleanup clearing firewall protection back to ACCEPT on failed enable. Current main differs in implementation, so release and main evidence must not be conflated. Custom firewall hooks would require a new ownership/lifecycle design; their existence does not prove safe stock gateway support.

Upstream moved from qdm12 to passteque; its README documents the migration and unchanged image names. Source identity verification must account for that documented migration without treating a redirect as provenance proof.

### Official recipe

The official recipe demonstrates an interactive client and token login, not a managed sibling router. Its textual explanation of `net.ipv6.conf.all.disable_ipv6=0` contradicts the setting's meaning, reinforcing that a recipe is not leakage proof. Nothing in this research changes the settled #98 stock-client conclusion or authorizes sysctl masking, patched kernel-operation results or broader ExitLane privileges.

## Ownership matrix for the evaluated topology

This matrix defines the required ownership allocation, not delivered gateway functionality. Unproven safety properties remain blockers to choosing that architecture.

| Concern | ExitLane responsibility | Helper / operator responsibility | Required evidence or unresolved boundary |
| --- | --- | --- | --- |
| Protected ingress | Own WG ingress and guard before activation | None | Existing container ingress invariants retained |
| Active-provider state | Sole transaction/generation and committed-state owner | Report observations only | Health cannot commit canonical state |
| Routing | Own protected policy table, explicit transit next hop and unreachable fallback | Own helper-local tunnel routes | No default-route fallback or attachment-order dependence |
| Firewall | Own permanent protected-interface and transition guards | Sole helper-local guard owner | **Helper guard must precede first reachable forwarding and survive recreation; not established** |
| DNS | Validate client DNS; route UDP/TCP queries through selected provider or drop | Forward into tunnel or bounded tunnel resolver | No Docker resolver or `GATEWAY_DNS=forward` bypass |
| IPv4 | Select exact protected provider route | Tunnel/NAT/return forwarding | SNAT identity and return path verified end to end |
| IPv6 | Permanently deny unsupported protected IPv6 | Independently deny unsupported IPv6 | RA, alternate default, DNS and transition cases need proof |
| Tunnel lifecycle | May deactivate routing; no container-engine control | Own tunnel reconnect and process lifecycle | External configuration semantics acceptable and explicit |
| Health/readiness | Own independently observed dataplane acceptance and revocation | Advisory tunnel/health observations only | Stale health cannot justify permissive fresh namespace |
| Provider authentication | Do not expose helper secrets through API/Activity | Authenticate to Nord | Credential-free CI; live proof separately authorized |
| Persistent state | Own encrypted canonical provider selection and pending transitions | Own declared helper configuration/state | Recreation cannot replay stale safety authorization |
| Secrets | Own only bounded control secret if needed | Root-protected provider credentials/config | Env boundary analyzed; no argv/log/artifact disclosure |
| Container lifecycle | Own ExitLane supervisor and guard ordering | Operator/Docker owns helper create/restart | No Docker socket; fresh namespace can invalidate proof before polling |
| Docker host/bridge | No arbitrary host firewall mutation | Docker owns bridge/NAT and host lifecycle | Private transit membership and bridge isolation explicitly qualified |
| Management routing | Preserve UI/control return routing | No default-route ownership over ExitLane management | Management remains reachable independently of Nord |
| Backup/restore | Restore canonical intent under closed guard; require fresh proof | Restore/reprovision external helper separately | Never restore a stale healthy/connected authorization |
| Provider switching | Close transition, prove target, commit generation | Keep helper-local guard independently effective | Direct-to-gateway and gateway-to-direct packet proof required |
| Rollback | Restore valid prior provider only after proof, otherwise block | Report actual helper state | Both rollback failure and helper recreation must remain drop |

## Failure-state analysis

| State | Required protected outcome | Current conclusion |
| --- | --- | --- |
| Helper absent / no usable next hop | Unreachable/drop | Explicit ExitLane policy route plus permanent guard can model this; not a gateway implementation proof |
| Fresh helper starting / recreated at previous address | VPN or drop from first reachable instant | **Unproven before helper DROP initialization; synthetic model confirms forwarding mechanism** |
| Tunnel disconnected / connecting / deleted | Drop until independently proven | Installed azinchen tunnel-only rules are promising; startup invariant still unresolved |
| Healthy tunnel | Proven tunnel egress | No real image/live Nord qualification performed |
| Helper process failure / shutdown / restart | Guard survives or traffic becomes unreachable | Requires namespace-lifetime evidence; process health alone insufficient |
| ExitLane restart | Guard before ingress, distrust persisted readiness | Existing startup contract must extend to external generation/next-hop identity |
| Docker daemon restart / host reboot / network recreation | No stale authorization over fresh permissive namespace | Not qualified; address/MAC reuse and bridge attachment are material |
| DNS failure / UDP-TCP fallback / IPv6 attempts | Drop or protected tunnel path | No complete gateway packet suite executed |
| Direct-to-Nord / Nord-to-direct / failed switch | Transition block then proven target only | No implementation; cannot inherit direct-provider acceptance without tests |
| Rollback success / failure | Proven previous provider or drop | No implementation proof; failure must never select ordinary default |
| Stale health / connected API with broken dataplane | Drop | Status is advisory; does not fix pre-firewall reachability |
| Persisted configuration recreation | Re-prove current dataplane under permanent guards | No inherited readiness claim accepted |

## Synthetic mechanism evidence and limits

A credential-free, separate-namespace model ran on local Docker Engine 26.1.5. It is not the required Engine >=28 support gate and did not execute any upstream candidate image, an ExitLane WG ingress path, or a commercial Nord connection.

The completed run used two private, non-masquerading bridges and a synthetic client, helper and uplink-side target. All container default routes were removed, including the default that attaching the helper's second network could add. Explicit host routes selected the helper. The helper had IPv4 forwarding enabled, Docker DNS NAT rules, no WG interface and no forward guard. Capture ran externally via namespace entry; capture privileges were not granted to the modeled appliance.

The unique `el-gateway-model-591ad4975e-pre-init` marker arrived at the helper ordinary `eth0` uplink capture and at the synthetic target. After installing a helper FORWARD drop guard the next protected marker timed out (`DROP`). A helper-origin positive control then reached the same target. This shows why a reachable forwarding-enabled namespace without its guard is unsafe, even without any default route. It does not show physical-host-uplink leakage or establish timing/reachability of a specific upstream release image.

Evidence receipts:

| Artifact | SHA-256 |
| --- | --- |
| `gateway_startup_model.py` | `4423a3269b2e8ac11d4e87a7dddf00cac59a45ffdff836df33eb5d3d5f0ea6b6` |
| `gateway-startup-model-no-default.jsonl` | `312a802f09fb522bde2698e4ef95cbbe96cbd7495d258bdb0006facc72fe71e3` |

The exact [model script](qualification/nordvpn-gateway-startup-model.py) and [completed receipt](qualification/nordvpn-gateway-startup-model.jsonl) are retained with this decision. They are research artifacts, not production code or a full packet-qualification harness. The script uses the existing D2/D3 fixture image built from source `03f8de679975d59b8bd6125a66cc99b5682e2ff9`; the recorded image is a local configuration ID, not a published registry digest. A one-packet positive observation establishes the mechanism; the short post-DROP timeout does not establish full negative qualification. Execution copies and failed attempts remain under `/tmp/exitlane-master-wave/`. Earlier internal-network/routing model attempts and partial capture attempts are retained as **INCONCLUSIVE**: some did not deliver the marker, one failed while applying its guard, and a previous purported final run still had a default route despite its summary wording. The completed no-default receipt above supersedes that summary for the bounded claim. No failure was suppressed or counted as a passed acceptance case.

## License, supply chain and remaining evidence

Both azinchen projects declare AGPL-3.0; Gluetun declares MIT. Consuming an unmodified external pinned image is distinct from incorporating AGPL source into ExitLane or redistributing a modified helper. Any future distribution must record notices, source and applicable corresponding-source obligations; changes/network interaction obligations require analysis of the actual packaging. This decision makes no legal conclusion about combined works and copies no upstream implementation into ExitLane.

No immutable OCI digest was selected, and no exact candidate image scan, signature verification, provenance verification or SBOM qualification was completed. Source SHAs are not image digests. Upstream WG CI publishes before its image-security job and includes a Trivy ignore file; upstream CI success cannot replace ExitLane's unchanged independent security gate. External images would need immutable version plus digest, verified source identity, current exact-image scans, truthful SBOM/provenance availability, and a controlled reviewed update process. Do not invent provenance when upstream supplies none.

Environment credentials, externally configured connect semantics and helper writable paths are reviewable boundaries, not automatic NO-GO criteria. The decisive rejection is the unestablished every-state startup/lifecycle forwarding invariant, with Gluetun's additional unsupported L3 ownership gap. A private bridge and a healthy flag alone do not establish that invariant.

## Decision consequences and reopening criteria

Do not implement or advertise a Docker NordVPN gateway from these findings. Preserve Docker stock-Nord denial, native NordVPN integration and the independent direct-provider Docker program. Do not use this optional investigation to postpone native v1 or weaken publication/security gates.

Reopen only on material new evidence of a supported startup and routed-gateway contract that closes first-reachability and recreation gaps without forbidden privileges, shared stacks, Docker socket, host-firewall workarounds or competing firewall owners. Any proposed new model needs a fresh Astra High challenge of actual source and ownership, immutable image/supply-chain evidence, full credential-free D3/D6-style packet qualification across the listed states, and separately authorized live provider proof. A genuine new architecture is a separately scoped investigation; repeatedly injecting speculative firewall patches is not this wave's next step.
