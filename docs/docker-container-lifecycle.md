# Synthetic container lifecycle (D2)

This slice implements container network lifecycle primitives and a bounded worker supervisor.
It is not a Docker appliance. Application runtime selection still accepts native Debian only;
the full application startup, direct-provider integration and durable recovery belong to D3/D4.
Native systemd units, configuration generation and installer behavior remain unchanged.

`exitlane.container_runtime.IngressConfig` accepts the current single-peer IPv4 ingress shape.
Root-owned regular configuration files must have private permissions and bounded size. The parser
rejects symlinks, nonregular nodes, duplicate/unknown directives and unsupported configuration.
Existing native hooks must pass the shared restore validator, but are never executed. Container
activation uses fixed `ip` and `wg` argv, passing private keys only through stdin. Keys are excluded
from object representations and failure messages. It reads the namespaced forwarding sysctl;
Docker must configure that sysctl rather than the container writing to `/proc/sys`.

Before adding an ingress interface, the lifecycle installs and semantically observes its separate
`inet exitlane_container_guard` table and the shared direct-provider unreachable RPDB guard in
both address families. The permanent table drops all forwarding from the ingress interface and
its protected IPv4 source network. D2 never opens a provider path; D3 must integrate proven provider
commit and routing without removing the permanent invariant. This table is independent of the
optional native killswitch. Existing foreign rules under its table name cause refusal.

Interface creation rejects collisions and pins the successful interface index. Cleanup does not
adopt or delete a replacement interface. A timeout/cancellation with uncertain creation ownership
retains protection and exits the supervisor; recovery requires a new container namespace. It never
guesses ownership from a name. Worker crashes stop ingress before bounded restart. Exhausted
restart budget terminates the container; SIGTERM/SIGINT stop ingress and terminate/reap the worker
with a bounded kill fallback. Guard state is retained until the namespace disappears. Docker init
owns process reaping, so supervisor death also terminates its container.

## Run the isolated qualification

On a development Docker host with WireGuard kernel support and `/dev/net/tun`:

```bash
docker build -f docker/testing/Dockerfile.lifecycle -t exitlane-lifecycle:test .
python3 scripts/qualification/container_lifecycle.py
```

The digest-pinned Debian 13/Python test image is labelled unsupported. It is not published and has
no production Compose contract. The harness uses uniquely named, disposable containers on one
internal Docker bridge with `cap-drop ALL`, `NET_ADMIN`, TUN, `no-new-privileges`, namespaced
forwarding and Docker init. No host network/PID, privileged container, Docker socket mount,
SYS_ADMIN, NET_RAW or host filesystem mount is used. The host-side Docker CLI controls only these
test-owned resources; cleanup deletes only resources created by the invocation.

Synthetic private keys enter the supervisor through a private FIFO and enter WireGuard through
stdin. The fixture worker proves encrypted ingress and management availability. Bounded continuous
protected marker probes must never reach the target without a provider, across worker restart/exhaustion, container
start and supervisor death. A separate intentionally unsafe gateway with namespaced SNAT proves
the target can detect plaintext marker packets. The candidate's protection is never weakened for
that positive control. This is endpoint packet evidence, not the multi-interface captures or
host/daemon restart qualification required by D6.

The lightweight kernel proof runs in CI when core, dependency, test-image, harness or workflow
files change. Documentation-only changes skip its image build and execution. Shared backend tests
remain one suite. Full production networking, restore/lease orchestration, image management,
disposable-host packet qualification and release publication remain the sequential gates in #90.
