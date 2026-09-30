"""Experimental direct-provider transactions with permanent container protection.

Native providers retain their existing lifecycle. This injected adapter opens
protected forwarding only after real provider state has been committed and the
exact candidate generation has complete dataplane proof. D4 supplies the outer
supervisor lease; lock order here never acquires a provider claim under policy_lock.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import stat
import struct
import time
from collections.abc import Awaitable, Callable, Iterable

from exitlane.container_runtime import ContainerLifecycleError, ContainerWireGuardLifecycle
from exitlane.services.killswitch import TunnelFacts
from exitlane.services.provider_wireguard import (
    PROBE_ADDRESS,
    PROBE_RULE_PRIORITY,
    TABLE_ID,
    EgressConfig,
    ProviderWireGuard,
    ProviderWireGuardError,
)

DnsProbe = Callable[[str, str, str, float], Awaitable[bool]]


def _valid_dns_response(response: bytes, query: bytes) -> bool:
    if len(response) < len(query) or response[:2] != query[:2]:
        return False
    flags, questions, answers = struct.unpack("!HHH", response[2:8])
    if (
        not flags & 0x8000
        or flags & 0x020F
        or questions != 1
        or not 1 <= answers <= 64
        or response[12 : len(query)] != query[12:]
    ):
        return False
    offset = len(query)
    for _ in range(answers):
        labels = 0
        while offset < len(response):
            size = response[offset]
            offset += 1
            if size == 0:
                break
            if size & 0xC0 == 0xC0:
                if offset >= len(response):
                    return False
                pointer = ((size & 0x3F) << 8) | response[offset]
                offset += 1
                if not 12 <= pointer < len(response):
                    return False
                break
            if size > 63 or offset + size > len(response):
                return False
            offset += size
            labels += 1
            if labels > 127:
                return False
        if offset + 10 > len(response):
            return False
        kind, klass, _, size = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        if offset + size > len(response):
            return False
        if kind == 1 and klass == 1 and size == 4:
            return not ipaddress.IPv4Address(response[offset : offset + size]).is_unspecified
        offset += size
    return False


def _dns_query(interface: str, address: str, hostname: str, timeout: float, *, tcp: bool) -> bool:
    """Bounded TCP DNS, bound to the provider device; no resolver fallback."""
    transaction = os.urandom(2)
    question = (
        b"".join(bytes((len(label),)) + label.encode("ascii") for label in hostname.split("."))
        + b"\0\0\1\0\1"
    )
    query = transaction + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        ) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
            client.settimeout(max(0.001, deadline - time.monotonic()))
            client.connect((address, 53))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            client.settimeout(remaining)
            if tcp:
                client.sendall(struct.pack("!H", len(query)) + query)
            else:
                client.send(query)

            def receive(size: int) -> bytes:
                data = bytearray()
                while len(data) < size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    client.settimeout(remaining)
                    chunk = client.recv(size - len(data))
                    if not chunk:
                        raise OSError
                    data.extend(chunk)
                return bytes(data)

            if tcp:
                size = struct.unpack("!H", receive(2))[0]
                if not len(query) <= size <= 4096:
                    return False
                response = receive(size)
            else:
                client.settimeout(max(0.001, deadline - time.monotonic()))
                response = client.recv(4096)
                if len(response) < len(query):
                    return False
    except OSError:
        return False
    return _valid_dns_response(response, query)


async def _default_dns_probe(interface: str, address: str, hostname: str, timeout: float) -> bool:
    return await asyncio.to_thread(_dns_query, interface, address, hostname, timeout, tcp=False)


async def _default_tcp_dns_probe(
    interface: str, address: str, hostname: str, timeout: float
) -> bool:
    return await asyncio.to_thread(_dns_query, interface, address, hostname, timeout, tcp=True)


class ContainerWireGuardEgress(ProviderWireGuard):
    def __init__(
        self,
        network: ContainerWireGuardLifecycle,
        *,
        runner=None,
        root=None,
        dns_probe: DnsProbe = _default_dns_probe,
        tcp_dns_probe: DnsProbe = _default_tcp_dns_probe,
    ):
        super().__init__(runner or network.runner, root=root, dns_probe=dns_probe)
        self.network = network
        self.tcp_dns_probe = tcp_dns_probe
        self.owned_epoch = None

    def _path(self, interface: str):
        # Shared native _path resolves aliases. Container teardown must never let
        # wg-quick infer another interface name from a redirected config basename.
        try:
            root = self.root.resolve(strict=False)
            candidate = root / f"{interface}.conf"
            if candidate.is_symlink():
                raise ValueError
            path = super()._path(interface)
            if path.name != f"{interface}.conf":
                raise ValueError
            return path
        except (OSError, RuntimeError, ValueError):
            raise ProviderWireGuardError("container_provider_configuration_invalid") from None

    def validate_candidate(self, config: EgressConfig) -> EgressConfig:
        try:
            item = config.validated()
            expected = {"mullvad": "wg-mullvad", "pia": "wg-pia", "proton": "wg-proton"}
            if (
                expected.get(item.provider_id) != item.interface
                or not item.generation.isascii()
                or not all(c.isalnum() or c in "_-" for c in item.generation)
            ):
                raise ValueError
            if (
                ipaddress.IPv4Interface(item.address).ip
                in ipaddress.IPv4Interface(self.network.config.address).network
            ):
                raise ValueError
            return item
        except (ValueError, TypeError, AttributeError, ProviderWireGuardError):
            raise ProviderWireGuardError("container_provider_configuration_invalid") from None

    async def _block(self, *, interface: str | None = None) -> None:
        async with self.network.policy_lock:
            candidate = self.network.policy_candidate
            if interface is not None and candidate is not None and candidate.interface != interface:
                return  # A stale provider cannot revoke another generation.
            try:
                await self.network.restrict_provider(None)
            except ContainerLifecycleError:
                raise ProviderWireGuardError("container_provider_guard_failed") from None
            self.network.policy_epoch += 1
            self.network.policy_candidate = self.network.policy_proof = None

    async def start(self, config: EgressConfig, ingress_interfaces: Iterable[str]) -> None:
        async with self.network.mutation_lock:
            await self._start(config, ingress_interfaces)

    async def _start(self, config: EgressConfig, ingress_interfaces: Iterable[str]) -> None:
        item = self.validate_candidate(config)
        ingress = tuple(ingress_interfaces)
        if ingress != (self.network.config.interface,):
            raise ProviderWireGuardError("container_provider_configuration_invalid")
        async with self.network.policy_lock:
            try:
                await self.network.restrict_provider(None)
                await self.network.register_source(item)
            except ContainerLifecycleError:
                raise ProviderWireGuardError("container_provider_guard_failed") from None
            self.network.policy_epoch += 1
            epoch = self.network.policy_epoch
            self.owned_epoch = epoch
            self.network.policy_candidate = item
            self.network.policy_proof = None
        try:
            await super().start(item, ingress)
            async with self.network.policy_lock:
                if epoch != self.network.policy_epoch or self.network.policy_candidate != item:
                    raise ProviderWireGuardError("container_provider_stale_generation")
        except BaseException:
            async with self.network.policy_lock:
                if epoch == self.network.policy_epoch:
                    await self.network.restrict_provider(None)
                    self.network.policy_candidate = self.network.policy_proof = None
                    self.network.policy_epoch += 1
            raise

    def validate_teardown_file(self, interface: str) -> None:
        """wg-quick may only see our hookless direct-provider grammar."""
        descriptor = None
        try:
            path = self._path(interface)
            if not path.exists() and not path.is_symlink():
                return
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_size > 65536
                or facts.st_uid != os.geteuid()
                or facts.st_mode & 0o077
            ):
                raise ValueError
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                content = source.read(65537).decode("ascii")
            values = {"Interface": {}, "Peer": {}}
            section = ""
            seen = set()
            for raw in content.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line in ("[Interface]", "[Peer]"):
                    section = line[1:-1]
                    if section in seen or section == "Peer" and "Interface" not in seen:
                        raise ValueError
                    seen.add(section)
                    continue
                if not section or "=" not in line:
                    raise ValueError
                name, value = (field.strip() for field in line.split("=", 1))
                allowed = (
                    {"PrivateKey", "Address", "MTU", "Table"}
                    if section == "Interface"
                    else {
                        "PublicKey",
                        "PresharedKey",
                        "Endpoint",
                        "AllowedIPs",
                        "PersistentKeepalive",
                    }
                )
                if name not in allowed or name in values[section]:
                    raise ValueError
                values[section][name] = value
            i, peer = values["Interface"], values["Peer"]
            if (
                i["Table"] != "off"
                or peer["AllowedIPs"] != "0.0.0.0/0"
                or peer["PersistentKeepalive"] != "25"
            ):
                raise ValueError
            # Reuse the actual typed renderer contract for field validation.
            endpoint, port = peer["Endpoint"].rsplit(":", 1)
            EgressConfig(
                "mullvad",
                "teardown-validation",
                interface,
                i["PrivateKey"],
                i["Address"],
                peer["PublicKey"],
                endpoint,
                "10.64.0.1",
                int(port),
                int(i["MTU"]),
                preshared_key=peer.get("PresharedKey"),
            ).validated()
        except (OSError, ValueError, KeyError, UnicodeError, ProviderWireGuardError):
            raise ProviderWireGuardError("container_provider_teardown_config_invalid") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    async def _stop_for_start(self, interface: str) -> None:
        # start already revoked forwarding; internal teardown must not invalidate
        # its exact candidate, unlike explicit stop/disconnect/rollback cleanup.
        self.validate_teardown_file(interface)
        await ProviderWireGuard.stop_interface(self, interface)

    def require_teardown_owner(self, interface: str) -> None:
        current = self.network.policy_candidate
        if (
            current is not None
            and current.interface == interface
            and self.owned_epoch != self.network.policy_epoch
        ):
            raise ProviderWireGuardError("container_provider_stale_generation")

    async def _stop_for_rollback(self, interface: str) -> None:
        # The start mutation lock is already held and policy remains blocked.
        self.validate_teardown_file(interface)
        await ProviderWireGuard.stop_interface(self, interface)
        await self._delete_rule("oif", interface, PROBE_RULE_PRIORITY, 4)

    async def stop_interface(self, interface: str) -> None:
        async with self.network.mutation_lock:
            self.require_teardown_owner(interface)
            await self._block(interface=interface)
            self.validate_teardown_file(interface)
            await super().stop_interface(interface)
            await self._delete_rule("oif", interface, PROBE_RULE_PRIORITY, 4)

    async def disarm(self, ingress_interfaces, egress_interface, **kwargs) -> None:
        # The shared RPDB/source/unreachable guards are permanent in containers.
        # Explicit disconnect revokes allowance but never removes these guards.
        async with self.network.mutation_lock:
            self.require_teardown_owner(egress_interface)
            await self._block(interface=egress_interface)
            await self._delete_rule("oif", egress_interface, PROBE_RULE_PRIORITY, 4)

    async def source_route_proven(self, item: EgressConfig) -> None:
        source = str(ipaddress.IPv4Interface(item.address).ip)
        rules = await self._json("-4", "rule", "show")
        self._check_source_rule_order(rules, required=True)
        if not any(
            self._owned_source_rule(rule) and rule["src"] in (source, source + "/32")
            for rule in rules
        ):
            raise ProviderWireGuardError("container_provider_source_guard_unproven")
        output = await self._run("ip", "-4", "route", "get", PROBE_ADDRESS, "from", source)
        fields = output.split()
        if (
            "dev" not in fields
            or fields[fields.index("dev") + 1] != item.interface
            or "table" not in fields
            or fields[fields.index("table") + 1] != str(TABLE_ID)
        ):
            raise ProviderWireGuardError("container_provider_source_guard_unproven")
        await self.network.observe_guard()

    async def probe(self, config: EgressConfig, *, timeout: float = 8) -> dict:
        item = self.validate_candidate(config)
        epoch = self.network.policy_epoch
        if self.network.policy_candidate != item:
            return {"ready": False, "connected": False, "handshake": 0}

        async def prove():
            last = {"ready": False}
            for _ in range(2):
                last, tcp = await asyncio.gather(
                    super(ContainerWireGuardEgress, self).probe(item, timeout=timeout / 2),
                    self.tcp_dns_probe(
                        item.interface, item.dns_address, item.dns_probe_hostname, timeout / 2
                    ),
                )
                observed = await super(ContainerWireGuardEgress, self).observe(item)
                last["dns_tcp"] = tcp
                last["ready"] = (
                    last.get("ready") is True and tcp is True and observed.get("ready") is True
                )
                if not last["ready"]:
                    return last
                await self.verify_route(item.interface, (self.network.config.interface,))
                await self.source_route_proven(item)
                if epoch != self.network.policy_epoch or self.network.policy_candidate != item:
                    return {"ready": False, "handshake": 0}
            return last

        try:
            observation = await asyncio.wait_for(prove(), max(0.01, timeout))
        except asyncio.CancelledError:

            async def revoke_cancelled():
                async with self.network.policy_lock:
                    if epoch == self.network.policy_epoch and self.network.policy_candidate == item:
                        await self.network.restrict_provider(None, keep_probe=True)
                        self.network.policy_proof = None

            cleanup = asyncio.create_task(revoke_cancelled())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
            raise
        except (TimeoutError, ProviderWireGuardError, ContainerLifecycleError):
            observation = {"ready": False, "handshake": 0}
        async with self.network.policy_lock:
            if epoch != self.network.policy_epoch or self.network.policy_candidate != item:
                return {"ready": False, "handshake": 0}
            if observation.get("ready") is True:
                self.network.policy_proof = (epoch, item, time.monotonic())
            else:
                self.network.policy_proof = None
                try:
                    await self.network.restrict_provider(None, keep_probe=True)
                except ContainerLifecycleError:
                    raise ProviderWireGuardError("container_provider_guard_failed") from None
        return observation

    async def transition_facts(self, config: EgressConfig):
        observation = await self.probe(config, timeout=5)
        ready = observation.get("ready") is True
        return TunnelFacts(
            available=ready,
            interface=config.interface if ready else None,
            supports_ipv4=ready,
            supports_ipv6=False,
            protected_egress=ready,
            reason="container_candidate_proven" if ready else "container_candidate_unproven",
        )

    async def committed(self, config: EgressConfig) -> None:
        async with self.network.mutation_lock:
            try:
                await self._committed(config)
            except asyncio.CancelledError:

                async def revoke_cancelled_commit():
                    async with self.network.policy_lock:
                        if self.network.policy_candidate == config:
                            await self.network.restrict_provider(None)
                            self.network.policy_proof = None

                cleanup = asyncio.create_task(revoke_cancelled_commit())
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    await cleanup
                raise

    async def _committed(self, config: EgressConfig) -> None:
        item = self.validate_candidate(config)
        async with self.network.policy_lock:
            epoch = self.network.policy_epoch
            if (
                self.network.policy_candidate != item
                or self.network.policy_proof is None
                or self.network.policy_proof[:2] != (epoch, item)
                or time.monotonic() - self.network.policy_proof[2] > 5
            ):
                raise ProviderWireGuardError("container_provider_commit_unproven")
            try:
                observed = await super().observe(item)
                if observed.get("ready") is not True:
                    raise ProviderWireGuardError("container_provider_commit_unproven")
                await self.source_route_proven(item)
                await self.network.restrict_provider(item)
                self.network.policy_committed = (epoch, item)
            except (ContainerLifecycleError, ProviderWireGuardError):
                self.network.policy_proof = None
                await self.network.restrict_provider(None)
                raise ProviderWireGuardError("container_provider_commit_failed") from None

    async def observe(self, config: EgressConfig) -> dict:
        # Extended dataplane observation may revoke, but never grants forwarding.
        observation = await self.probe(config, timeout=5)
        async with self.network.policy_lock:
            committed = self.network.policy_committed == (self.network.policy_epoch, config)
            connected = (
                observation.get("ready") is True
                and committed
                and self.network.policy_interface == config.interface
            )
        return {**observation, "connected": connected}
