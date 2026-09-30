#!/usr/bin/env python3
"""D3 test guest, never a production entrypoint.

Boot secrets arrive once through root-only /run/d3-boot FIFO. Internal HTTP
8990 accepts <=4KiB JSON POST / commands connect, disconnect, switch, status;
provider is mullvad/pia/proton, target is synthetic peer a/b, timeout is 1..15.
GET / returns sanitized status. UDP 10.77.0.1:5666 echoes ingress proof.
No host publication, credentials in argv/env, arbitrary commands or real accounts.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

from exitlane import core, main
from exitlane.container_egress import ContainerWireGuardEgress
from exitlane.container_runtime import (
    ContainerWireGuardLifecycle,
    IngressConfig,
)
from exitlane.providers import mullvad, pia, proton
from exitlane.providers.pia_api import PiaKeyResponse, PiaServer
from exitlane.providers.registry import ProviderRegistry
from exitlane.services import (
    auth_security,
    killswitch,
    vpn_operations,
)

_STAGE = "loading"


def stage(name, error=None):
    """Only fixed stages and recognized error identifiers enter root-only receipts."""
    global _STAGE
    if error is None:
        _STAGE = name
    receipt = {"stage": _STAGE, "failed": error is not None}
    if error is not None:
        classes = {
            "ContainerLifecycleError",
            "ProviderWireGuardError",
            "ValueError",
            "TypeError",
            "KeyError",
            "AttributeError",
            "OSError",
            "FileNotFoundError",
            "PermissionError",
            "RuntimeError",
            "HTTPException",
        }
        receipt["error_class"] = (
            type(error).__name__ if type(error).__name__ in classes else "unclassified"
        )
        codes = {
            "container_ingress_config_invalid",
            "container_network_command_failed",
            "container_guard_resource_conflict",
            "container_guard_unproven",
            "container_interface_creation_uncertain",
            "container_interface_ownership_unproven",
            "management_routing_failed",
            "provider_switch_failed",
            "provider_connection_conflict",
        }
        code = (
            getattr(error, "detail", None)
            if isinstance(error, main.HTTPException)
            else getattr(error, "code", None)
        )
        receipt["error_code"] = (
            code
            if isinstance(code, str) and code in codes
            else "synthetic_fixture_failed"
        )
    path = Path("/run/fixture-status.json")
    path.write_text(json.dumps(receipt))
    path.chmod(0o600)


class SyntheticApi:
    """Only upstream response boundaries are synthetic; use production parsers."""

    def __init__(self, boot):
        self.boot = boot
        self.device = None
        self.selected_peer = "a"

    async def devices(self):
        return [self.device] if self.device else []

    async def create_device(self, public_key):
        self.device = mullvad.Device.parse(
            {
                "id": "d3-fixture-device",
                "name": "Synthetic device",
                "pubkey": public_key,
                "ipv4_address": "10.64.0.2/32",
                "ipv6_address": None,
            }
        )
        return self.device

    async def relays(self):
        result = []
        for label, peer in self.boot["peers"].items():
            if label != self.selected_peer:
                continue
            parsed = mullvad.Relay.parse(
                {
                    "type": "wireguard",
                    "active": True,
                    "hostname": f"nl-ams-wg-{label}",
                    "country_code": "nl",
                    "city_code": "ams",
                    "country_name": "Netherlands",
                    "city_name": "Amsterdam",
                    "ipv4_addr_in": peer["endpoint"],
                    "pubkey": peer["public_key"],
                }
            )
            if parsed is None:
                raise ValueError("invalid synthetic relay")
            result.append(parsed)
        return result

    async def token(self):
        return "fixture-token-not-an-upstream-token"

    async def catalog(self):
        return [
            PiaServer.parse(
                {"id": label, "name": f"Synthetic {label}", "country": "NL"},
                {"ip": peer["endpoint"], "cn": f"synthetic-{label}"},
                peer["endpoint"],
            )
            for label, peer in self.boot["peers"].items()
            if label == self.selected_peer
        ]

    async def add_key(self, server, public_key):
        peer = self.boot["peers"][server.region_id]
        return PiaKeyResponse.parse(
            {
                "status": "OK",
                "peer_ip": "10.65.0.2/32",
                "server_key": peer["public_key"],
                "server_port": peer.get("port", 51820),
                "dns_servers": ["10.65.0.1"],
                "peer_pubkey": public_key,
                "server_ip": server.address,
            },
            expected_public_key=public_key,
            expected_server_address=server.address,
        )


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        if len(data) <= 1024:
            self.transport.sendto(data, peer)


class Fixture:
    def __init__(self, boot):
        if set(boot["peers"]) != {"a", "b"}:
            raise ValueError("invalid peers")
        self.boot = boot
        self.network = ContainerWireGuardLifecycle(IngressConfig(**boot["ingress"]))
        self.providers = {}
        self.profiles = {}
        self.committed_configs = []
        self.lock = asyncio.Lock()
        self.request = SimpleNamespace(state=SimpleNamespace(user=None))

    async def initialize(self):
        stage("core-init")
        core.init()
        stage("master-key")
        auth_security.ensure_master_key()
        stage("settings")
        core.set_settings(
            {
                "wireguard_interface": self.network.config.interface,
                "wireguard_subnet": str(
                    ipaddress.IPv4Interface(self.network.config.address).network
                ),
                "wireguard_configured": True,
                "setup_complete": True,
                "vpn.provider_id": "mullvad",
                killswitch.SETTING_INGRESS: [self.network.config.interface],
                killswitch.SETTING_CONFIGURED: False,
            }
        )
        stage("network-activate")
        await self.network.activate()
        stage("provider-initialize")
        self.apis = {name: SyntheticApi(self.boot) for name in ("mullvad", "pia")}
        private, public = (
            self.boot["provider_private_key"],
            self.boot["provider_public_key"],
        )
        keypair = lambda: (private, public)
        mullvad._wireguard_keypair = keypair
        pia._wireguard_keypair = keypair

        async def absent_legacy_daemon():
            return False

        mullvad.Mullvad._legacy_conflict = staticmethod(absent_legacy_daemon)
        for name, factory in (
            ("mullvad", mullvad.Mullvad),
            ("pia", pia.Pia),
            ("proton", proton.Proton),
        ):
            wireguard = ContainerWireGuardEgress(
                self.network, root=core.DATA / "provider-egress"
            )
            args = {"wireguard": wireguard}
            if name != "proton":
                args["api_factory"] = lambda *args, api=self.apis[name]: api
            self.providers[name] = factory(**args)
        for name, instance in self.providers.items():
            committed = instance.wireguard.committed

            async def record_commit(
                config, commit=committed, adapter=instance.wireguard
            ):
                await commit(config)
                self.committed_configs.append((adapter, config))

            instance.wireguard.committed = record_commit
            original = instance.connect

            async def connect_observed(
                target=None, *, timeout=40, provider_name=name, connect=original
            ):
                before = Path("/run/d3-before-target")
                if before.exists() and before.read_text() == provider_name:
                    Path("/run/d3-before-target-paused").touch()
                    deadline = asyncio.get_running_loop().time() + 90
                    while not Path("/run/d3-before-target-release").exists():
                        if asyncio.get_running_loop().time() >= deadline:
                            raise RuntimeError("synthetic_pause_timeout")
                        await asyncio.sleep(0.05)
                    for path in (
                        before,
                        Path("/run/d3-before-target-paused"),
                        Path("/run/d3-before-target-release"),
                    ):
                        path.unlink(missing_ok=True)
                result = await connect(target, timeout=timeout)
                pause = Path("/run/d3-pause-target")
                if (
                    result.get("ok")
                    and pause.exists()
                    and pause.read_text() == provider_name
                ):
                    Path("/run/d3-target-paused").touch()
                    deadline = asyncio.get_running_loop().time() + 90
                    while not Path("/run/d3-release-target").exists():
                        if asyncio.get_running_loop().time() >= deadline:
                            raise RuntimeError("synthetic_pause_timeout")
                        await asyncio.sleep(0.05)
                    for path in (
                        pause,
                        Path("/run/d3-target-paused"),
                        Path("/run/d3-release-target"),
                    ):
                        path.unlink(missing_ok=True)
                return result

            instance.connect = connect_observed
        # Observe actual routing errors without bypassing or changing orchestration.
        routing_codes = {
            "management_direct_route_postcondition_failed",
            "management_gateway_postcondition_failed",
            "management_lock_timeout",
            "management_lock_unavailable",
            "management_provider_route_conflict",
            "management_provider_route_postcondition_failed",
            "management_provider_table_state_failed",
            "management_route_discovery_failed",
            "management_routed_route_postcondition_failed",
            "management_rule_apply_failed",
            "management_rule_postcondition_failed",
            "protected_destination_configuration_invalid",
            "protected_destination_fail_closed_postcondition_failed",
            "protected_destination_route_postcondition_failed",
            "protected_destination_route_unavailable",
            "provider_route_postcondition_failed",
            "too_many_management_prefixes",
        }
        for operation in ("prepare_provider_transition", "reconcile"):
            original_routing = getattr(main.management_routing, operation)

            async def observed_routing(
                *args, operation=operation, run=original_routing, **kwargs
            ):
                try:
                    return await run(*args, **kwargs)
                except main.management_routing.ManagementRoutingError as error:
                    receipt = {
                        "operation": operation,
                        "error_code": error.code
                        if error.code in routing_codes
                        else "synthetic_management_routing_failed",
                    }
                    path = Path("/run/management-status.json")
                    path.write_text(json.dumps(receipt))
                    path.chmod(0o600)
                    raise

            setattr(main.management_routing, operation, observed_routing)
        # Main's actual switching coordinator sees the real shared implementations.
        main.provider_registry = ProviderRegistry(
            self.providers.values(), default_id="mullvad"
        )
        main.provider = self.providers["mullvad"]
        main.mullvad_provider = self.providers["mullvad"]
        main.proton_provider = self.providers["proton"]
        vpn_operations.CONNECT_TIMEOUT_SECONDS = 5
        vpn_operations.PROVIDER_SWITCH_TIMEOUT_SECONDS = 20

        async def optional_telemetry(*args, **kwargs):
            return {"latency_ms": None, "latency_measured_at": None}

        main.ensure_active_server_latency = optional_telemetry
        stage("provider-authenticate")
        for result in (
            await self.providers["mullvad"].authenticate("0000000000000000"),
            await self.providers["pia"].authenticate_credentials(
                "p0000000", "synthetic-fixture-only"
            ),
        ):
            if not result.get("ok"):
                raise ValueError("synthetic authentication failed")
        stage("provider-profile-import")
        for label, peer in self.boot["peers"].items():
            profile = (
                f"[Interface]\nPrivateKey = {self.boot['provider_private_key']}\n"
                "Address = 10.64.0.2/32\nDNS = 10.64.0.1\nMTU = 1380\n"
                f"[Peer]\nPublicKey = {peer['public_key']}\n"
                f"Endpoint = {peer['endpoint']}:{peer.get('port', 51820)}\nAllowedIPs = 0.0.0.0/0\n"
            )
            result = await self.providers["proton"].import_profile(
                profile, f"Synthetic {label}", "NL"
            )
            if not result.get("ok"):
                raise ValueError("synthetic profile import failed")
            self.profiles[label] = result["profile"]["id"]
        # Credentials are now in the actual encrypted provider store. Drop boot references.
        self.boot.pop("provider_private_key")

    async def status(self):
        active = core.setting("vpn.provider_id", "mullvad")
        try:
            facts = await self.providers[active].network_facts()
            await self.network.observe_guard()
            return {
                "ok": True,
                "active_provider": active,
                "connected": facts.protected_egress,
                "interface": facts.interface,
                "protected_egress": facts.protected_egress,
                "guard_observed": True,
            }
        except Exception:  # noqa: BLE001 - degraded management must remain usable without secret disclosure
            return {
                "ok": True,
                "active_provider": active,
                "connected": False,
                "protected_egress": False,
                "guard_observed": False,
                "error_code": "synthetic_dataplane_unavailable",
            }

    async def command(self, payload):
        if not isinstance(payload, dict) or set(payload) - {
            "command",
            "provider",
            "target",
            "timeout",
        }:
            raise ValueError("invalid command")
        command = payload.get("command")
        provider_id = payload.get(
            "provider", core.setting("vpn.provider_id", "mullvad")
        )
        target = payload.get("target", "a")
        timeout = payload.get("timeout", 5)
        if (
            command
            not in {
                "status",
                "connect",
                "disconnect",
                "switch",
                "stale-commit",
                "snapshot",
            }
            or provider_id not in self.providers
            or target not in {"a", "b"}
            or type(timeout) is not int
            or not 1 <= timeout <= 15
        ):
            raise ValueError("invalid command")
        if command == "snapshot":
            candidate = self.network.policy_candidate
            return {
                "ok": True,
                "active_provider": core.setting("vpn.provider_id"),
                "optional_guard_configured": bool(
                    core.setting(killswitch.SETTING_CONFIGURED, False)
                ),
                "outer_transition": bool(
                    core.setting(killswitch.SETTING_TRANSITION, False)
                ),
                "operation_state": (vpn_operations.active_snapshot() or {"state": "idle"})["state"],
                "policy_epoch": self.network.policy_epoch,
                "candidate_provider": candidate.provider_id if candidate else None,
                "candidate_committed": self.network.policy_committed
                == (self.network.policy_epoch, candidate),
            }
        if command == "status":
            return await self.status()
        async with self.lock:
            if command == "stale-commit":
                before = (self.network.policy_epoch, self.network.policy_committed)
                adapter, old = next(
                    (adapter, config)
                    for adapter, config in self.committed_configs
                    if config != self.network.policy_candidate
                )
                try:
                    await adapter.committed(old)
                except Exception as error:  # noqa: BLE001 - static proof result only
                    return {
                        "ok": getattr(error, "code", None)
                        == "container_provider_commit_unproven"
                        and before
                        == (self.network.policy_epoch, self.network.policy_committed),
                        "error_code": "stale_commit_rejected",
                    }
                return {"ok": False, "error_code": "stale_commit_accepted"}
            selected = self.providers[provider_id]
            if provider_id in self.apis:
                self.apis[provider_id].selected_peer = target
            self.providers["mullvad"]._relay_deadline = 0
            self.providers["pia"]._catalog_deadline = 0
            if provider_id == "proton" and command == "switch":
                state = selected._state()
                state["last_profile_id"] = self.profiles[target]
                selected._save(state)
            if command == "switch":
                result = await main.activate_vpn_provider(provider_id, self.request)
                if hasattr(result, "body"):
                    result = json.loads(result.body)
            elif command == "connect":
                if core.setting("vpn.provider_id", "mullvad") != provider_id:
                    raise ValueError("switch required")
                destination = (
                    f"nl-ams-wg-{target}"
                    if provider_id == "mullvad"
                    else target
                    if provider_id == "pia"
                    else self.profiles[target]
                )
                result = await selected.connect(destination, timeout=timeout)
            else:
                result = await selected.disconnect(timeout=timeout)
            # Only explicit non-secret result fields leave the test controller.
            return {
                "ok": result.get("ok") is True,
                "error_code": result.get("error_code") or result.get("detail"),
                **{
                    key: value
                    for key, value in (await self.status()).items()
                    if key != "ok"
                },
            }

    async def http(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
            if len(header) > 2048:
                raise ValueError("header too large")
            lines = header.decode("ascii").split("\r\n")
            method, path, version = lines[0].split()
            if method not in {"GET", "POST"} or path != "/" or version != "HTTP/1.1":
                raise ValueError("unsupported request")
            headers = {}
            for line in lines[1:]:
                if line:
                    name, value = line.split(":", 1)
                    if name.lower() in headers:
                        raise ValueError("duplicate header")
                    headers[name.lower()] = value.strip()
            if "transfer-encoding" in headers:
                raise ValueError("unsupported encoding")
            length = int(headers.get("content-length", "0"))
            if not 0 <= length <= 4096 or (method == "POST" and length == 0):
                raise ValueError("body budget")
            body = await asyncio.wait_for(reader.readexactly(length), 3)
            result = await self.command(
                json.loads(body) if method == "POST" else {"command": "status"}
            )
            status = 200
        except Exception as error:  # noqa: BLE001 - static receipt only
            stage("command-failed", error)
            code = (
                getattr(error, "detail", None)
                if isinstance(error, main.HTTPException)
                else None
            )
            if code not in {
                "management_routing_failed",
                "provider_switch_failed",
                "provider_connection_conflict",
            }:
                code = "synthetic_operation_failed"
            # Never stringify provider exceptions/configurations or echo request bytes.
            result, status = (
                {"ok": False, "error_code": code},
                400,
            )
        data = json.dumps(result).encode("ascii")
        writer.write(
            f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode()
            + data
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()


def proxy_answer(query):
    if len(query) < 12:
        return b""
    return (
        query[:2]
        + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        + query[12:]
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01"
    )


class ProxyDns(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, query, peer):
        self.transport.sendto(proxy_answer(query), peer)


async def proxy_tcp(reader, writer):
    try:
        size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 2))[0]
        if size > 1024:
            return
        answer = proxy_answer(await asyncio.wait_for(reader.readexactly(size), 2))
        writer.write(struct.pack("!H", len(answer)) + answer)
        await writer.drain()
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run(boot):
    stage("config-load")
    fixture = Fixture(boot)
    await fixture.initialize()
    stage("ingress-echo")
    await asyncio.get_running_loop().create_datagram_endpoint(
        Echo, local_addr=("10.77.0.1", 5666)
    )
    # Test-only positive listener proves INPUT rejection rather than an absent service.
    await asyncio.get_running_loop().create_datagram_endpoint(
        ProxyDns, local_addr=("10.77.0.1", 53)
    )
    proxy_server = await asyncio.start_server(proxy_tcp, "10.77.0.1", 53)
    stage("management-http")
    server = await asyncio.start_server(fixture.http, "0.0.0.0", 8990, limit=4096)  # nosec B104 - internal synthetic bridge only
    stage("ready")
    async with server, proxy_server:
        await server.serve_forever()


if __name__ == "__main__":
    os.umask(0o077)
    path = Path("/run/d3-boot")
    stage("boot-fifo")
    os.mkfifo(path, 0o600)
    try:
        with path.open() as source:
            boot = json.loads(source.read(16385))
        path.unlink()
        asyncio.run(run(boot))
    except Exception as error:  # noqa: BLE001 - never stringify secrets
        stage("failed", error)
        print("synthetic_fixture_failed", flush=True)
        raise SystemExit(2) from None
