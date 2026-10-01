"""Imported Proton WireGuard profiles using the shared direct-egress lifecycle."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import shutil
import socket
import time
from dataclasses import asdict

from exitlane.services import killswitch, provider_secrets, vpn_operations
from exitlane.services.killswitch import TunnelFacts
from exitlane.services.provider_wireguard import (
    EgressConfig,
    ProviderWireGuard,
    ProviderWireGuardError,
)

from .base import (
    DirectEgressIntent,
    InstallationState,
    Provider,
    ProviderActionUnsupported,
    ProviderMetadata,
)
from .proton_profile import ProtonProfile, ProtonProfileError, parse_profile

INTERFACE = "wg-proton"
MAX_PROFILES = 32
DISPLAY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,79}$")


class Proton(Provider):
    id = "proton"
    display_name = "Proton VPN"
    direct_egress_interface = INTERFACE
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="Proton",
        description="Imported Proton WireGuard profiles",
        icon="shield-check",
        authentication_method="profile_import",
    )

    def __init__(self, *, wireguard: ProviderWireGuard | None = None):
        self.wireguard = wireguard or ProviderWireGuard()
        self._operation_lock = asyncio.Lock()

    @staticmethod
    def _state() -> dict:
        return provider_secrets.load("proton") or {"version": 1, "profiles": {}}

    @staticmethod
    def _save(state: dict) -> None:
        provider_secrets.save("proton", state)

    @staticmethod
    def _tools_available() -> bool:
        return all(shutil.which(name) for name in ("ip", "wg", "wg-quick", "ping"))

    @staticmethod
    def _profiles(state: dict) -> dict[str, dict]:
        value = state.get("profiles")
        if not isinstance(value, dict):
            raise ProtonProfileError()
        return value

    def direct_egress_intent(self) -> DirectEgressIntent | None:
        state = self._state()
        generation = state.get("pending") or state.get("active")
        if not isinstance(generation, dict):
            return None
        return DirectEgressIntent(
            provider_id=self.id,
            connection_id="provider:proton",
            interface=INTERFACE,
            source_address=generation.get("address"),
            generation=generation.get("generation"),
        )

    async def import_profile(
        self, content: str, display_name: str, country_code: str | None = None
    ) -> dict:
        if (
            not isinstance(display_name, str)
            or DISPLAY_NAME.fullmatch(display_name.strip()) is None
            or (
                country_code is not None
                and (
                    not isinstance(country_code, str)
                    or len(country_code) != 2
                    or not country_code.isascii()
                    or not country_code.isalpha()
                )
            )
        ):
            return {"ok": False, "error_code": "invalid_proton_profile_metadata"}
        try:
            parsed = parse_profile(content)
            async with self._operation_lock:
                state = self._state()
                profiles = self._profiles(state)
                if len(profiles) >= MAX_PROFILES:
                    return {"ok": False, "error_code": "proton_profile_limit"}
                if any(item.get("config") == asdict(parsed) for item in profiles.values()):
                    return {"ok": False, "error_code": "proton_profile_duplicate"}
                identifier = secrets.token_hex(12)
                profiles[identifier] = {
                    "id": identifier,
                    "name": display_name.strip(),
                    "country_code": country_code.upper() if country_code else None,
                    "imported_at": int(time.time()),
                    "config": asdict(parsed),
                }
                self._save(state)
                return {"ok": True, "profile": self._summary(profiles[identifier])}
        except (ProtonProfileError, provider_secrets.ProviderSecretError) as error:
            return {"ok": False, "error_code": getattr(error, "code", "invalid_proton_profile")}

    @staticmethod
    def _summary(item: dict) -> dict:
        config = item["config"]
        return {
            "id": item["id"],
            "display_name": item["name"],
            "country_code": item["country_code"],
            "endpoint": config["endpoint_host"],
            "port": config["endpoint_port"],
            "imported_at": item["imported_at"],
        }

    async def list_profiles(self) -> list[dict]:
        return [self._summary(item) for item in self._profiles(self._state()).values()]

    async def rename_profile(self, identifier: str, display_name: str) -> dict:
        if (
            not isinstance(display_name, str)
            or DISPLAY_NAME.fullmatch(display_name.strip()) is None
        ):
            return {"ok": False, "error_code": "invalid_proton_profile_metadata"}
        async with self._operation_lock:
            state = self._state()
            profile = self._profiles(state).get(identifier)
            if profile is None:
                return {"ok": False, "error_code": "proton_profile_not_found"}
            profile["name"] = display_name.strip()
            self._save(state)
            return {"ok": True, "profile": self._summary(profile)}

    async def delete_profile(self, identifier: str) -> dict:
        async with self._operation_lock:
            state = self._state()
            if identifier not in self._profiles(state):
                return {"ok": False, "error_code": "proton_profile_not_found"}
            if any(
                isinstance(state.get(key), dict) and state[key].get("profile_id") == identifier
                for key in ("active", "pending")
            ):
                return {"ok": False, "error_code": "proton_profile_active"}
            if (
                state.get("last_profile_id") == identifier
                and not state.get("active")
                and not state.get("pending")
            ):
                try:
                    self.wireguard.remove_config(INTERFACE)
                except OSError:
                    return {"ok": False, "error_code": "proton_profile_cleanup_failed"}
            del state["profiles"][identifier]
            if state.get("last_profile_id") == identifier:
                state.pop("last_profile_id", None)
            self._save(state)
            return {"ok": True}

    def capabilities(
        self, *, installation_state: str, authentication_state: str, connection_state: str
    ) -> dict[str, bool]:
        configured = authentication_state == "configured"
        available = installation_state == InstallationState.AVAILABLE
        return {
            "can_sign_in": False,
            "can_sign_out": False,
            "can_connect": available and configured and connection_state == "disconnected",
            "can_disconnect": available and configured and connection_state == "connected",
            "can_reconnect": available
            and configured
            and connection_state in {"connected", "disconnected"},
            "can_select_country": available and configured,
            "can_select_server": available and configured,
            "can_measure_latency": available and configured,
            "can_select_location": available and configured,
            "can_manage_provider_killswitch": False,
            "can_install": False,
        }

    async def installation_status(self) -> dict:
        available = self._tools_available()
        return {
            "state": InstallationState.AVAILABLE if available else InstallationState.NOT_INSTALLED,
            "phase": "completed" if available else "dependencies_missing",
            "error_code": None if available else "provider_wireguard_tools_unavailable",
            "installation_in_progress": False,
            "provider_available": available,
            "operation_state": "completed" if available else "not_started",
            "retry_action": None,
        }

    async def start_installation(self) -> dict:
        raise ProviderActionUnsupported("managed_installation_unsupported")

    async def countries(self) -> list[dict]:
        profiles = self._profiles(self._state()).values()
        codes = sorted({item["country_code"] for item in profiles if item["country_code"]})
        return [{"id": code, "country_code": code, "provider_name": code} for code in codes]

    async def servers(self, location_id: int | str, *, limit: int = 256) -> list[dict]:
        code = str(location_id).upper()
        return [
            {
                "id": item["id"],
                "hostname": item["id"],
                "station": item["config"]["endpoint_host"],
                "country_code": code,
                "city": item["name"],
                "city_code": item["id"],
            }
            for item in self._profiles(self._state()).values()
            if item["country_code"] == code
        ][:limit]

    async def _endpoint(self, host: str) -> str:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                answers = await asyncio.wait_for(
                    asyncio.to_thread(
                        socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_DGRAM
                    ),
                    timeout=5,
                )
            except (OSError, TimeoutError) as error:
                raise ProtonProfileError("proton_endpoint_unavailable") from error
            candidates = sorted({item[4][0] for item in answers})
            if not candidates:
                raise ProtonProfileError("proton_endpoint_unavailable")
            address = ipaddress.ip_address(candidates[0])
        if address.version != 4 or not address.is_global:
            raise ProtonProfileError("proton_endpoint_invalid")
        return str(address)

    @staticmethod
    def _config(profile: dict, generation: dict) -> EgressConfig:
        item = ProtonProfile(**profile["config"])
        return EgressConfig(
            provider_id="proton",
            generation=generation["generation"],
            interface=INTERFACE,
            private_key=item.private_key,
            address=item.address,
            peer_public_key=item.peer_public_key,
            endpoint_address=generation["endpoint_address"],
            endpoint_port=item.endpoint_port,
            dns_address=item.dns_address,
            mtu=item.mtu,
            dns_probe_hostname="protonvpn.com",
            preshared_key=item.preshared_key,
        ).validated()

    @staticmethod
    def _owns_transition() -> bool:
        operation = vpn_operations.active_snapshot()
        return not (
            isinstance(operation, dict) and operation.get("connection_id") == "provider-switch"
        )

    async def _complete_transition(self, config: EgressConfig | None = None) -> bool:
        try:
            facts = await self.wireguard.transition_facts(config) if config is not None else None
            if facts is None:
                facts = await self.network_facts()
            await killswitch.complete_provider_transition(facts)
            return True
        except (
            killswitch.KillswitchError,
            ProviderWireGuardError,
            provider_secrets.ProviderSecretError,
        ):
            return False

    async def _restore(
        self, state: dict, previous: dict | None, candidate: dict | None, *, timeout: float
    ) -> bool:
        state.pop("active", None)
        state.pop("pending", None)
        if previous:
            state["pending"] = previous
            self._save(state)
            try:
                profile = self._profiles(state)[previous["profile_id"]]
                ingress, _ = killswitch.configuration()
                config = self._config(profile, previous)
                await self.wireguard.start(config, ingress)
                if (await self.wireguard.probe(config, timeout=timeout)).get("ready") is True:
                    state["active"] = previous
                    state.pop("pending", None)
                    self._save(state)
                    await self.wireguard.committed(config)
                    return True
            except (KeyError, TypeError, ValueError, ProviderWireGuardError):
                pass
        try:
            await self.wireguard.stop_interface(INTERFACE)
            self.wireguard.remove_config(INTERFACE)
            if previous is None and candidate is not None:
                ingress, _ = killswitch.configuration()
                await self.wireguard.disarm(ingress, INTERFACE)
        except (OSError, ProviderWireGuardError):
            state["pending"] = previous or candidate or {"recovery": "failed_connect"}
            state["teardown_failed"] = True
        else:
            if previous:
                state["pending"] = previous
            state.pop("teardown_failed", None)
        self._save(state)
        return False

    async def connect(self, target: str | None = None, *, timeout: float = 40) -> dict:
        async with self._operation_lock:
            state = self._state()
            profiles = self._profiles(state)
            if not profiles:
                return {"ok": False, "error_code": "proton_profile_required"}
            if isinstance(target, str) and target in profiles:
                profile = profiles[target]
            else:
                remembered = state.get("active") or {}
                preferred_id = remembered.get("profile_id") or state.get("last_profile_id")
                if target is None and preferred_id in profiles:
                    candidates = [profiles[preferred_id]]
                elif target is None:
                    candidates = list(profiles.values())
                elif isinstance(target, str) and re.fullmatch(r"[A-Za-z]{2}", target):
                    candidates = [
                        item for item in profiles.values() if item["country_code"] == target.upper()
                    ]
                else:
                    candidates = []
                if not candidates:
                    return {"ok": False, "error_code": "proton_profile_not_found"}
                profile = candidates[secrets.randbelow(len(candidates))]
            try:
                item = ProtonProfile(**profile["config"])
            except (KeyError, TypeError, ValueError):
                return {"ok": False, "error_code": "invalid_proton_profile"}
            owns_transition = self._owns_transition()
            if owns_transition:
                try:
                    await killswitch.arm_provider_transition()
                except killswitch.KillswitchError:
                    return {"ok": False, "error_code": "firewall_apply_failed"}
            previous = state.get("active") if isinstance(state.get("active"), dict) else None
            try:
                endpoint = await self._endpoint(item.endpoint_host)
                generation = {
                    "generation": secrets.token_hex(16),
                    "profile_id": profile["id"],
                    "endpoint_address": endpoint,
                    "address": item.address,
                }
                config = self._config(profile, generation)
                state["pending"] = generation
                self._save(state)
                ingress, _ = killswitch.configuration()
                await self.wireguard.start(config, ingress)
                deadline = time.monotonic() + max(1, timeout)
                observation = {"ready": False}
                while time.monotonic() < deadline:
                    observation = await self.wireguard.probe(config, timeout=min(5, timeout))
                    if observation.get("ready") is True:
                        break
                    await asyncio.sleep(0.5)
                if observation.get("ready") is not True:
                    raise ProtonProfileError("vpn_connect_timeout")
                state["active"] = generation
                state["last_profile_id"] = profile["id"]
                state.pop("pending", None)
                self._save(state)
                if owns_transition and not await self._complete_transition(config):
                    return {"ok": False, "error_code": "firewall_apply_failed"}
                await self.wireguard.committed(config)
                return {
                    "ok": True,
                    "state": "connected",
                    "target": profile["id"],
                    "error_code": None,
                }
            except asyncio.CancelledError:
                cleanup = asyncio.create_task(
                    self._restore(state, previous, state.get("pending"), timeout=min(5, timeout))
                )
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    await cleanup
                if owns_transition and cleanup.result():
                    await self._complete_transition()
                raise
            except (
                KeyError,
                TypeError,
                ValueError,
                ProtonProfileError,
                ProviderWireGuardError,
                provider_secrets.ProviderSecretError,
            ) as error:
                safe = await self._restore(
                    state, previous, state.get("pending"), timeout=min(5, timeout)
                )
                if owns_transition and safe:
                    await self._complete_transition()
                return {
                    "ok": False,
                    "state": "error",
                    "error_code": getattr(error, "code", "provider_connect_failed"),
                }

    async def connect_country(
        self, country_code: str, *, server_hostname: str | None = None, timeout: float = 40
    ) -> dict:
        code = country_code.upper()
        if len(code) != 2 or not code.isalpha():
            return {"ok": False, "error_code": "invalid_target"}
        if server_hostname is not None:
            profile = self._profiles(self._state()).get(server_hostname)
            if profile is None or profile["country_code"] != code:
                return {"ok": False, "error_code": "invalid_target"}
        return await self.connect(server_hostname or code, timeout=timeout)

    async def reconnect(self, target: str | None = None, *, timeout: float = 40) -> dict:
        return await self.connect(target, timeout=timeout)

    async def disconnect(self, *, timeout: float = 15) -> dict:
        del timeout
        async with self._operation_lock:
            owns_transition = self._owns_transition()
            try:
                if owns_transition:
                    await killswitch.arm_provider_transition()
                state = self._state()
                generation = state.get("active")
                ingress, _ = killswitch.configuration()
                if isinstance(generation, dict):
                    await self.wireguard.arm_source(INTERFACE, generation["address"])
                await self.wireguard.stop_interface(INTERFACE)
                await self.wireguard.disarm(ingress, INTERFACE)
                self.wireguard.remove_config(INTERFACE)
                state.pop("active", None)
                state.pop("pending", None)
                self._save(state)
                if owns_transition:
                    await killswitch.complete_provider_transition(TunnelFacts(False))
                return {"ok": True, "state": "disconnected", "error_code": None}
            except (
                KeyError,
                OSError,
                ProviderWireGuardError,
                provider_secrets.ProviderSecretError,
                killswitch.KillswitchError,
            ):
                return {"ok": False, "state": "error", "error_code": "provider_disconnect_failed"}

    async def status(self, *, timeout: float = 8) -> dict:
        del timeout
        state = self._state()
        profiles = self._profiles(state)
        generation = state.get("active")
        profile = (
            profiles.get(generation.get("profile_id")) if isinstance(generation, dict) else None
        )
        observation: dict = {}
        connected = False
        if profile is not None:
            try:
                observation = await self.wireguard.observe(self._config(profile, generation))
                connected = observation.get("connected") is True
            except (KeyError, TypeError, ValueError, ProviderWireGuardError):
                pass
        available = self._tools_available()
        state_name = "connected" if connected else "disconnected"
        configured = bool(profiles)
        error = None if available else "provider_wireguard_tools_unavailable"
        return {
            "installed": available,
            "available": available,
            "daemon_active": available,
            "authenticated": configured,
            "connected": connected,
            "state": state_name,
            "country": profile["country_code"] if profile else None,
            "country_code": profile["country_code"] if profile else None,
            "city": profile["name"] if profile else None,
            "city_code": profile["id"] if profile else None,
            "server": profile["id"] if profile else None,
            "external_ip": None,
            "technology": "WireGuard",
            "tunnel_interface": INTERFACE if connected else None,
            "latency_endpoint": profile["config"]["endpoint_host"] if profile else None,
            "handshake": observation.get("handshake", 0),
            "error_code": error,
            "management": self.management_status(
                installation_state=InstallationState.AVAILABLE
                if available
                else InstallationState.NOT_INSTALLED,
                authentication_state="configured" if configured else "unconfigured",
                connection_state=state_name,
                error_code=error,
            ),
        }

    async def local_status(self, *, timeout: float = 6) -> dict:
        current = await self.status(timeout=timeout)
        return {
            "installed": current["installed"],
            "daemon_active": current["available"],
            "local_control_available": current["available"],
            "connected": current["connected"],
            "connection_state": current["state"],
            "error_code": current["error_code"],
        }

    async def prepare_activation(self) -> dict:
        if not self._tools_available():
            return {"ok": False, "error_code": "provider_wireguard_tools_unavailable"}
        if not self._profiles(self._state()):
            return {"ok": False, "error_code": "proton_profile_required"}
        return {"ok": True, "error_code": None}

    async def network_facts(self) -> TunnelFacts:
        connected = (await self.status())["connected"]
        return TunnelFacts(
            available=connected,
            interface=INTERFACE if connected else None,
            supports_ipv4=connected,
            supports_ipv6=False,
            protected_egress=connected,
            reason="tunnel_available" if connected else "tunnel_unavailable",
        )


provider = Proton()
