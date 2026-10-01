"""PIA direct WireGuard adapter; ExitLane owns all local dataplane state."""

from __future__ import annotations

import asyncio
import secrets
import shutil
import time
from collections.abc import Callable
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
    ProviderControlPlaneFailure,
    ProviderFailureClass,
    ProviderMetadata,
)
from .pia_api import PiaApi, PiaApiError, PiaKeyResponse, PiaServer
from .wireguard_keys import _public_key_for_private, _wireguard_keypair

INTERFACE = "wg-pia"
CATALOG_TTL = 300
AUTH_ERRORS = frozenset(
    {
        "invalid_credential_payload",
        "invalid_credentials",
        "provider_api_timeout",
        "provider_api_unavailable",
        "provider_api_invalid_response",
        "provider_secret_key_unavailable",
        "provider_secret_storage_failed",
        "provider_error",
    }
)


def validate_credentials(username: str, password: str) -> bool:
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    if len(username) + len(password) > 512:
        return False
    return (
        1 <= len(username) <= 80
        and username.isascii()
        and username.isalnum()
        and 1 <= len(password) <= 400
        and password.isprintable()
    )


class Pia(Provider):
    id = "pia"
    display_name = "Private Internet Access"
    direct_egress_interface = INTERFACE
    authentication_error_codes = AUTH_ERRORS
    sign_out_error_codes = frozenset({"already_signed_out", "provider_error"})
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="PIA",
        description="Direct PIA WireGuard egress",
        icon="shield-check",
        authentication_method="username_password",
    )

    def __init__(
        self,
        *,
        api_factory: Callable[[str | None, str | None], PiaApi] = PiaApi,
        wireguard: ProviderWireGuard | None = None,
    ):
        self.api_factory = api_factory
        self.wireguard = wireguard or ProviderWireGuard()
        self._api: PiaApi | None = None
        self._catalog: list[PiaServer] = []
        self._catalog_deadline = 0.0
        self._operation_lock = asyncio.Lock()

    @staticmethod
    def _state() -> dict[str, object] | None:
        return provider_secrets.load("pia")

    @staticmethod
    def _save(state: dict[str, object]) -> None:
        provider_secrets.save("pia", state)

    @staticmethod
    def _tools_available() -> bool:
        return all(shutil.which(name) for name in ("ip", "wg", "wg-quick", "ping"))

    def _client(self, state: dict[str, object]) -> PiaApi:
        if self._api is None:
            self._api = self.api_factory(str(state["username"]), str(state["password"]))
        return self._api

    def direct_egress_intent(self) -> DirectEgressIntent | None:
        state = self._state()
        if not state:
            return None
        generation = (
            state.get("pending") if isinstance(state.get("pending"), dict) else state.get("active")
        )
        if not isinstance(generation, dict):
            return None
        return DirectEgressIntent(
            provider_id=self.id,
            connection_id="provider:pia",
            interface=INTERFACE,
            source_address=generation.get("address")
            if isinstance(generation.get("address"), str)
            else None,
            generation=generation.get("generation")
            if isinstance(generation.get("generation"), str)
            else None,
        )

    def capabilities(
        self, *, installation_state: str, authentication_state: str, connection_state: str
    ) -> dict[str, bool]:
        available = installation_state == InstallationState.AVAILABLE
        signed_in = authentication_state == "signed_in"
        stable = connection_state in {"connected", "disconnected"}
        return {
            "can_sign_in": available and not signed_in,
            "can_sign_out": available and signed_in,
            "can_connect": available and signed_in and connection_state == "disconnected",
            "can_disconnect": available and signed_in and connection_state == "connected",
            "can_reconnect": available and signed_in and stable,
            "can_select_country": available and signed_in and stable,
            "can_select_server": available and signed_in and stable,
            "can_measure_latency": available and signed_in and stable,
            "can_select_location": available and signed_in and stable,
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

    async def authenticate(self, credential: str) -> dict:
        del credential
        return {"ok": False, "error": "invalid_credential_payload"}

    async def authenticate_credentials(self, username: str, password: str) -> dict:
        if not validate_credentials(username, password):
            return {"ok": False, "error": "invalid_credential_payload"}
        async with self._operation_lock:
            try:
                if self._state():
                    return {"ok": False, "error": "provider_error"}
                client = self.api_factory(username, password)
                await client.token()
                self._save({"version": 1, "username": username, "password": password})
                self._api = client
                return {"ok": True, "error": None}
            except (PiaApiError, provider_secrets.ProviderSecretError) as error:
                return {"ok": False, "error": error.code}

    async def sign_out(self) -> dict:
        async with self._operation_lock:
            try:
                state = self._state()
                if not state:
                    return {"ok": True, "error": "already_signed_out", "already_signed_out": True}
                if state.get("active") or state.get("pending"):
                    return {"ok": False, "error": "provider_error"}
                await self.wireguard.stop_interface(INTERFACE)
                # A disconnected PIA generation was already disarmed by disconnect.
                # The shared table may now belong to another direct provider.
                provider_secrets.delete("pia")
                self._api = None
                self.wireguard.remove_config(INTERFACE)
                return {"ok": True, "error": None, "already_signed_out": False}
            except (ProviderWireGuardError, provider_secrets.ProviderSecretError):
                return {"ok": False, "error": "provider_error"}

    async def _servers(self) -> list[PiaServer]:
        if self._catalog and time.monotonic() < self._catalog_deadline:
            return list(self._catalog)
        catalog = await self.api_factory(None, None).catalog()
        self._catalog = catalog
        self._catalog_deadline = time.monotonic() + CATALOG_TTL
        return list(catalog)

    async def countries(self) -> list[dict]:
        unique = {(item.country_code, item.region_name) for item in await self._servers()}
        names: dict[str, str] = {}
        for code, name in sorted(unique):
            names.setdefault(code, name)
        return [
            {"id": code, "country_code": code, "provider_name": name}
            for code, name in sorted(names.items())
        ]

    async def servers(self, location_id: int | str, *, limit: int = 256) -> list[dict]:
        code = str(location_id).upper()
        if len(code) != 2 or not code.isalpha():
            return []
        matches = [item for item in await self._servers() if item.country_code == code]
        first_per_region: list[PiaServer] = []
        seen_regions: set[str] = set()
        for item in matches:
            if item.region_id not in seen_regions:
                seen_regions.add(item.region_id)
                first_per_region.append(item)
        ordered = first_per_region + [item for item in matches if item not in first_per_region]
        return [
            {
                "id": item.selection_id,
                "hostname": item.selection_id,
                "station": item.latency_address,
                "country_code": code,
                "city": item.region_name,
                "city_code": item.region_id,
            }
            for item in ordered
        ][:limit]

    async def _select(self, target: str | None) -> PiaServer:
        servers = await self._servers()
        if target is None:
            candidates = servers
        else:
            value = target.casefold()
            candidates = [
                item
                for item in servers
                if item.country_code.casefold() == value
                or item.selection_id == value
                or item.region_id == value
            ]
        if not candidates:
            raise PiaApiError("relay_unavailable")
        return candidates[secrets.randbelow(len(candidates))]

    @staticmethod
    def _config(generation: dict[str, object]) -> EgressConfig:
        if _public_key_for_private(generation.get("private_key")) != generation.get("public_key"):
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        server = PiaServer(**generation["server"])
        response = PiaKeyResponse(**generation["response"])
        return EgressConfig(
            provider_id="pia",
            generation=str(generation["generation"]),
            interface=INTERFACE,
            private_key=str(generation["private_key"]),
            address=response.peer_ip,
            peer_public_key=response.server_key,
            endpoint_address=server.address,
            dns_address=response.dns_address,
            endpoint_port=response.server_port,
            mtu=1380,
            dns_probe_hostname="privateinternetaccess.com",
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

    async def connect(self, target: str | None = None, *, timeout: float = 40) -> dict:
        async with self._operation_lock:
            state = self._state()
            if not state:
                return {"ok": False, "error_code": "provider_authentication_required"}
            owns_transition = self._owns_transition()
            if owns_transition:
                try:
                    await killswitch.arm_provider_transition()
                except killswitch.KillswitchError:
                    return {"ok": False, "error_code": "firewall_apply_failed"}
            previous = state.get("active") if isinstance(state.get("active"), dict) else None
            try:
                server = await self._select(target)
                private, public = _wireguard_keypair()
                response = await self._client(state).add_key(server, public)
                generation = {
                    "generation": secrets.token_hex(16),
                    "server": asdict(server),
                    "response": asdict(response),
                    "private_key": private,
                    "public_key": public,
                    "address": response.peer_ip,
                }
                config = self._config(generation)
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
                    raise PiaApiError(
                        "provider_dns_unavailable"
                        if observation.get("dataplane") is True and observation.get("dns") is False
                        else "vpn_connect_timeout"
                    )
                state["active"] = generation
                state.pop("pending", None)
                self._save(state)
                if owns_transition and not await self._complete_transition(config):
                    return {
                        "ok": False,
                        "action": "connect",
                        "state": "error",
                        "error_code": "firewall_apply_failed",
                    }
                await self.wireguard.committed(config)
                return {
                    "ok": True,
                    "action": "connect",
                    "state": "connected",
                    "target": server.selection_id,
                    "error_code": None,
                }
            except asyncio.CancelledError:
                cleanup = asyncio.create_task(
                    self._rollback(state, previous, timeout=min(5, timeout))
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
                PiaApiError,
                ProviderWireGuardError,
                provider_secrets.ProviderSecretError,
            ) as error:
                safe = await self._rollback(state, previous, timeout=min(5, timeout))
                if owns_transition and safe:
                    await self._complete_transition()
                return {
                    "ok": False,
                    "action": "connect",
                    "state": "error",
                    "error_code": getattr(error, "code", "provider_connect_failed"),
                }

    async def _rollback(
        self, state: dict[str, object], previous: dict | None, *, timeout: float
    ) -> bool:
        candidate = state.get("pending") if isinstance(state.get("pending"), dict) else None
        state.pop("active", None)
        state.pop("pending", None)
        if previous:
            state["pending"] = previous
            self._save(state)
            try:
                config = self._config(previous)
                ingress, _ = killswitch.configuration()
                await self.wireguard.start(config, ingress)
                observation = await self.wireguard.probe(config, timeout=timeout)
                if observation.get("ready") is True:
                    state["active"] = previous
                    state.pop("pending", None)
                    self._save(state)
                    await self.wireguard.committed(config)
                    return True
            except (KeyError, TypeError, ValueError, ProviderWireGuardError):
                pass
            # PIA may replace a peer binding when addKey registers the next key.
            # Re-register the last proven key before declaring rollback failed.
            try:
                restored = dict(previous)
                response = await self._client(state).add_key(
                    PiaServer(**previous["server"]), str(previous["public_key"])
                )
                restored["response"] = asdict(response)
                restored["address"] = response.peer_ip
                state["pending"] = restored
                self._save(state)
                config = self._config(restored)
                ingress, _ = killswitch.configuration()
                await self.wireguard.start(config, ingress)
                observation = await self.wireguard.probe(config, timeout=timeout)
                if observation.get("ready") is True:
                    state["active"] = restored
                    state.pop("pending", None)
                    self._save(state)
                    await self.wireguard.committed(config)
                    return True
            except (KeyError, TypeError, ValueError, PiaApiError, ProviderWireGuardError):
                pass
        teardown_failed = False
        try:
            await self.wireguard.stop_interface(INTERFACE)
            if previous is None and candidate is not None:
                # A failed first generation may already have installed the PIA
                # probe rule. Remove it before another direct provider starts.
                ingress, _ = killswitch.configuration()
                await self.wireguard.disarm(ingress, INTERFACE)
        except ProviderWireGuardError:
            state["teardown_failed"] = True
            teardown_failed = True
        if previous:
            # The old active identity still needs a fail-closed boot guard.
            state["pending"] = previous
        elif teardown_failed:
            # An uncertain local interface must retain its generation intent.
            state["pending"] = candidate or {"recovery": "failed_connect"}
        else:
            state.pop("teardown_failed", None)
        self._save(state)
        return False

    async def connect_country(
        self, country_code: str, *, server_hostname: str | None = None, timeout: float = 40
    ) -> dict:
        code = country_code.upper()
        if len(code) != 2 or not code.isalpha():
            return {"ok": False, "error_code": "invalid_target"}
        if server_hostname is not None:
            matching = [
                item
                for item in await self._servers()
                if item.country_code == code and item.selection_id == server_hostname.casefold()
            ]
            if not matching:
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
                ingress, _ = killswitch.configuration()
                generation = state.get("active") if isinstance(state, dict) else None
                if isinstance(generation, dict):
                    await self.wireguard.arm_source(INTERFACE, generation["address"])
                await self.wireguard.stop_interface(INTERFACE)
                await self.wireguard.disarm(ingress, INTERFACE)
                if state:
                    state.pop("active", None)
                    state.pop("pending", None)
                    self._save(state)
                if owns_transition:
                    await killswitch.complete_provider_transition(TunnelFacts(False))
                return {
                    "ok": True,
                    "action": "disconnect",
                    "state": "disconnected",
                    "error_code": None,
                }
            except (
                KeyError,
                ProviderWireGuardError,
                provider_secrets.ProviderSecretError,
                killswitch.KillswitchError,
            ):
                return {
                    "ok": False,
                    "action": "disconnect",
                    "state": "error",
                    "error_code": "provider_disconnect_failed",
                }

    async def status(self, *, timeout: float = 8) -> dict:
        del timeout
        state = self._state()
        installed = self._tools_available()
        active = state.get("active") if isinstance(state, dict) else None
        connected = False
        observation: dict = {}
        server: dict = {}
        if isinstance(active, dict):
            server = active.get("server") if isinstance(active.get("server"), dict) else {}
            try:
                observation = await self.wireguard.observe(self._config(active))
                connected = observation.get("connected") is True
            except (KeyError, TypeError, ValueError, ProviderWireGuardError):
                pass
        state_name = "connected" if connected else "disconnected"
        signed_in = bool(state and isinstance(state.get("username"), str))
        install_state = (
            InstallationState.AVAILABLE if installed else InstallationState.NOT_INSTALLED
        )
        error = None if installed else "provider_wireguard_tools_unavailable"
        return {
            "installed": installed,
            "available": installed,
            "daemon_active": installed,
            "authenticated": signed_in,
            "connected": connected,
            "state": state_name,
            "country": server.get("region_name"),
            "country_code": server.get("country_code"),
            "city": server.get("region_name"),
            "city_code": server.get("region_id"),
            "server": (
                f"{server['region_id']}.{server['hostname']}"
                if server.get("region_id") and server.get("hostname")
                else None
            ),
            "external_ip": None,
            "technology": "WireGuard",
            "tunnel_interface": INTERFACE if connected else None,
            "latency_endpoint": server.get("latency_address"),
            "handshake": observation.get("handshake", 0),
            "error_code": error,
            "management": self.management_status(
                installation_state=install_state,
                authentication_state="signed_in" if signed_in else "signed_out",
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
        state = self._state()
        if not state:
            return {"ok": False, "error_code": "provider_authentication_required"}
        try:
            await self._client(state).token()
            await self._servers()
            return {"ok": True, "error_code": None}
        except (PiaApiError, provider_secrets.ProviderSecretError) as error:
            return {"ok": False, "error_code": error.code}

    def classify_activation_failure(self, status: dict) -> ProviderControlPlaneFailure | None:
        code = status.get("error_code")
        if not code:
            return None
        return ProviderControlPlaneFailure(
            operation="pia_readiness",
            error_code=str(code),
            classification=(
                ProviderFailureClass.TRANSIENT
                if code in {"provider_api_timeout", "provider_api_unavailable"}
                else ProviderFailureClass.TERMINAL
            ),
        )

    async def network_facts(self) -> TunnelFacts:
        current = await self.status()
        connected = current.get("connected") is True
        return TunnelFacts(
            available=connected,
            interface=INTERFACE if connected else None,
            supports_ipv4=connected,
            supports_ipv6=False,
            protected_egress=connected,
            reason="tunnel_available" if connected else "tunnel_unavailable",
        )


provider = Pia()
