from __future__ import annotations

import asyncio
import base64
import gzip
import io
import ipaddress
import json
import re
import secrets
import shutil
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from exitlane.core import command
from exitlane.services import killswitch, provider_secrets, vpn_operations
from exitlane.services.killswitch import TunnelFacts
from exitlane.services.provider_wireguard import (
    EgressConfig,
    ProviderWireGuard,
    ProviderWireGuardError,
)

from .base import (
    InstallationState,
    Provider,
    ProviderActionUnsupported,
    ProviderControlPlaneFailure,
    ProviderFailureClass,
    ProviderMetadata,
)

API_ORIGIN = "https://api.mullvad.net"
TOKEN_PATH = "/auth/v1/webtoken"
DEVICES_PATH = "/accounts/v1/devices"
RELAYS_PATH = "/www/relays/all"
INTERFACE = "wg-mullvad"
DEFAULT_PORT = 51820
DEFAULT_MTU = 1380
DNS_ADDRESS = "10.64.0.1"
API_TIMEOUT_SECONDS = 15
MAX_ACCOUNT_RESPONSE = 256 * 1024
MAX_RELAY_RESPONSE = 8 * 1024 * 1024
TOKEN_TTL_SECONDS = 240
RELAY_TTL_SECONDS = 300

ACCOUNT_NUMBER_PATTERN = re.compile(r"^[0-9]{16}$")
COUNTRY_CODE_PATTERN = re.compile(r"^[a-z]{2}$")
CITY_CODE_PATTERN = re.compile(r"^[a-z0-9]{2,8}$")
HOSTNAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DEVICE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9 -]{1,64}$")

AUTHENTICATION_ERROR_CODES = frozenset(
    {
        "invalid_account_format",
        "invalid_account",
        "too_many_devices",
        "device_key_in_use",
        "credential_replacement_unsupported",
        "provider_api_timeout",
        "provider_api_unavailable",
        "provider_api_invalid_response",
        "provider_secret_key_unavailable",
        "provider_secret_storage_failed",
        "provider_error",
    }
)
SIGN_OUT_ERROR_CODES = frozenset(
    {
        "already_signed_out",
        "device_revoked",
        "provider_api_timeout",
        "provider_api_unavailable",
        "provider_api_invalid_response",
        "provider_error",
    }
)


class MullvadApiError(RuntimeError):
    def __init__(self, code: str, *, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_account_number(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = "".join(value.split())
    return normalized if ACCOUNT_NUMBER_PATTERN.fullmatch(normalized) else None


def _wireguard_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode("ascii"), base64.b64encode(public_raw).decode(
        "ascii"
    )


def _valid_wireguard_key(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 44:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        return None
    return value if len(decoded) == 32 else None


def _public_key_for_private(private_key: object) -> str | None:
    private = _valid_wireguard_key(private_key)
    if private is None:
        return None
    try:
        key = X25519PrivateKey.from_private_bytes(base64.b64decode(private))
    except ValueError:
        return None
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public).decode("ascii")


def _safe_label(value: object, maximum: int = 80) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip()
    if not result or len(result) > maximum or not result.isprintable():
        return None
    return result


def _ipv4_host(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError:
        return None
    return str(interface) if interface.version == 4 and interface.network.prefixlen == 32 else None


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    pubkey: str
    ipv4_address: str
    ipv6_address: str | None

    @classmethod
    def parse(cls, payload: object) -> Device:
        if not isinstance(payload, dict):
            raise MullvadApiError("provider_api_invalid_response")
        identifier = payload.get("id")
        name = payload.get("name")
        pubkey = _valid_wireguard_key(payload.get("pubkey"))
        ipv4 = _ipv4_host(payload.get("ipv4_address"))
        ipv6_value = payload.get("ipv6_address")
        try:
            ipv6 = str(ipaddress.ip_interface(ipv6_value)) if ipv6_value else None
        except (TypeError, ValueError):
            ipv6 = None
        if (
            not isinstance(identifier, str)
            or DEVICE_ID_PATTERN.fullmatch(identifier) is None
            or not isinstance(name, str)
            or DEVICE_NAME_PATTERN.fullmatch(name) is None
            or pubkey is None
            or ipv4 is None
            or (ipv6 is not None and ipaddress.ip_interface(ipv6).version != 6)
        ):
            raise MullvadApiError("provider_api_invalid_response")
        return cls(identifier, name, pubkey, ipv4, ipv6)


@dataclass(frozen=True)
class Relay:
    hostname: str
    country_code: str
    country: str
    city_code: str
    city: str
    endpoint: str
    pubkey: str

    @classmethod
    def parse(cls, payload: object) -> Relay | None:
        if not isinstance(payload, dict) or payload.get("type") != "wireguard":
            return None
        if payload.get("active") is not True:
            return None
        hostname = payload.get("hostname")
        country_code = payload.get("country_code")
        city_code = payload.get("city_code")
        country = _safe_label(payload.get("country_name"))
        city = _safe_label(payload.get("city_name"))
        pubkey = _valid_wireguard_key(payload.get("pubkey"))
        endpoint_value = payload.get("ipv4_addr_in")
        try:
            endpoint = ipaddress.ip_address(endpoint_value)
        except (TypeError, ValueError):
            return None
        if (
            not isinstance(hostname, str)
            or HOSTNAME_PATTERN.fullmatch(hostname) is None
            or not isinstance(country_code, str)
            or COUNTRY_CODE_PATTERN.fullmatch(country_code) is None
            or not isinstance(city_code, str)
            or CITY_CODE_PATTERN.fullmatch(city_code) is None
            or country is None
            or city is None
            or pubkey is None
            or endpoint.version != 4
            or not endpoint.is_global
        ):
            return None
        return cls(hostname, country_code, country, city_code, city, str(endpoint), pubkey)


class MullvadApi:
    """Narrow client for the endpoints used by Mullvad's official wg-tools."""

    def __init__(self, account_number: str | None = None):
        self.account_number = account_number
        self._token: str | None = None
        self._token_deadline = 0.0
        self._opener = urllib.request.build_opener(_NoRedirect)

    @staticmethod
    def _decode_response(response, maximum: int) -> object:
        raw = response.read(maximum + 1)
        if len(raw) > maximum:
            raise MullvadApiError("provider_api_invalid_response")
        if response.headers.get("Content-Encoding", "").casefold() == "gzip":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    raw = compressed.read(maximum + 1)
            except (OSError, EOFError) as error:
                raise MullvadApiError("provider_api_invalid_response") from error
            if len(raw) > maximum:
                raise MullvadApiError("provider_api_invalid_response")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise MullvadApiError("provider_api_invalid_response") from error

    def _request_sync(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict | None = None,
        token: str | None = None,
        maximum: int = MAX_ACCOUNT_RESPONSE,
        empty_ok: bool = False,
    ) -> object | None:
        if not path.startswith("/") or "//" in path or "?" in path or "#" in path:
            raise MullvadApiError("provider_api_invalid_response")
        encoded = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        request = urllib.request.Request(API_ORIGIN + path, data=encoded, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("Accept-Encoding", "gzip")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with self._opener.open(request, timeout=API_TIMEOUT_SECONDS) as response:
                if empty_ok and response.status == 204:
                    return None
                return self._decode_response(response, maximum)
        except urllib.error.HTTPError as error:
            try:
                error_payload = self._decode_response(error, MAX_ACCOUNT_RESPONSE)
            except MullvadApiError:
                error_payload = {}
            provider_code = error_payload.get("code") if isinstance(error_payload, dict) else None
            code = (
                "invalid_account"
                if error.code in {401, 403} or provider_code == "INVALID_ACCOUNT"
                else "device_revoked"
                if method == "DELETE" and error.code == 404
                else "too_many_devices"
                if provider_code in {"MAX_DEVICES_REACHED", "TOO_MANY_DEVICES"}
                else "device_key_in_use"
                if provider_code == "PUBKEY_IN_USE"
                else "provider_api_unavailable"
            )
            raise MullvadApiError(code, status=error.code) from error
        except (TimeoutError, urllib.error.URLError) as error:
            reason = getattr(error, "reason", None)
            code = (
                "provider_api_timeout"
                if isinstance(reason, TimeoutError)
                else "provider_api_unavailable"
            )
            raise MullvadApiError(code) from error

    async def token(self) -> str:
        if self._token and time.monotonic() < self._token_deadline:
            return self._token
        if self.account_number is None:
            raise MullvadApiError("invalid_account")
        payload = await asyncio.to_thread(
            self._request_sync,
            TOKEN_PATH,
            method="POST",
            body={"account_number": self.account_number},
        )
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not 16 <= len(token) <= 8192 or not token.isascii():
            raise MullvadApiError("provider_api_invalid_response")
        self._token = token
        self._token_deadline = time.monotonic() + TOKEN_TTL_SECONDS
        return token

    async def devices(self) -> list[Device]:
        payload = await asyncio.to_thread(
            self._request_sync, DEVICES_PATH, token=await self.token()
        )
        if not isinstance(payload, list) or len(payload) > 32:
            raise MullvadApiError("provider_api_invalid_response")
        return [Device.parse(item) for item in payload]

    async def create_device(self, pubkey: str) -> Device:
        payload = await asyncio.to_thread(
            self._request_sync,
            DEVICES_PATH,
            method="POST",
            body={"pubkey": pubkey, "hijack_dns": True},
            token=await self.token(),
        )
        return Device.parse(payload)

    async def delete_device(self, device_id: str) -> None:
        if DEVICE_ID_PATTERN.fullmatch(device_id) is None:
            raise MullvadApiError("provider_api_invalid_response")
        await asyncio.to_thread(
            self._request_sync,
            f"{DEVICES_PATH}/{device_id}",
            method="DELETE",
            token=await self.token(),
            empty_ok=True,
        )

    async def relays(self) -> list[Relay]:
        payload = await asyncio.to_thread(
            self._request_sync, RELAYS_PATH, maximum=MAX_RELAY_RESPONSE
        )
        if not isinstance(payload, list) or len(payload) > 4096:
            raise MullvadApiError("provider_api_invalid_response")
        result = [relay for item in payload if (relay := Relay.parse(item)) is not None]
        if not result:
            raise MullvadApiError("provider_api_invalid_response")
        return sorted(result, key=lambda relay: relay.hostname)


class Mullvad(Provider):
    id = "mullvad"
    display_name = "Mullvad VPN"
    authentication_error_codes = AUTHENTICATION_ERROR_CODES
    sign_out_error_codes = SIGN_OUT_ERROR_CODES
    supports_timeout_recovery = False
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="Mullvad",
        description="Direct Mullvad WireGuard egress",
        icon="shield-check",
        logo="/assets/providers/mullvad.svg",
        authentication_method="account_number",
    )

    def __init__(
        self,
        *,
        api_factory: Callable[[str | None], MullvadApi] = MullvadApi,
        wireguard: ProviderWireGuard | None = None,
    ):
        self.api_factory = api_factory
        self.wireguard = wireguard or ProviderWireGuard()
        self._relay_cache: list[Relay] = []
        self._relay_deadline = 0.0
        self._operation_lock = asyncio.Lock()

    @staticmethod
    def _state() -> dict[str, object] | None:
        return provider_secrets.load("mullvad")

    @staticmethod
    def _save(state: dict[str, object]) -> None:
        provider_secrets.save("mullvad", state)

    @staticmethod
    def _tools_available() -> bool:
        return all(shutil.which(name) for name in ("ip", "wg", "wg-quick", "ping"))

    @staticmethod
    async def _legacy_conflict() -> bool:
        daemon_rc, _, _ = await command("systemctl", "is-active", "mullvad-daemon", timeout=3)
        table_rc, _, _ = await command("nft", "list", "table", "inet", "mullvad", timeout=3)
        return daemon_rc == 0 or table_rc == 0

    def capabilities(
        self, *, installation_state: str, authentication_state: str, connection_state: str
    ) -> dict[str, bool]:
        available = installation_state == InstallationState.AVAILABLE
        authenticated = authentication_state == "signed_in"
        stable = connection_state in {"connected", "disconnected"}
        return {
            "can_sign_in": available and authentication_state == "signed_out",
            "can_sign_out": available and authenticated,
            "can_connect": available and authenticated and connection_state == "disconnected",
            "can_disconnect": available and authenticated and connection_state == "connected",
            "can_reconnect": available and authenticated and stable,
            "can_select_country": available and authenticated and stable,
            "can_select_server": available and authenticated and stable,
            "can_measure_latency": available and authenticated and stable,
            "can_select_location": available and authenticated and stable,
            "can_manage_provider_killswitch": False,
            "can_install": False,
        }

    async def installation_status(self) -> dict:
        available = self._tools_available()
        legacy_conflict = await self._legacy_conflict()
        return {
            "state": (
                InstallationState.FAILED
                if legacy_conflict
                else InstallationState.AVAILABLE
                if available
                else InstallationState.NOT_INSTALLED
            ),
            "phase": (
                "legacy_runtime_conflict"
                if legacy_conflict
                else "completed"
                if available
                else "dependencies_missing"
            ),
            "error_code": (
                "legacy_mullvad_runtime_conflict"
                if legacy_conflict
                else None
                if available
                else "provider_wireguard_tools_unavailable"
            ),
            "installation_in_progress": False,
            "provider_available": available,
            "operation_state": "completed" if available else "not_started",
            "retry_action": None,
        }

    async def start_installation(self) -> dict:
        raise ProviderActionUnsupported("managed_installation_unsupported")

    async def authenticate(self, credential: str) -> dict:
        account = normalize_account_number(credential)
        if account is None:
            return {"ok": False, "error": "invalid_account_format"}
        async with self._operation_lock:
            state: dict[str, object] | None = None
            try:
                state = self._state()
                if state and state.get("account_number") != account:
                    if state.get("registration") != "pending":
                        return {"ok": False, "error": "credential_replacement_unsupported"}
                    old_api = self.api_factory(str(state.get("account_number")))
                    try:
                        old_devices = await old_api.devices()
                    except MullvadApiError as error:
                        if error.code != "invalid_account":
                            return {"ok": False, "error": error.code}
                        old_devices = []
                    old_device = next(
                        (item for item in old_devices if item.pubkey == state.get("public_key")),
                        None,
                    )
                    if old_device is not None:
                        state.update(
                            {
                                "registration": "registered",
                                "device_id": old_device.id,
                                "device_name": old_device.name,
                                "ipv4_address": old_device.ipv4_address,
                                "ipv6_address": old_device.ipv6_address,
                            }
                        )
                        self._save(state)
                        return {"ok": False, "error": "credential_replacement_unsupported"}
                    provider_secrets.delete("mullvad")
                    state = None
                api = self.api_factory(account)
                devices = await api.devices()
                if not state:
                    private_key, public_key = _wireguard_keypair()
                    state = {
                        "version": 1,
                        "registration": "pending",
                        "account_number": account,
                        "private_key": private_key,
                        "public_key": public_key,
                    }
                    self._save(state)
                public_key = state.get("public_key")
                if (
                    _valid_wireguard_key(public_key) is None
                    or _public_key_for_private(state.get("private_key")) != public_key
                ):
                    return {"ok": False, "error": "provider_error"}
                device = next((item for item in devices if item.pubkey == public_key), None)
                if device is None:
                    device = await api.create_device(str(public_key))
                if device.pubkey != public_key:
                    raise MullvadApiError("provider_api_invalid_response")
                state.update(
                    {
                        "registration": "registered",
                        "device_id": device.id,
                        "device_name": device.name,
                        "ipv4_address": device.ipv4_address,
                        "ipv6_address": device.ipv6_address,
                    }
                )
                self._save(state)
                return {"ok": True, "error": None}
            except (MullvadApiError, provider_secrets.ProviderSecretError) as error:
                if (
                    isinstance(error, MullvadApiError)
                    and error.code == "invalid_account"
                    and state
                    and state.get("registration") == "pending"
                ):
                    provider_secrets.delete("mullvad")
                return {"ok": False, "error": error.code}

    async def sign_out(self) -> dict:
        async with self._operation_lock:
            state = self._state()
            if not state:
                return {"ok": True, "error": "already_signed_out", "already_signed_out": True}
            if state.get("active"):
                return {"ok": False, "error": "provider_error"}
            account = state.get("account_number")
            device_id = state.get("device_id")
            if not isinstance(account, str):
                return {"ok": False, "error": "provider_error"}
            try:
                ingress, _ = killswitch.configuration()
                await self.wireguard.stop_interface(INTERFACE)
                await self.wireguard.disarm(ingress, INTERFACE)
                api = self.api_factory(account)
                if not isinstance(device_id, str):
                    devices = await api.devices()
                    matched = next(
                        (item for item in devices if item.pubkey == state.get("public_key")), None
                    )
                    device_id = matched.id if matched else None
                if device_id is not None:
                    await api.delete_device(device_id)
            except MullvadApiError as error:
                if error.code not in {"device_revoked", "invalid_account"}:
                    return {"ok": False, "error": error.code}
            except ProviderWireGuardError:
                return {"ok": False, "error": "provider_error"}
            provider_secrets.delete("mullvad")
            self.wireguard.remove_config(INTERFACE)
            return {"ok": True, "error": None, "already_signed_out": False}

    async def _relays(self) -> list[Relay]:
        if self._relay_cache and time.monotonic() < self._relay_deadline:
            return list(self._relay_cache)
        self._relay_cache = await self.api_factory(None).relays()
        self._relay_deadline = time.monotonic() + RELAY_TTL_SECONDS
        return list(self._relay_cache)

    async def countries(self) -> list[dict]:
        relays = await self._relays()
        unique = {(item.country_code, item.country) for item in relays}
        return [
            {"id": code.upper(), "country_code": code.upper(), "provider_name": name}
            for code, name in sorted(unique)
        ]

    async def servers(self, location_id: int | str, *, limit: int = 5) -> list[dict]:
        code = str(location_id).casefold()
        if COUNTRY_CODE_PATTERN.fullmatch(code) is None:
            return []
        return [
            self._relay_dict(item) for item in await self._relays() if item.country_code == code
        ][:limit]

    @staticmethod
    def _relay_dict(relay: Relay) -> dict:
        return {
            "id": relay.hostname,
            "hostname": relay.hostname,
            "station": relay.endpoint,
            "country_code": relay.country_code.upper(),
            "city": relay.city,
            "city_code": relay.city_code,
        }

    async def _select_relay(self, target: str | None) -> Relay:
        relays = await self._relays()
        normalized = target.casefold() if isinstance(target, str) and target else None
        candidates = (
            relays
            if normalized is None
            else [item for item in relays if item.country_code == normalized]
            if COUNTRY_CODE_PATTERN.fullmatch(normalized)
            else [item for item in relays if item.hostname == normalized]
            if HOSTNAME_PATTERN.fullmatch(normalized)
            else []
        )
        if not candidates:
            raise MullvadApiError("relay_unavailable")
        return candidates[secrets.randbelow(len(candidates))]

    @staticmethod
    def _config(state: dict[str, object], relay: Relay, generation: str) -> EgressConfig:
        if _public_key_for_private(state.get("private_key")) != state.get("public_key"):
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        return EgressConfig(
            provider_id="mullvad",
            generation=generation,
            interface=INTERFACE,
            private_key=str(state["private_key"]),
            address=str(state["ipv4_address"]),
            peer_public_key=relay.pubkey,
            endpoint_address=relay.endpoint,
            dns_address=DNS_ADDRESS,
            endpoint_port=DEFAULT_PORT,
            mtu=DEFAULT_MTU,
        ).validated()

    async def _complete_owned_transition(self) -> bool:
        try:
            facts = await self.network_facts()
            await killswitch.complete_provider_transition(facts)
        except (
            killswitch.KillswitchError,
            ProviderWireGuardError,
            provider_secrets.ProviderSecretError,
        ):
            return False
        return True

    @staticmethod
    def _owns_transition() -> bool:
        operation = vpn_operations.active_snapshot()
        return not (
            isinstance(operation, dict) and operation.get("connection_id") == "provider-switch"
        )

    async def connect(self, target: str | None = None, *, timeout: float = 40) -> dict:
        async with self._operation_lock:
            state = self._state()
            if not state or state.get("registration") != "registered":
                return {"ok": False, "error_code": "provider_authentication_required"}
            owns_transition = self._owns_transition()
            if owns_transition:
                try:
                    await killswitch.arm_provider_transition()
                except killswitch.KillswitchError:
                    return {"ok": False, "error_code": "firewall_apply_failed"}
            previous_active = state.get("active") if isinstance(state.get("active"), dict) else None
            try:
                devices = await self.api_factory(str(state["account_number"])).devices()
                if not any(item.pubkey == state.get("public_key") for item in devices):
                    raise MullvadApiError("device_revoked")
                relay = await self._select_relay(target)
                generation = secrets.token_hex(16)
                config = self._config(state, relay, generation)
                state["pending"] = {"generation": generation, "relay": asdict(relay)}
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
                    code = (
                        "provider_dns_unavailable"
                        if observation.get("dataplane") is True
                        and observation.get("handshake", 0) > 0
                        and observation.get("dns") is False
                        else "vpn_connect_timeout"
                    )
                    raise MullvadApiError(code)
                state["active"] = {
                    "generation": generation,
                    "relay": asdict(relay),
                    "handshake": observation.get("handshake", 0),
                }
                state.pop("pending", None)
                self._save(state)
                if owns_transition and not await self._complete_owned_transition():
                    return {
                        "ok": False,
                        "action": "connect",
                        "state": "error",
                        "error_code": "firewall_apply_failed",
                    }
                return {
                    "ok": True,
                    "action": "connect",
                    "state": "connected",
                    "target": relay.hostname,
                    "error_code": None,
                }
            except asyncio.CancelledError:
                cleanup = asyncio.create_task(
                    self._rollback_connection(state, previous_active, timeout=min(5, timeout))
                )
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    await cleanup
                rollback_safe = cleanup.result()
                if owns_transition and rollback_safe:
                    transition_cleanup = asyncio.create_task(self._complete_owned_transition())
                    try:
                        await asyncio.shield(transition_cleanup)
                    except asyncio.CancelledError:
                        await transition_cleanup
                raise
            except (
                KeyError,
                TypeError,
                ValueError,
                MullvadApiError,
                ProviderWireGuardError,
                provider_secrets.ProviderSecretError,
            ) as error:  # rollback preserves the fail-closed route guard
                rollback_safe = await self._rollback_connection(
                    state, previous_active, timeout=min(5, timeout)
                )
                if owns_transition and rollback_safe:
                    await self._complete_owned_transition()
                code = getattr(error, "code", "provider_connect_failed")
                return {"ok": False, "action": "connect", "state": "error", "error_code": code}

    async def _rollback_connection(
        self, state: dict[str, object], previous_active: dict | None, *, timeout: float
    ) -> bool:
        candidate = state.get("pending") if isinstance(state.get("pending"), dict) else None
        state.pop("pending", None)
        state.pop("active", None)
        if previous_active:
            state["pending"] = {
                "generation": previous_active.get("generation"),
                "relay": previous_active.get("relay"),
                "recovery": "restore_previous",
            }
            try:
                old_relay = Relay(**previous_active["relay"])
                old_config = self._config(state, old_relay, str(previous_active["generation"]))
                ingress, _ = killswitch.configuration()
                await self.wireguard.start(old_config, ingress)
                observation = await self.wireguard.probe(old_config, timeout=timeout)
                if observation.get("ready") is True:
                    state["active"] = {
                        **previous_active,
                        "handshake": observation.get("handshake", 0),
                    }
                    state.pop("pending", None)
                    self._save(state)
                    return True
            except (KeyError, TypeError, ValueError, ProviderWireGuardError):
                pass
            try:
                await self.wireguard.stop_interface(INTERFACE)
            except ProviderWireGuardError:
                state["teardown_failed"] = True
        else:
            try:
                await self.wireguard.stop_interface(INTERFACE)
            except ProviderWireGuardError:
                state["teardown_failed"] = True
            state["pending"] = candidate or {"recovery": "failed_connect"}
        self._save(state)
        return False

    async def connect_country(
        self, country_code: str, *, server_hostname: str | None = None, timeout: float = 40
    ) -> dict:
        code = country_code.casefold()
        if COUNTRY_CODE_PATTERN.fullmatch(code) is None:
            return {"ok": False, "error_code": "invalid_target"}
        if server_hostname is not None:
            relay = next(
                (
                    item
                    for item in await self._relays()
                    if item.hostname == server_hostname.casefold()
                ),
                None,
            )
            if relay is None or relay.country_code != code:
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
                await self.wireguard.stop_interface(INTERFACE)
                ingress, _ = killswitch.configuration()
                await self.wireguard.disarm(ingress, INTERFACE)
                state = self._state()
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
        legacy_conflict = await self._legacy_conflict()
        available = installed and not legacy_conflict
        authenticated = bool(state and state.get("registration") == "registered")
        active = state.get("active") if isinstance(state, dict) else None
        connected = False
        observation: dict = {}
        relay: dict = {}
        if (
            not legacy_conflict
            and authenticated
            and isinstance(active, dict)
            and isinstance(active.get("relay"), dict)
        ):
            relay = active["relay"]
            try:
                config = self._config(state, Relay(**relay), str(active["generation"]))
                observation = await self.wireguard.observe(config)
                connected = observation.get("connected") is True
            except (KeyError, TypeError, ValueError, ProviderWireGuardError):
                connected = False
        connection_state = "connected" if connected else "disconnected"
        authentication_state = "signed_in" if authenticated else "signed_out"
        install_state = (
            InstallationState.FAILED
            if legacy_conflict
            else InstallationState.AVAILABLE
            if installed
            else InstallationState.NOT_INSTALLED
        )
        error_code = (
            "legacy_mullvad_runtime_conflict"
            if legacy_conflict
            else None
            if installed
            else "provider_wireguard_tools_unavailable"
        )
        return {
            "installed": installed,
            "available": available,
            "daemon_active": available,
            "authenticated": authenticated,
            "connected": connected,
            "state": connection_state,
            "country": relay.get("country"),
            "country_code": str(relay.get("country_code", "")).upper() or None,
            "city": relay.get("city"),
            "city_code": relay.get("city_code"),
            "server": relay.get("hostname"),
            "external_ip": None,
            "technology": "WireGuard",
            "tunnel_interface": INTERFACE if connected else None,
            "latency_endpoint": relay.get("endpoint"),
            "handshake": observation.get("handshake", 0),
            "error_code": error_code,
            "management": self.management_status(
                installation_state=install_state,
                authentication_state=authentication_state,
                connection_state=connection_state,
                error_code=error_code,
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
        state = self._state()
        if await self._legacy_conflict():
            return {"ok": False, "error_code": "legacy_mullvad_runtime_conflict"}
        if not self._tools_available():
            return {"ok": False, "error_code": "provider_wireguard_tools_unavailable"}
        if not state or state.get("registration") != "registered":
            return {"ok": False, "error_code": "provider_authentication_required"}
        try:
            devices = await self.api_factory(str(state["account_number"])).devices()
        except MullvadApiError as error:
            return {"ok": False, "error_code": error.code}
        if not any(item.pubkey == state.get("public_key") for item in devices):
            return {"ok": False, "error_code": "device_revoked"}
        return {"ok": True, "error_code": None}

    def classify_activation_failure(self, status: dict) -> ProviderControlPlaneFailure | None:
        error_code = status.get("error_code")
        if not error_code:
            return None
        transient = error_code in {"timeout", "provider_api_timeout", "provider_api_unavailable"}
        return ProviderControlPlaneFailure(
            operation="device_status",
            error_code=str(error_code),
            classification=(
                ProviderFailureClass.TRANSIENT if transient else ProviderFailureClass.TERMINAL
            ),
        )

    async def network_facts(self) -> TunnelFacts:
        current = await self.status()
        available = current.get("connected") is True
        return TunnelFacts(
            available=available,
            interface=INTERFACE if available else None,
            supports_ipv4=available,
            supports_ipv6=False,
            protected_egress=available,
            reason="tunnel_available" if available else "tunnel_unavailable",
        )


provider = Mullvad()
