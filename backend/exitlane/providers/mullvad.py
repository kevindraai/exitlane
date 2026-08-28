from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from exitlane.core import command
from exitlane.services.killswitch import TunnelFacts

from .base import InstallationState, Provider, ProviderMetadata

logger = logging.getLogger(__name__)

ACCOUNT_NUMBER_PATTERN = re.compile(r"^[0-9]{16}$")
COUNTRY_CODE_PATTERN = re.compile(r"^[a-z]{2}$")
CITY_CODE_PATTERN = re.compile(r"^[a-z]{3}$")
RELAY_HOSTNAME_PATTERN = re.compile(r"^(?P<country>[a-z]{2})-(?P<city>[a-z]{3})-[a-z0-9-]{2,48}$")
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
LOGIN_TIMEOUT_SECONDS = 35
SIGN_OUT_TIMEOUT_SECONDS = 15
STATUS_TIMEOUT_SECONDS = 8
SENSITIVE_OUTPUT_LIMIT = 16 * 1024

AUTHENTICATION_ERROR_CODES = frozenset(
    {
        "already_logged_in",
        "invalid_account_format",
        "invalid_account",
        "too_many_devices",
        "account_expired",
        "timeout",
        "daemon_unavailable",
        "command_unavailable",
        "credential_replacement_unsupported",
        "provider_error",
    }
)
SIGN_OUT_ERROR_CODES = frozenset(
    {
        "already_signed_out",
        "timeout",
        "daemon_unavailable",
        "command_unavailable",
        "provider_error",
    }
)


def _provider_cli_environment() -> dict[str, str]:
    """Use a fixed locale without adding credential-bearing environment values."""
    environment = {
        name: os.environ[name]
        for name in ("HOME", "PATH", "XDG_RUNTIME_DIR")
        if name in os.environ
    }
    environment.update({"LANG": "C", "LC_ALL": "C"})
    return environment


def normalize_account_number(value: str) -> str | None:
    normalized = "".join(value.split())
    return normalized if ACCOUNT_NUMBER_PATTERN.fullmatch(normalized) else None


def _ascii_lower_in_place(value: bytearray) -> None:
    for index, byte in enumerate(value):
        if 65 <= byte <= 90:
            value[index] = byte + 32


async def _collect_sensitive_output(
    stream: asyncio.StreamReader,
    sink: bytearray,
) -> None:
    while chunk := await stream.read(1024):
        remaining = SENSITIVE_OUTPUT_LIMIT - len(sink)
        if remaining > 0:
            sink.extend(chunk[:remaining])


async def _run_sensitive_cli(
    *args: str,
    input_value: str | None = None,
    timeout: float,
    executable: str = "mullvad",
) -> tuple[int, bytearray]:
    """Run a Mullvad account command without putting credentials in argv or journals."""
    output = bytearray()
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            *args,
            stdin=asyncio.subprocess.PIPE if input_value is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=_provider_cli_environment(),
        )
    except FileNotFoundError:
        return 127, output

    if process.stdout is None:
        if process.returncode is None:
            process.kill()
            await process.wait()
        return 1, output
    reader = asyncio.create_task(_collect_sensitive_output(process.stdout, output))
    encoded = bytearray()
    try:
        if input_value is not None:
            if process.stdin is None:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                return 1, output
            encoded.extend(input_value.encode("ascii"))
            process.stdin.write(encoded)
            process.stdin.write(b"\n")
            await process.stdin.drain()
            process.stdin.close()
            with suppress(BrokenPipeError, ConnectionResetError):
                await process.stdin.wait_closed()
        try:
            await asyncio.wait_for(process.wait(), timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            return 124, output
        await reader
        return int(process.returncode or 0), output
    except asyncio.CancelledError:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise
    finally:
        encoded[:] = b"\0" * len(encoded)
        if not reader.done():
            reader.cancel()
            with suppress(asyncio.CancelledError):
                await reader


def classify_login_failure(return_code: int, output: bytes | bytearray) -> str | None:
    if return_code == 0:
        return None
    if return_code == 124:
        return "timeout"
    if return_code == 127:
        return "command_unavailable"
    message = bytearray(output)
    _ascii_lower_in_place(message)
    try:
        if b"too many devices" in message or b"one must be revoked" in message:
            return "too_many_devices"
        if b"account does not exist" in message or b"invalid account" in message:
            return "invalid_account"
        if b"already logged in" in message:
            return "already_logged_in"
        if b"out of time" in message or b"account has expired" in message:
            return "account_expired"
        if b"management rpc" in message or b"connect to mullvad daemon" in message:
            return "daemon_unavailable"
        return "provider_error"
    finally:
        message[:] = b"\0" * len(message)


def classify_sign_out_failure(
    return_code: int, output: bytes | bytearray | str
) -> str | None:
    if return_code == 0:
        return None
    if return_code == 124:
        return "timeout"
    if return_code == 127:
        return "command_unavailable"
    message = bytearray(output.encode() if isinstance(output, str) else output)
    _ascii_lower_in_place(message)
    try:
        if b"not logged in" in message or b"already logged out" in message:
            return "already_signed_out"
        if b"management rpc" in message or b"connect to mullvad daemon" in message:
            return "daemon_unavailable"
        return "provider_error"
    finally:
        message[:] = b"\0" * len(message)


def _safe_ip_from_endpoint(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    address = value.strip()
    if address.startswith("[") and "]:" in address:
        address = address[1 : address.index("]:")]
    elif address.count(":") == 1:
        address = address.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None


def _safe_label(value: object, *, maximum_length: int = 80) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.strip()
    if (
        not label
        or len(label) > maximum_length
        or not label.isprintable()
        or any(character in label for character in "<>&")
    ):
        return None
    return label


def parse_status_json(output: str) -> dict:
    try:
        payload = json.loads(output)
    except (TypeError, ValueError):
        return {"state": "error", "error_code": "provider_status_unavailable"}
    if not isinstance(payload, dict):
        return {"state": "error", "error_code": "provider_status_unavailable"}

    state = payload.get("state")
    if state not in {"disconnected", "connecting", "connected", "disconnecting", "error"}:
        return {"state": "error", "error_code": "provider_status_unavailable"}
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    endpoint = details.get("endpoint") if isinstance(details.get("endpoint"), dict) else {}
    location = details.get("location") if isinstance(details.get("location"), dict) else {}
    active = state in {"connecting", "connected"}

    hostname = location.get("hostname") if active else None
    if not isinstance(hostname, str) or not RELAY_HOSTNAME_PATTERN.fullmatch(hostname):
        hostname = None
    hostname_match = RELAY_HOSTNAME_PATTERN.fullmatch(hostname or "")
    interface = endpoint.get("tunnel_interface") if state == "connected" else None
    if not isinstance(interface, str) or not INTERFACE_PATTERN.fullmatch(interface):
        interface = None
    country = _safe_label(location.get("country")) if active else None
    city = _safe_label(location.get("city")) if active else None
    external_ip = location.get("ipv4") if state == "connected" else None
    if external_ip is not None:
        try:
            parsed_external_ip = ipaddress.ip_address(external_ip)
            external_ip = str(parsed_external_ip) if parsed_external_ip.version == 4 else None
        except (TypeError, ValueError):
            external_ip = None

    error_code = None
    if state == "error":
        cause = details.get("cause") if isinstance(details.get("cause"), dict) else {}
        reason = cause.get("reason")
        reason_details = cause.get("details")
        if reason == "auth_failed" and isinstance(reason_details, str):
            error_code = {
                "[EXPIRED_ACCOUNT]": "account_expired",
                "[INVALID_ACCOUNT]": "invalid_account",
                "[TOO_MANY_CONNECTIONS]": "too_many_connections",
            }.get(reason_details.split(" ", 1)[0], "provider_tunnel_error")
        elif reason == "tunnel_parameter_error":
            error_code = "relay_unavailable"
        else:
            error_code = "provider_tunnel_error"
    elif state == "disconnected" and details.get("locked_down") is True:
        error_code = "provider_lockdown_enabled"

    return {
        "state": state,
        "connected": state == "connected",
        "country": country if isinstance(country, str) else None,
        "country_code": hostname_match.group("country").upper() if hostname_match else None,
        "city": city if isinstance(city, str) else None,
        "city_code": hostname_match.group("city") if hostname_match else None,
        "server": hostname,
        "external_ip": external_ip,
        "technology": "WireGuard",
        "tunnel_interface": interface,
        "latency_endpoint": _safe_ip_from_endpoint(endpoint.get("address")),
        "error_code": error_code,
    }


COUNTRY_LINE = re.compile(r"^(?P<name>[^\t].*?) \((?P<code>[a-z]{2})\)$")
CITY_LINE = re.compile(
    r"^\t(?P<name>.+?) \((?P<code>[a-z]{3})\) @ [-0-9.]+\u00b0N, [-0-9.]+\u00b0W$"
)
RELAY_LINE = re.compile(
    r"^\t\t(?P<hostname>[a-z0-9-]+) \((?P<addresses>[^)]+)\) - hosted by .+ \((?:Mullvad-owned|rented)\)$"
)


def parse_relay_list(output: str) -> tuple[list[dict], list[dict]]:
    countries: list[dict] = []
    relays: list[dict] = []
    country: dict | None = None
    city: dict | None = None
    for line in output.splitlines():
        if not line.strip():
            continue
        if match := COUNTRY_LINE.fullmatch(line):
            country_name = _safe_label(match.group("name"))
            if country_name is None:
                country = None
                city = None
                continue
            country = {
                "id": match.group("code").upper(),
                "country_code": match.group("code").upper(),
                "provider_name": country_name,
            }
            countries.append(country)
            city = None
            continue
        if match := CITY_LINE.fullmatch(line):
            if country is None or not CITY_CODE_PATTERN.fullmatch(match.group("code")):
                continue
            city_name = _safe_label(match.group("name"))
            if city_name is None:
                city = None
                continue
            city = {"name": city_name, "code": match.group("code")}
            continue
        if match := RELAY_LINE.fullmatch(line):
            if country is None or city is None:
                continue
            hostname = match.group("hostname")
            hostname_match = RELAY_HOSTNAME_PATTERN.fullmatch(hostname)
            if (
                hostname_match is None
                or hostname_match.group("country").upper() != country["country_code"]
                or hostname_match.group("city") != city["code"]
            ):
                continue
            addresses = [item.strip() for item in match.group("addresses").split(",")]
            station = next(
                (
                    str(address)
                    for value in addresses
                    if (address := _parse_ip(value)) is not None and address.version == 4
                ),
                None,
            )
            if station:
                relays.append(
                    {
                        "id": hostname,
                        "hostname": hostname,
                        "station": station,
                        "country_code": country["country_code"],
                        "city": city["name"],
                        "city_code": city["code"],
                    }
                )
    return countries, relays


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _parse_systemd_properties(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


INSTALL_UNIT = "exitlane-provider-install-mullvad.service"
INSTALL_START_TIMEOUT_SECONDS = 10
INSTALL_PHASE_FILE = Path("/run/exitlane-provider-install/mullvad.phase")
INSTALLATION_COMPLETE_MARKER = Path("/etc/exitlane/mullvad-installation-complete")
INSTALL_PHASES = (
    "checking_system",
    "preparing_repository",
    "verifying_repository",
    "refreshing_packages",
    "installing_client",
    "starting_daemon",
    "waiting_for_provider",
    "applying_gateway_settings",
    "validating_installation",
)
INSTALL_RESPONSE_PHASES = frozenset((*INSTALL_PHASES, "completed", "failed"))
INSTALL_ERROR_CODES = frozenset(
    {
        "unsupported_platform",
        "helper_timeout",
        "repository_failed",
        "client_install_failed",
        "provider_daemon_failed",
        "provider_installation_validation_failed",
        "provider_readiness_timeout",
        "gateway_settings_failed",
        "provider_service_suppression_failed",
        "provider_firewall_unsafe",
        "management_connectivity_unavailable",
        "installation_start_failed",
        "installation_failed",
        "insufficient_privileges",
        "package_operation_in_progress",
    }
)
INSTALL_HELPER_ERROR_MAP = {
    "repository_download_failed": "repository_failed",
    "repository_verification_failed": "repository_failed",
    "repository_setup_failed": "repository_failed",
    "package_index_failed": "repository_failed",
    "client_install_failed": "client_install_failed",
    "provider_daemon_failed": "provider_daemon_failed",
    "provider_installation_validation_failed": "provider_installation_validation_failed",
    "provider_readiness_timeout": "provider_readiness_timeout",
    "provider_service_suppression_failed": "provider_service_suppression_failed",
    "provider_firewall_unsafe": "provider_firewall_unsafe",
    "management_connectivity_unavailable": "management_connectivity_unavailable",
    "unsupported_platform": "unsupported_platform",
    "insufficient_privileges": "insufficient_privileges",
    "package_operation_in_progress": "package_operation_in_progress",
}
GATEWAY_SETTINGS = (
    ("auto_connect", ("auto-connect", "get"), "Autoconnect: off", ("auto-connect", "set", "off")),
    ("lan", ("lan", "get"), "Local network sharing setting: allow", ("lan", "set", "allow")),
    (
        "lockdown_mode",
        ("lockdown-mode", "get"),
        "Block traffic when the VPN is disconnected: off",
        ("lockdown-mode", "set", "off"),
    ),
    ("ipv6", ("tunnel", "get"), "IPv6: off", ("tunnel", "set", "ipv6", "off")),
    ("split_tunnel", ("split-tunnel", "list"), "Excluded PIDs:", ("split-tunnel", "clear")),
)

_installation_starting = False
_installation_started_at: str | None = None
_gateway_defaults_task: asyncio.Task | None = None
_installation_monitor_task: asyncio.Task | None = None
_installation_status_lock: asyncio.Lock | None = None
_relay_catalog_cache: tuple[list[dict], list[dict]] = ([], [])
_relay_catalog_updated_at = 0.0


def _supports_managed_installation() -> bool:
    try:
        values = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
        return (
            values.get("ID") == "debian"
            and values.get("VERSION_ID") == "13"
            and os.uname().machine in {"x86_64", "amd64"}
        )
    except OSError:
        return False


def _installation_started_timestamp() -> str:
    global _installation_started_at
    if _installation_started_at is None:
        try:
            _installation_started_at = datetime.fromtimestamp(
                INSTALL_PHASE_FILE.stat().st_mtime, UTC
            ).isoformat()
        except OSError:
            _installation_started_at = datetime.now(UTC).isoformat()
    return _installation_started_at


def _read_installation_phase() -> tuple[str | None, str | None, str | None]:
    try:
        value = INSTALL_PHASE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None, None, None
    if value in INSTALL_RESPONSE_PHASES:
        return value, None, None
    fields = value.split("|")
    if len(fields) == 3 and fields[0] == "failed" and fields[1] in INSTALL_PHASES:
        error_code = INSTALL_HELPER_ERROR_MAP.get(fields[2], fields[2])
        if error_code not in INSTALL_ERROR_CODES:
            error_code = "installation_failed"
        return "failed", fields[1], error_code
    return None, None, None


def _installation_error_code(unit: dict[str, str]) -> str:
    if unit.get("Result") == "timeout":
        return "helper_timeout"
    return {
        "64": "unsupported_platform",
        "65": "repository_failed",
        "66": "client_install_failed",
        "67": "provider_daemon_failed",
        "68": "provider_installation_validation_failed",
        "69": "provider_readiness_timeout",
        "70": "provider_service_suppression_failed",
        "71": "provider_firewall_unsafe",
        "72": "management_connectivity_unavailable",
        "77": "insufficient_privileges",
        "75": "package_operation_in_progress",
    }.get(unit.get("ExecMainStatus", ""), "installation_failed")


def _installation_response(
    *,
    phase: str,
    error_code: str | None = None,
    failed_phase: str | None = None,
    provider_available: bool = False,
) -> dict:
    safe_phase = phase if phase in INSTALL_RESPONSE_PHASES else "failed"
    safe_error = error_code if error_code in INSTALL_ERROR_CODES else (
        "installation_failed" if error_code else None
    )
    active_phase = failed_phase if safe_phase == "failed" else safe_phase
    active_index = INSTALL_PHASES.index(active_phase) if active_phase in INSTALL_PHASES else len(
        INSTALL_PHASES
    )
    steps = []
    for index, step_phase in enumerate(INSTALL_PHASES):
        if safe_phase == "completed":
            status = "completed"
        elif safe_phase == "failed" and index == active_index:
            status = "failed"
        elif index < active_index:
            status = "completed"
        elif index == active_index:
            status = "active"
        else:
            status = "pending"
        steps.append(
            {
                "phase": step_phase,
                "status": status,
                "error_code": safe_error if status == "failed" else None,
            }
        )
    retry_action = None
    if safe_phase == "failed":
        retry_action = (
            "reapply_gateway_settings"
            if active_phase == "applying_gateway_settings"
            else "recheck_provider"
            if active_phase in {"starting_daemon", "waiting_for_provider"}
            else "revalidate_installation"
            if active_phase == "validating_installation"
            else "restart_installation"
        )
    return {
        "state": InstallationState.AVAILABLE
        if safe_phase == "completed"
        else InstallationState.FAILED
        if safe_phase == "failed"
        else InstallationState.INSTALLING,
        "phase": safe_phase,
        "steps": steps,
        "started_at": _installation_started_timestamp(),
        "error_code": safe_error,
        "installation_in_progress": safe_phase not in {"completed", "failed"},
        "provider_available": provider_available,
        "operation_state": {
            "applying_gateway_settings": "configuring_gateway",
            "validating_installation": "validating",
            "completed": "completed",
            "failed": "failed",
        }.get(safe_phase, "installing"),
        "retry_action": retry_action,
    }


class Mullvad(Provider):
    id = "mullvad"
    display_name = "Mullvad VPN"
    authentication_error_codes = AUTHENTICATION_ERROR_CODES
    sign_out_error_codes = SIGN_OUT_ERROR_CODES
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="Mullvad",
        description="Mullvad VPN Linux client",
        icon="shield-check",
        logo="/assets/providers/mullvad.svg",
        authentication_method="account_number",
    )

    def capabilities(
        self,
        *,
        installation_state: str,
        authentication_state: str,
        connection_state: str,
    ) -> dict[str, bool]:
        available = installation_state == InstallationState.AVAILABLE
        authenticated = authentication_state == "signed_in"
        stable_connection = connection_state in {"connected", "disconnected"}
        return {
            "can_sign_in": available and authentication_state == "signed_out",
            "can_sign_out": available and authenticated,
            "can_connect": available and authenticated and connection_state == "disconnected",
            "can_disconnect": available and authenticated and connection_state == "connected",
            "can_reconnect": available and authenticated and stable_connection,
            "can_select_country": available and authenticated and stable_connection,
            "can_select_server": available and authenticated and stable_connection,
            "can_measure_latency": available and authenticated and stable_connection,
            "can_select_location": available and authenticated and stable_connection,
            "can_manage_provider_killswitch": False,
            "can_install": installation_state
            in {
                InstallationState.NOT_INSTALLED,
                InstallationState.DAEMON_MISSING,
                InstallationState.DAEMON_INACTIVE,
            },
        }

    async def _installation_health(self) -> dict:
        if shutil.which("mullvad") is None:
            return {"state": InstallationState.NOT_INSTALLED, "error_code": None}
        load_rc, load_out, _ = await command(
            "systemctl", "show", "mullvad-daemon", "--property=LoadState", "--value", timeout=5
        )
        if load_rc != 0 or load_out.strip() != "loaded":
            return {
                "state": InstallationState.DAEMON_MISSING,
                "error_code": "provider_daemon_failed",
            }
        daemon_rc, _, _ = await command("systemctl", "is-active", "mullvad-daemon", timeout=5)
        if daemon_rc != 0:
            return {
                "state": InstallationState.DAEMON_INACTIVE,
                "error_code": "provider_daemon_failed",
            }
        status_rc, status_out, _ = await command(
            "mullvad", "status", "--json", timeout=5, environment=_provider_cli_environment()
        )
        if status_rc == 0 and parse_status_json(status_out).get("state") != "error":
            return {"state": InstallationState.AVAILABLE, "error_code": None}
        return {
            "state": InstallationState.FAILED,
            "error_code": "provider_installation_validation_failed",
        }

    async def installation_status(self) -> dict:
        global _installation_status_lock
        if _installation_status_lock is None:
            _installation_status_lock = asyncio.Lock()
        async with _installation_status_lock:
            return await self._installation_status_unlocked()

    async def _installation_status_unlocked(self) -> dict:
        global _gateway_defaults_task
        if not _supports_managed_installation():
            response = _installation_response(
                phase="failed", failed_phase="checking_system", error_code="unsupported_platform"
            )
            return {**response, "state": InstallationState.UNSUPPORTED}

        unit_rc, unit_out, _ = await command(
            "systemctl",
            "show",
            INSTALL_UNIT,
            "--property=ActiveState",
            "--property=Result",
            "--property=ExecMainStatus",
            timeout=5,
        )
        unit = _parse_systemd_properties(unit_out) if unit_rc == 0 else {}
        active_state = unit.get("ActiveState", "")
        phase, failed_phase, phase_error = _read_installation_phase()
        health = await self._installation_health()
        provider_available = health["state"] == InstallationState.AVAILABLE

        if _installation_starting or active_state in {"activating", "active"}:
            return _installation_response(
                phase=phase if phase in INSTALL_PHASES else "checking_system",
                provider_available=provider_available,
            )
        if provider_available:
            if phase == "completed" or INSTALLATION_COMPLETE_MARKER.is_file():
                return _installation_response(phase="completed", provider_available=True)
            if phase == "failed" and failed_phase == "applying_gateway_settings":
                results = await self.gateway_settings_status()
                if not results or not all(item["ok"] for item in results):
                    return _installation_response(
                        phase="failed",
                        failed_phase=failed_phase,
                        error_code=phase_error or "gateway_settings_failed",
                        provider_available=True,
                    )
                self._write_phase("validating_installation")
                return _installation_response(
                    phase="validating_installation", provider_available=True
                )
            if phase == "validating_installation":
                results = await self.gateway_settings_status()
                if not results or not all(item["ok"] for item in results):
                    self._write_phase(
                        "failed|applying_gateway_settings|gateway_settings_failed"
                    )
                    return _installation_response(
                        phase="failed",
                        failed_phase="applying_gateway_settings",
                        error_code="gateway_settings_failed",
                        provider_available=True,
                    )
                self._write_phase("completed")
                return _installation_response(phase="completed", provider_available=True)
            if _gateway_defaults_task is None:
                self._write_phase("applying_gateway_settings")
                _gateway_defaults_task = asyncio.create_task(self.defaults())
                return _installation_response(
                    phase="applying_gateway_settings", provider_available=True
                )
            if not _gateway_defaults_task.done():
                return _installation_response(
                    phase="applying_gateway_settings", provider_available=True
                )
            try:
                results = _gateway_defaults_task.result()
            except Exception:  # noqa: BLE001 - only a stable code crosses this boundary.
                results = []
            _gateway_defaults_task = None
            if not results or not all(item["ok"] for item in results):
                self._write_phase("failed|applying_gateway_settings|gateway_settings_failed")
                return _installation_response(
                    phase="failed",
                    failed_phase="applying_gateway_settings",
                    error_code="gateway_settings_failed",
                    provider_available=True,
                )
            if (await self._installation_health())["state"] != InstallationState.AVAILABLE:
                return _installation_response(
                    phase="failed",
                    failed_phase="validating_installation",
                    error_code="provider_installation_validation_failed",
                )
            self._write_phase("validating_installation")
            return _installation_response(phase="validating_installation", provider_available=True)

        if phase == "failed":
            return _installation_response(
                phase="failed",
                failed_phase=failed_phase,
                error_code=phase_error or _installation_error_code(unit),
            )
        if active_state == "failed":
            return _installation_response(
                phase="failed",
                failed_phase=phase if phase in INSTALL_PHASES else "installing_client",
                error_code=_installation_error_code(unit),
            )
        response = _installation_response(phase="checking_system")
        return {
            **response,
            "state": health["state"],
            "installation_in_progress": False,
            "operation_state": "not_started",
            "error_code": health["error_code"],
        }

    @staticmethod
    def _write_phase(value: str) -> None:
        try:
            INSTALL_PHASE_FILE.write_text(f"{value}\n", encoding="utf-8")
        except OSError:
            logger.warning("Could not persist Mullvad installation phase")

    async def start_installation(self) -> dict:
        global _gateway_defaults_task, _installation_monitor_task
        global _installation_started_at, _installation_starting
        status = await self.installation_status()
        if status["state"] == InstallationState.UNSUPPORTED:
            return {"ok": False, "error_code": "unsupported_platform"}
        if status["state"] == InstallationState.INSTALLING or _installation_starting:
            return {"ok": False, "error_code": "installation_in_progress"}

        _installation_starting = True
        _installation_started_at = datetime.now(UTC).isoformat()
        retry_action = status.get("retry_action")
        try:
            if retry_action == "reapply_gateway_settings" and status.get("provider_available"):
                self._write_phase("applying_gateway_settings")
                _gateway_defaults_task = asyncio.create_task(self.defaults())
                return_code = 0
            elif retry_action == "revalidate_installation" and status.get("provider_available"):
                self._write_phase("validating_installation")
                return_code = 0
            else:
                with suppress(OSError):
                    INSTALL_PHASE_FILE.unlink(missing_ok=True)
                await command(
                    "systemctl", "reset-failed", INSTALL_UNIT, timeout=INSTALL_START_TIMEOUT_SECONDS
                )
                return_code, _, _ = await command(
                    "systemctl",
                    "start",
                    "--no-block",
                    INSTALL_UNIT,
                    timeout=INSTALL_START_TIMEOUT_SECONDS,
                )
        finally:
            _installation_starting = False
        if return_code == 124:
            return {"ok": False, "error_code": "helper_timeout"}
        if return_code != 0:
            return {"ok": False, "error_code": "installation_start_failed"}
        if _installation_monitor_task is None or _installation_monitor_task.done():
            _installation_monitor_task = asyncio.create_task(self._monitor_installation())
        initial_phase = {
            "reapply_gateway_settings": "applying_gateway_settings",
            "revalidate_installation": "validating_installation",
        }.get(retry_action, "checking_system")
        return {
            "ok": True,
            **_installation_response(
                phase=initial_phase,
                provider_available=bool(status.get("provider_available")),
            ),
        }

    async def _monitor_installation(self) -> None:
        for _ in range(360):
            await asyncio.sleep(1)
            if not (await self.installation_status())["installation_in_progress"]:
                return
        logger.warning("Mullvad installation monitor reached its bounded deadline")

    async def authenticate(self, credential: str) -> dict:
        account_number = normalize_account_number(credential)
        if account_number is None:
            return {"ok": False, "error": "invalid_account_format"}
        gateway = await self.prepare_authentication()
        if not gateway.get("ok"):
            logger.warning("Mullvad gateway defaults were not ready before authentication")
            return {"ok": False, "error": "provider_error"}
        output = bytearray()
        try:
            return_code, output = await _run_sensitive_cli(
                "account",
                "login",
                input_value=account_number,
                timeout=LOGIN_TIMEOUT_SECONDS,
            )
            error = classify_login_failure(return_code, output)
            if error:
                logger.warning("Mullvad account authentication failed: %s", error)
                return {"ok": False, "error": error}
            output[:] = b"\0" * len(output)
            gateway = await self.prepare_activation()
            if not gateway.get("ok"):
                logout_output = bytearray()
                try:
                    _, logout_output = await _run_sensitive_cli(
                        "account", "logout", timeout=SIGN_OUT_TIMEOUT_SECONDS
                    )
                finally:
                    logout_output[:] = b"\0" * len(logout_output)
                logger.warning("Mullvad post-authentication gateway defaults were not ready")
                return {"ok": False, "error": "provider_error"}
            return {"ok": True, "error": None}
        finally:
            output[:] = b"\0" * len(output)
            account_number = ""

    async def _authentication_state(self) -> tuple[str, str | None]:
        output = bytearray()
        try:
            return_code, output = await _run_sensitive_cli(
                "account", "get", timeout=STATUS_TIMEOUT_SECONDS
            )
            lowered = bytearray(output)
            _ascii_lower_in_place(lowered)
            try:
                if return_code == 124:
                    return "unknown", "timeout"
                if return_code == 127:
                    return "unavailable", "command_unavailable"
                if b"not logged in on any account" in lowered:
                    return "signed_out", None
                if b"current device has been revoked" in lowered:
                    return "signed_out", "device_revoked"
                if return_code == 0 and b"mullvad account:" in lowered:
                    return "signed_in", None
                if b"management rpc" in lowered or b"connect to mullvad daemon" in lowered:
                    return "unavailable", "daemon_unavailable"
                return "unknown", "provider_status_unavailable"
            finally:
                lowered[:] = b"\0" * len(lowered)
        finally:
            output[:] = b"\0" * len(output)

    async def sign_out(self) -> dict:
        output = bytearray()
        try:
            return_code, output = await _run_sensitive_cli(
                "account", "logout", timeout=SIGN_OUT_TIMEOUT_SECONDS
            )
            error = classify_sign_out_failure(return_code, output)
            return {
                "ok": error is None or error == "already_signed_out",
                "error": error,
                "already_signed_out": error == "already_signed_out",
            }
        finally:
            output[:] = b"\0" * len(output)

    async def status(self, *, timeout: float = STATUS_TIMEOUT_SECONDS) -> dict:
        if shutil.which("mullvad") is None:
            error_code = (
                "unsupported_container_runtime"
                if Path("/.dockerenv").exists()
                else "provider_cli_unavailable"
            )
            return {
                "installed": False,
                "available": False,
                "daemon_active": False,
                "authenticated": False,
                "connected": False,
                "state": "unavailable",
                "error_code": error_code,
                "management": self.management_status(
                    installation_state=(await self.installation_status())["state"],
                    authentication_state="unavailable",
                    connection_state="unknown",
                    error_code=error_code,
                ),
            }

        daemon_rc, _, _ = await command(
            "systemctl", "is-active", "mullvad-daemon", timeout=timeout
        )
        daemon_active = daemon_rc == 0
        if daemon_active:
            authentication_state, authentication_error = await self._authentication_state()
            status_rc, status_out, _ = await command(
                "mullvad",
                "status",
                "--json",
                timeout=timeout,
                environment=_provider_cli_environment(),
            )
            parsed = parse_status_json(status_out) if status_rc == 0 else {
                "state": "error",
                "connected": False,
                "error_code": "timeout" if status_rc == 124 else "provider_status_unavailable",
            }
        else:
            authentication_state = "unavailable"
            authentication_error = "timeout" if daemon_rc == 124 else "daemon_unavailable"
            parsed = {"state": "error", "connected": False, "error_code": authentication_error}

        connection_state = str(parsed.get("state", "error"))
        status_error = authentication_error or parsed.get("error_code")
        available = daemon_active and authentication_error in {None, "device_revoked"} and (
            parsed.get("error_code") != "provider_status_unavailable"
        )
        installation_state = (
            InstallationState.AVAILABLE
            if available
            else InstallationState.DAEMON_INACTIVE
            if not daemon_active
            else InstallationState.FAILED
        )
        return {
            "installed": True,
            "available": available,
            "daemon_active": daemon_active,
            "authenticated": authentication_state == "signed_in",
            **parsed,
            "error_code": status_error,
            "management": self.management_status(
                installation_state=installation_state,
                authentication_state=authentication_state,
                connection_state=connection_state,
                error_code=status_error,
            ),
        }

    async def _relay_catalog(self) -> tuple[list[dict], list[dict]]:
        global _relay_catalog_cache, _relay_catalog_updated_at
        now = time.monotonic()
        if _relay_catalog_cache[0] and now - _relay_catalog_updated_at < 300:
            return (
                [dict(item) for item in _relay_catalog_cache[0]],
                [dict(item) for item in _relay_catalog_cache[1]],
            )
        await command(
            "mullvad", "relay", "update", timeout=10, environment=_provider_cli_environment()
        )
        return_code, output, _ = await command(
            "mullvad", "relay", "list", timeout=10, environment=_provider_cli_environment()
        )
        if return_code == 0:
            countries, relays = parse_relay_list(output)
            if countries and relays:
                _relay_catalog_cache = (countries, relays)
                _relay_catalog_updated_at = now
        return (
            [dict(item) for item in _relay_catalog_cache[0]],
            [dict(item) for item in _relay_catalog_cache[1]],
        )

    async def countries(self) -> list[dict]:
        countries, _ = await self._relay_catalog()
        return countries

    async def servers(self, location_id: int | str, *, limit: int = 5) -> list[dict]:
        code = str(location_id).upper()
        if not re.fullmatch(r"[A-Z]{2}", code):
            return []
        _, relays = await self._relay_catalog()
        return [item for item in relays if item["country_code"] == code][:limit]

    async def connect(self, target: str | None = None, *, timeout: float = 40) -> dict:
        if shutil.which("mullvad") is None:
            return {"ok": False, "error_code": "provider_cli_unavailable"}
        if target:
            normalized = target.casefold()
            if not (
                COUNTRY_CODE_PATTERN.fullmatch(normalized)
                or RELAY_HOSTNAME_PATTERN.fullmatch(normalized)
            ):
                return {"ok": False, "error_code": "invalid_target"}
            location_rc, _, _ = await command(
                "mullvad",
                "relay",
                "set",
                "location",
                normalized,
                timeout=10,
                environment=_provider_cli_environment(),
            )
            if location_rc != 0:
                return {
                    "ok": False,
                    "action": "connect",
                    "state": "error",
                    "target": normalized,
                    "error_code": "relay_unavailable",
                }
        return_code, _, error_output = await command(
            "mullvad",
            "connect",
            "--wait",
            timeout=timeout,
            environment=_provider_cli_environment(),
        )
        message = error_output.casefold()
        error_code = (
            None
            if return_code == 0
            else "vpn_connect_timeout"
            if return_code == 124
            else "account_expired"
            if "out of time" in message or "account has expired" in message
            else "provider_connect_failed"
        )
        return {
            "ok": return_code == 0,
            "action": "connect",
            "state": "connecting" if return_code == 0 else "error",
            "target": target,
            "exit_code": return_code,
            "error_code": error_code,
        }

    async def connect_country(
        self,
        country_code: str,
        *,
        server_hostname: str | None = None,
        timeout: float = 40,
    ) -> dict:
        code = country_code.casefold()
        if not COUNTRY_CODE_PATTERN.fullmatch(code):
            return {"ok": False, "error_code": "invalid_target"}
        if server_hostname is not None:
            match = RELAY_HOSTNAME_PATTERN.fullmatch(server_hostname)
            if match is None or match.group("country") != code:
                return {"ok": False, "error_code": "invalid_target"}
        return await self.connect(server_hostname or code, timeout=timeout)

    async def reconnect(self, target: str | None = None, *, timeout: float = 40) -> dict:
        if target:
            return await self.connect(target, timeout=timeout)
        return_code, _, _ = await command(
            "mullvad",
            "reconnect",
            "--wait",
            timeout=timeout,
            environment=_provider_cli_environment(),
        )
        return {
            "ok": return_code == 0,
            "action": "reconnect",
            "error_code": "vpn_connect_timeout"
            if return_code == 124
            else None
            if return_code == 0
            else "provider_connect_failed",
        }

    async def disconnect(self, *, timeout: float = 15) -> dict:
        return_code, _, _ = await command(
            "mullvad",
            "disconnect",
            "--wait",
            timeout=timeout,
            environment=_provider_cli_environment(),
        )
        return {
            "ok": return_code == 0,
            "action": "disconnect",
            "state": "disconnecting" if return_code == 0 else "error",
            "error_code": None
            if return_code == 0
            else "vpn_disconnect_timeout"
            if return_code == 124
            else "provider_disconnect_failed",
        }

    async def gateway_settings_status(self) -> list[dict]:
        return await self._gateway_settings_status(GATEWAY_SETTINGS)

    async def _gateway_settings_status(self, settings: tuple) -> list[dict]:
        results = []
        for name, get_args, expected, _set_args in settings:
            return_code, output, _ = await command(
                "mullvad", *get_args, timeout=8, environment=_provider_cli_environment()
            )
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            ok = return_code == 0 and (
                lines == [expected]
                if name == "split_tunnel"
                else any(line == expected for line in lines)
            )
            results.append({"setting": name, "ok": ok})
        return results

    async def _apply_gateway_settings(self, settings: tuple) -> list[dict]:
        current = {
            result["setting"]: result["ok"]
            for result in await self._gateway_settings_status(settings)
        }
        for name, _get_args, _expected, set_args in settings:
            if not current.get(name, False):
                await command(
                    "mullvad", *set_args, timeout=10, environment=_provider_cli_environment()
                )
        return await self._gateway_settings_status(settings)

    async def defaults(self) -> list[dict]:
        return await self._apply_gateway_settings(GATEWAY_SETTINGS)

    async def prepare_authentication(self) -> dict:
        results = await self._apply_gateway_settings(GATEWAY_SETTINGS[:3])
        return_code, output, _ = await command(
            "mullvad",
            "status",
            "--json",
            timeout=8,
            environment=_provider_cli_environment(),
        )
        disconnected = return_code == 0 and parse_status_json(output).get("state") == "disconnected"
        if not disconnected:
            await command(
                "mullvad", "disconnect", timeout=10, environment=_provider_cli_environment()
            )
            return_code, output, _ = await command(
                "mullvad",
                "status",
                "--json",
                timeout=8,
                environment=_provider_cli_environment(),
            )
            disconnected = (
                return_code == 0 and parse_status_json(output).get("state") == "disconnected"
            )
        ready = bool(results) and all(item.get("ok") is True for item in results) and disconnected
        return {
            "ok": ready,
            "error_code": None if ready else "gateway_settings_failed",
        }

    async def prepare_activation(self) -> dict:
        results = await self.defaults()
        ready = bool(results) and all(item.get("ok") is True for item in results)
        return {
            "ok": ready,
            "error_code": None if ready else "gateway_settings_failed",
        }

    async def network_facts(self) -> TunnelFacts:
        current = await self.status()
        connected = bool(current.get("connected"))
        interface = current.get("tunnel_interface")
        valid_interface = isinstance(interface, str) and INTERFACE_PATTERN.fullmatch(interface)
        available = connected and bool(valid_interface)
        return TunnelFacts(
            available=available,
            interface=interface if available else None,
            supports_ipv4=connected,
            supports_ipv6=False,
            protected_egress=available,
            reason=(
                "tunnel_available"
                if available
                else "tunnel_unavailable"
                if not connected
                else "tunnel_interface_unknown"
            ),
        )


provider = Mullvad()
