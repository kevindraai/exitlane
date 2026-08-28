from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import re
import shutil
import termios
import time
import urllib.parse
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from exitlane.core import command

from .base import InstallationState, Provider, ProviderMetadata

logger = logging.getLogger(__name__)
SERVER_HOSTNAME_PATTERN = re.compile(r"^([a-z]{2}[0-9]+)\.nordvpn\.com$")
CONNECT_FAILURE_TIMEOUT_SECONDS = 25
TOKEN_LOGIN_TIMEOUT_SECONDS = 30
SIGN_OUT_TIMEOUT_SECONDS = 15
TOKEN_ERROR_CODES = frozenset(
    {
        "already_logged_in",
        "invalid_token_format",
        "invalid_token",
        "token_expired",
        "token_revoked",
        "timeout",
        "daemon_unavailable",
        "command_unavailable",
        "token_replacement_unsupported",
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
    """Return the minimal non-secret environment needed by the installed CLI."""
    allowed = ("HOME", "LANG", "LC_ALL", "PATH", "XDG_RUNTIME_DIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}


async def _login_token_via_pty(
    token: str,
    *,
    executable: str = "nordvpn",
    timeout: int = TOKEN_LOGIN_TIMEOUT_SECONDS,
    output_sink: bytearray | None = None,
) -> int:
    """Enter a token only after the provider terminal has disabled input echo."""
    master, slave = os.openpty()
    process = None
    try:
        try:
            process = await asyncio.create_subprocess_exec(
                executable,
                "login",
                "--token",
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=_provider_cli_environment(),
            )
        except FileNotFoundError:
            return 127
        finally:
            os.close(slave)

        os.set_blocking(master, False)
        prompt = bytearray()
        consent_answered = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = os.read(master, 1024)
            except BlockingIOError:
                chunk = b""
            except OSError:
                break
            if chunk:
                prompt.extend(chunk)
                if output_sink is not None:
                    output_sink.extend(chunk)
                    if len(output_sink) > 4096:
                        del output_sink[:-4096]
                if len(prompt) > 4096:
                    del prompt[:-4096]
            try:
                echo_disabled = not termios.tcgetattr(master)[3] & termios.ECHO
            except OSError:
                echo_disabled = False
            if (
                not consent_answered
                and b"Do you allow us to collect and use limited app performance data? (y/n)"
                in prompt
            ):
                os.write(master, b"n\n")
                consent_answered = True
                prompt.clear()
                await asyncio.sleep(0.01)
                continue
            if b"Enter access token:" in prompt and echo_disabled:
                encoded = bytearray(token.encode())
                try:
                    os.write(master, encoded)
                    os.write(master, b"\n")
                finally:
                    encoded[:] = b"\0" * len(encoded)
                break
            if process.returncode is not None:
                return process.returncode
            await asyncio.sleep(0.01)
        else:
            process.kill()
            await process.wait()
            return 124

        remaining = max(deadline - time.monotonic(), 0.01)
        try:
            return await asyncio.wait_for(process.wait(), remaining)
        except TimeoutError:
            process.kill()
            await process.wait()
            return 124
    except asyncio.CancelledError:
        if process and process.returncode is None:
            process.kill()
            await process.wait()
        raise
    finally:
        with suppress(OSError):
            os.close(master)


def classify_token_login_failure(return_code: int, output: str, error: str) -> str:
    """Classify known CLI failures without returning uncontrolled provider text."""
    if return_code == 124:
        return "timeout"
    if return_code == 127:
        return "command_unavailable"
    message = f"{output}\n{error}".casefold()
    if any(marker in message for marker in ("token has expired", "expired token")):
        return "token_expired"
    if any(marker in message for marker in ("token has been revoked", "revoked token")):
        return "token_revoked"
    if any(
        marker in message
        for marker in ("already logged in", "already logged-in", "already signed in")
    ):
        return "already_logged_in"
    if any(
        marker in message
        for marker in (
            "invalid token",
            "token is invalid",
            "access token is not valid",
            "incorrect token",
        )
    ):
        return "invalid_token"
    if any(
        marker in message
        for marker in (
            "daemon is not running",
            "daemon not running",
            "cannot reach daemon",
            "can't connect to nordvpn daemon",
            "nordvpnd",
        )
    ):
        return "daemon_unavailable"
    if any(
        marker in message
        for marker in (
            "log out first",
            "logout first",
            "cannot login while",
            "can't login while",
        )
    ):
        return "token_replacement_unsupported"
    return "provider_error"


def classify_sign_out_failure(return_code: int, output: str, error: str) -> str:
    """Classify logout failures without exposing provider-controlled output."""
    if return_code == 124:
        return "timeout"
    if return_code == 127:
        return "command_unavailable"
    message = f"{output}\n{error}".casefold()
    if any(
        marker in message
        for marker in ("not logged in", "not signed in", "already logged out", "already signed out")
    ):
        return "already_signed_out"
    if any(
        marker in message
        for marker in (
            "daemon is not running",
            "daemon not running",
            "cannot reach daemon",
            "can't connect to nordvpn daemon",
            "nordvpnd",
        )
    ):
        return "daemon_unavailable"
    return "provider_error"


def _connect_timed_out(return_code: int, output: str, error: str, elapsed: float) -> bool:
    provider_message = f"{output}\n{error}".casefold()
    return (
        return_code == 124
        or "context deadline exceeded" in provider_message
        or (return_code != 0 and elapsed >= CONNECT_FAILURE_TIMEOUT_SECONDS)
    )


def build_connect_target(country_code: str, server_hostname: str | None = None) -> str:
    """Build a native NordVPN CLI target, never an arbitrary hostname or argument."""
    if not re.fullmatch(r"[A-Za-z]{2}", country_code):
        raise ValueError("invalid country code")
    if server_hostname is None:
        return country_code.lower()
    match = SERVER_HOSTNAME_PATTERN.fullmatch(server_hostname)
    if not match:
        raise ValueError("invalid NordVPN server hostname")
    return match.group(1)


def parse(output: str) -> dict[str, str]:
    result: dict[str, str] = {}

    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()

    return result


def _parse_systemd_properties(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


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
        "77": "insufficient_privileges",
        "75": "package_operation_in_progress",
    }.get(unit.get("ExecMainStatus", ""), "installation_failed")


_country_catalog_cache: list[dict] = []
INSTALL_UNIT = "exitlane-provider-install-nordvpn.service"
INSTALL_START_TIMEOUT_SECONDS = 10
INSTALL_PHASE_FILE = Path("/run/exitlane-provider-install/nordvpn.phase")
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
    "unsupported_platform": "unsupported_platform",
    "insufficient_privileges": "insufficient_privileges",
    "package_operation_in_progress": "package_operation_in_progress",
}
GATEWAY_SETTINGS = (
    ("technology", "NordLynx", "Technology", "nordlynx"),
    ("routing", "on", "Routing", "enabled"),
    ("lan-discovery", "on", "LAN Discovery", "enabled"),
    ("firewall", "on", "Firewall", "enabled"),
    ("killswitch", "off", "Kill Switch", "disabled"),
    ("analytics", "off", "User Consent", "disabled"),
    ("autoconnect", "off", "Auto-connect", "disabled"),
)
_installation_starting = False
_installation_started_at: str | None = None
_gateway_defaults_task: asyncio.Task | None = None
_installation_monitor_task: asyncio.Task | None = None
_installation_status_lock: asyncio.Lock | None = None


def _installation_started_timestamp() -> str:
    global _installation_started_at
    if _installation_started_at is None:
        try:
            timestamp = INSTALL_PHASE_FILE.stat().st_mtime
            _installation_started_at = datetime.fromtimestamp(timestamp, UTC).isoformat()
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


def _installation_response(
    *,
    phase: str,
    error_code: str | None = None,
    failed_phase: str | None = None,
    provider_available: bool = False,
) -> dict:
    safe_phase = phase if phase in INSTALL_RESPONSE_PHASES else "failed"
    safe_error = (
        error_code
        if error_code in INSTALL_ERROR_CODES
        else ("installation_failed" if error_code else None)
    )
    active_phase = failed_phase if safe_phase == "failed" else safe_phase
    active_index = (
        INSTALL_PHASES.index(active_phase)
        if active_phase in INSTALL_PHASES
        else len(INSTALL_PHASES)
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
    operation_state = {
        "applying_gateway_settings": "configuring_gateway",
        "validating_installation": "validating",
        "completed": "completed",
        "failed": "failed",
    }.get(safe_phase, "installing")
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
        "state": (
            InstallationState.AVAILABLE
            if safe_phase == "completed"
            else InstallationState.FAILED
            if safe_phase == "failed"
            else InstallationState.INSTALLING
        ),
        "phase": safe_phase,
        "steps": steps,
        "started_at": _installation_started_timestamp(),
        "error_code": safe_error,
        "installation_in_progress": safe_phase not in {"completed", "failed"},
        "provider_available": provider_available,
        "operation_state": operation_state,
        "retry_action": retry_action,
    }


def _supports_managed_installation() -> bool:
    try:
        values = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
        return values.get("ID") == "debian" and values.get("VERSION_ID") == "13"
    except OSError:
        return False


class NordVPN(Provider):
    id = "nordvpn"
    display_name = "NordVPN"
    authentication_error_codes = TOKEN_ERROR_CODES
    sign_out_error_codes = SIGN_OUT_ERROR_CODES
    supports_timeout_recovery = True
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="NordVPN",
        description="NordVPN Linux client",
        icon="shield-check",
        logo="/assets/providers/nordvpn.svg",
    )

    def capabilities(
        self,
        *,
        installation_state: str,
        authentication_state: str,
        connection_state: str,
    ) -> dict[str, bool]:
        available = installation_state == InstallationState.AVAILABLE
        return {
            "can_sign_in": available and authentication_state == "signed_out",
            "can_sign_out": available and authentication_state == "signed_in",
            "can_connect": (
                available
                and authentication_state == "signed_in"
                and connection_state == "disconnected"
            ),
            "can_disconnect": (
                available
                and authentication_state == "signed_in"
                and connection_state == "connected"
            ),
            "can_reconnect": (
                available
                and authentication_state == "signed_in"
                and connection_state in {"connected", "disconnected"}
            ),
            "can_select_country": (
                available
                and authentication_state == "signed_in"
                and connection_state in {"connected", "disconnected"}
            ),
            "can_select_server": False,
            "can_measure_latency": (
                available
                and authentication_state == "signed_in"
                and connection_state in {"connected", "disconnected"}
            ),
            "can_select_location": (
                available
                and authentication_state == "signed_in"
                and connection_state in {"connected", "disconnected"}
            ),
            # Deliberately reserved for a later security/networking design.
            "can_manage_provider_killswitch": False,
            "can_install": installation_state
            in {
                InstallationState.NOT_INSTALLED,
                InstallationState.DAEMON_MISSING,
                InstallationState.DAEMON_INACTIVE,
            },
        }

    async def _installation_health(self) -> dict:
        installed = shutil.which("nordvpn") is not None
        if not installed:
            return {
                "state": InstallationState.NOT_INSTALLED,
                "error_code": None,
            }
        load_rc, load_out, _ = await command(
            "systemctl",
            "show",
            "nordvpnd",
            "--property=LoadState",
            "--value",
            timeout=5,
        )
        if load_rc != 0 or load_out.strip() != "loaded":
            return {
                "state": InstallationState.DAEMON_MISSING,
                "error_code": "provider_daemon_failed",
            }
        daemon_rc, _, _ = await command("systemctl", "is-active", "nordvpnd", timeout=5)
        if daemon_rc != 0:
            return {
                "state": InstallationState.DAEMON_INACTIVE,
                "error_code": "provider_daemon_failed",
            }
        provider_rc, provider_out, provider_err = await command("nordvpn", "status", timeout=5)
        provider_output = f"{provider_out}\n{provider_err}".casefold()
        if provider_rc == 0 or any(
            marker in provider_output for marker in ("not logged in", "not signed in")
        ):
            return {
                "state": InstallationState.AVAILABLE,
                "error_code": None,
            }
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
                phase="failed",
                failed_phase="checking_system",
                error_code="unsupported_platform",
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
            current = phase if phase in INSTALL_PHASES else "checking_system"
            return _installation_response(
                phase=current,
                provider_available=provider_available,
            )

        if provider_available:
            if phase == "failed" and failed_phase == "applying_gateway_settings":
                gateway_results = await self.gateway_settings_status()
                if not gateway_results or not all(
                    result.get("ok", False) for result in gateway_results
                ):
                    return _installation_response(
                        phase="failed",
                        failed_phase=failed_phase,
                        error_code=phase_error or "gateway_settings_failed",
                        provider_available=True,
                    )
                try:
                    INSTALL_PHASE_FILE.write_text("validating_installation\n", encoding="utf-8")
                except OSError:
                    logger.warning("Could not persist reconciled installation phase")
                return _installation_response(
                    phase="validating_installation",
                    provider_available=True,
                )
            if phase == "completed":
                return _installation_response(
                    phase="completed",
                    provider_available=True,
                )
            if phase == "validating_installation":
                try:
                    INSTALL_PHASE_FILE.write_text("completed\n", encoding="utf-8")
                except OSError:
                    logger.warning("Could not persist completed provider installation phase")
                return _installation_response(
                    phase="completed",
                    provider_available=True,
                )
            if _gateway_defaults_task is None:
                try:
                    INSTALL_PHASE_FILE.write_text(
                        "applying_gateway_settings\n",
                        encoding="utf-8",
                    )
                except OSError:
                    logger.warning("Could not persist the provider installation phase")
                _gateway_defaults_task = asyncio.create_task(self.defaults())
                return _installation_response(
                    phase="applying_gateway_settings",
                    provider_available=True,
                )
            if not _gateway_defaults_task.done():
                return _installation_response(
                    phase="applying_gateway_settings",
                    provider_available=True,
                )
            try:
                gateway_results = _gateway_defaults_task.result()
            except Exception:  # noqa: BLE001 - provider boundary emits only a stable code.
                gateway_results = []
            _gateway_defaults_task = None
            if not gateway_results or not all(
                result.get("ok", False) for result in gateway_results
            ):
                try:
                    INSTALL_PHASE_FILE.write_text(
                        "failed|applying_gateway_settings|gateway_settings_failed\n",
                        encoding="utf-8",
                    )
                except OSError:
                    logger.warning("Could not persist failed gateway configuration phase")
                return _installation_response(
                    phase="failed",
                    failed_phase="applying_gateway_settings",
                    error_code="gateway_settings_failed",
                    provider_available=True,
                )
            final_health = await self._installation_health()
            if final_health["state"] != InstallationState.AVAILABLE:
                return _installation_response(
                    phase="failed",
                    failed_phase="validating_installation",
                    error_code="provider_installation_validation_failed",
                )
            try:
                INSTALL_PHASE_FILE.write_text(
                    "validating_installation\n",
                    encoding="utf-8",
                )
            except OSError:
                logger.warning("Could not persist final provider validation phase")
            return _installation_response(
                phase="validating_installation",
                provider_available=True,
            )

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
        try:
            retry_action = status.get("retry_action")
            if retry_action == "reapply_gateway_settings" and status.get("provider_available"):
                INSTALL_PHASE_FILE.write_text("applying_gateway_settings\n", encoding="utf-8")
                _gateway_defaults_task = asyncio.create_task(self.defaults())
                return_code = 0
            elif retry_action == "revalidate_installation" and status.get("provider_available"):
                INSTALL_PHASE_FILE.write_text("validating_installation\n", encoding="utf-8")
                return_code = 0
            elif retry_action == "recheck_provider" and shutil.which("nordvpn"):
                INSTALL_PHASE_FILE.write_text("waiting_for_provider\n", encoding="utf-8")
                return_code, _, _ = await command(
                    "systemctl",
                    "enable",
                    "--now",
                    "nordvpnd",
                    timeout=INSTALL_START_TIMEOUT_SECONDS,
                )
            else:
                try:
                    INSTALL_PHASE_FILE.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not reset the provider installation phase")
                await command(
                    "systemctl",
                    "reset-failed",
                    INSTALL_UNIT,
                    timeout=INSTALL_START_TIMEOUT_SECONDS,
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
        return {
            "ok": True,
            **_installation_response(
                phase=(
                    "applying_gateway_settings"
                    if retry_action == "reapply_gateway_settings"
                    else "validating_installation"
                    if retry_action == "revalidate_installation"
                    else "waiting_for_provider"
                    if retry_action == "recheck_provider"
                    else "checking_system"
                ),
                provider_available=bool(status.get("provider_available")),
            ),
        }

    async def _monitor_installation(self) -> None:
        for _ in range(360):
            await asyncio.sleep(1)
            status = await self.installation_status()
            if not status["installation_in_progress"]:
                return
        logger.warning("Provider installation monitor reached its bounded deadline")

    async def authenticate(self, credential: str) -> dict:
        return await self.login_token(credential)

    async def network_facts(self):
        from exitlane.services.killswitch import TunnelFacts

        current = await self.status()
        connected = bool(current.get("connected"))
        technology = str(current.get("technology", "")).casefold()
        # Provider-specific interface knowledge is translated here; the generic
        # firewall service never hardcodes NordLynx.
        interface = None
        if connected and "nordlynx" in technology:
            interface = "nordlynx"
        return TunnelFacts(
            available=connected and interface is not None,
            interface=interface,
            supports_ipv4=connected,
            supports_ipv6=False,
            protected_egress=connected and interface is not None,
            reason=(
                "tunnel_available"
                if connected and interface is not None
                else "tunnel_unavailable"
                if not connected
                else "tunnel_interface_unknown"
            ),
        )

    async def status(self, *, timeout: float = 8):
        if not shutil.which("nordvpn"):
            in_container = Path("/.dockerenv").exists()
            error_code = (
                "unsupported_container_runtime" if in_container else "provider_cli_unavailable"
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
            "systemctl",
            "is-active",
            "nordvpnd",
            timeout=timeout,
        )

        status_rc, status_out, status_err = await command(
            "nordvpn",
            "status",
            timeout=timeout,
        )
        values = parse(status_out or status_err)
        account_rc, account_out, account_err = await command(
            "nordvpn",
            "account",
            timeout=timeout,
        )

        account_output = account_out or account_err
        daemon_active = daemon_rc == 0
        account_message = account_output.casefold()

        if daemon_rc == 124:
            authentication_state = "unknown"
            authentication_error = "timeout"
        elif not daemon_active:
            authentication_state = "unavailable"
            authentication_error = "daemon_unavailable"
        elif account_rc == 0 and "not logged in" not in account_message:
            authentication_state = "signed_in"
            authentication_error = None
        elif "not logged in" in account_message or "not signed in" in account_message:
            authentication_state = "signed_out"
            authentication_error = None
        elif account_rc == 124:
            authentication_state = "unknown"
            authentication_error = "timeout"
        elif account_rc == 127:
            authentication_state = "unavailable"
            authentication_error = "command_unavailable"
        else:
            authentication_state = "unknown"
            authentication_error = "provider_status_unavailable"

        raw_connection_state = values.get("Status", "").casefold()
        if raw_connection_state in {
            "connected",
            "disconnected",
            "connecting",
            "disconnecting",
        }:
            connection_state = raw_connection_state
        elif authentication_state == "signed_out":
            connection_state = "disconnected"
        elif not daemon_active:
            connection_state = "error"
        else:
            connection_state = "unknown"
        connected = connection_state == "connected"
        hostname = values.get("Hostname", values.get("Server", ""))
        hostname_match = SERVER_HOSTNAME_PATTERN.fullmatch(hostname.casefold())
        hostname_code = hostname_match.group(1)[:2].upper() if hostname_match else None
        country_code = {"UK": "GB"}.get(hostname_code, hostname_code)
        if authentication_error:
            status_error = authentication_error
        elif status_rc == 124:
            status_error = "timeout"
        elif status_rc == 127:
            status_error = "command_unavailable"
        elif status_rc == 0 or authentication_state == "signed_out":
            status_error = None
        else:
            status_error = "provider_status_unavailable"

        return {
            "installed": True,
            "available": daemon_active and status_error is None,
            "daemon_active": daemon_active,
            "authenticated": authentication_state == "signed_in",
            "connected": connected,
            "state": values.get("Status", "error").lower() if status_rc == 0 else "error",
            "error_code": status_error,
            "country": values.get("Country", ""),
            "country_code": country_code,
            "city": values.get("City", ""),
            "server": hostname,
            "tunnel_interface": "nordlynx" if connected and "nordlynx" in values.get(
                "Current technology", ""
            ).casefold() else None,
            "external_ip": values.get("IP", ""),
            "technology": values.get(
                "Current technology",
                "",
            ),
            "management": self.management_status(
                installation_state=(
                    InstallationState.AVAILABLE
                    if daemon_active and status_error is None
                    else (
                        InstallationState.DAEMON_INACTIVE
                        if not daemon_active
                        else InstallationState.FAILED
                    )
                ),
                authentication_state=authentication_state,
                connection_state=connection_state,
                error_code=status_error,
            ),
        }

    async def login_token(self, token):
        if not re.fullmatch(
            r"[A-Za-z0-9._~-]{20,512}",
            token,
        ):
            return {
                "ok": False,
                "error": "invalid_token_format",
            }

        output = bytearray()
        rc = await _login_token_via_pty(token, output_sink=output)
        message = output.decode(errors="replace")
        error = None if rc == 0 else classify_token_login_failure(rc, message, "")
        output[:] = b"\0" * len(output)
        if error is not None:
            logger.warning("NordVPN token authentication failed: %s", error)

        return {
            "ok": error is None,
            "error": error,
        }

    async def sign_out(self) -> dict:
        rc, out, err = await command(
            "nordvpn",
            "logout",
            timeout=SIGN_OUT_TIMEOUT_SECONDS,
            environment=_provider_cli_environment(),
        )
        error = None if rc == 0 else classify_sign_out_failure(rc, out, err)
        return {
            "ok": rc == 0 or error == "already_signed_out",
            "error": error,
            "already_signed_out": error == "already_signed_out",
        }

    async def login_callback(self, url):
        if not url.startswith(
            ("nordvpn://", "https://"),
        ):
            return {
                "ok": False,
                "message": "invalid callback URL",
            }

        rc, out, err = await command(
            "nordvpn",
            "login",
            "--callback",
            url,
        )

        return {
            "ok": rc == 0,
            "stdout": out,
            "stderr": err,
        }

    @staticmethod
    def _normalise_gateway_value(value: str) -> str:
        normalised = value.strip().casefold()
        return {
            "on": "enabled",
            "true": "enabled",
            "off": "disabled",
            "false": "disabled",
        }.get(normalised, normalised)

    async def gateway_settings_status(self) -> list[dict]:
        settings_rc, settings_out, _ = await command("nordvpn", "settings")
        actual_settings = parse(settings_out) if settings_rc == 0 else {}
        results = [
            {
                "setting": setting,
                "ok": settings_rc == 0
                and self._normalise_gateway_value(actual_settings.get(key, "")) == expected,
            }
            for setting, _value, key, expected in GATEWAY_SETTINGS
        ]
        mismatches = [result["setting"] for result in results if not result["ok"]]
        if mismatches:
            logger.warning(
                "Managed NordVPN gateway settings differ: %s",
                ", ".join(mismatches),
            )
        return results

    async def defaults(self) -> list[dict]:
        current = {
            result["setting"]: result["ok"] for result in await self.gateway_settings_status()
        }
        for setting, value, _key, _expected in GATEWAY_SETTINGS:
            if not current.get(setting, False):
                await command("nordvpn", "set", setting, value)
        return await self.gateway_settings_status()

    async def start_browser_login(self):
        _rc, out, err = await command(
            "nordvpn",
            "login",
            timeout=30,
        )

        output = out or err

        match = re.search(
            r"https://api\.nordvpn\.com/\S+",
            output,
        )

        login_url = match.group(0).rstrip(".,)") if match else None

        return {
            "ok": login_url is not None,
            "login_url": login_url,
            "stdout": out,
            "stderr": err,
            "message": (
                "Open de aanmeldlink in je browser."
                if login_url
                else "NordVPN-aanmeldlink kon niet worden gevonden."
            ),
        }

    async def countries(self):
        global _country_catalog_cache
        data = await self._api_json("/v1/servers/countries")
        countries = sorted(
            (
                {
                    "id": item["id"],
                    "country_code": item["code"].upper(),
                    "provider_name": item["name"],
                }
                for item in data
                if item.get("id") is not None and item.get("code")
            ),
            key=lambda item: item["provider_name"],
        )
        if countries:
            _country_catalog_cache = countries
        return [dict(item) for item in (countries or _country_catalog_cache)]

    async def servers(self, country_id: int, *, limit: int = 5) -> list[dict]:
        query = urllib.parse.urlencode({"filters[country_id]": country_id, "limit": limit})
        data = await self._api_json(f"/v1/servers/recommendations?{query}")
        return [
            {
                "id": item.get("id"),
                "hostname": item.get("hostname"),
                "station": item.get("station"),
                "load": item.get("load"),
            }
            for item in data
            if item.get("hostname")
        ][:limit]

    async def _api_json(self, path: str) -> list[dict]:
        def fetch() -> list[dict]:
            connection = http.client.HTTPSConnection("api.nordvpn.com", timeout=8)
            try:
                connection.request("GET", path, headers={"User-Agent": "ExitLane/0.2"})
                response = connection.getresponse()
                if response.status != 200:
                    return []
                payload = json.loads(response.read())
            finally:
                connection.close()
            return payload if isinstance(payload, list) else []

        try:
            return await asyncio.to_thread(fetch)
        except (OSError, ValueError):
            return []

    async def connect(self, target=None, *, timeout: float = 40):
        if not shutil.which("nordvpn"):
            return {
                "ok": False,
                "action": "connect",
                "state": "error",
                "target": target,
                "error_code": "provider_cli_unavailable",
            }
        args = ["nordvpn", "connect"]

        if target:
            if not re.fullmatch(r"(?:[A-Za-z]{2}|[a-z]{2}[0-9]+)", target):
                return {
                    "ok": False,
                    "action": "connect",
                    "state": "error",
                    "target": target,
                    "error_code": "invalid_target",
                }

            args.append(target.lower())

        started_at = time.monotonic()
        rc, out, err = await command(
            *args,
            timeout=timeout,
        )
        elapsed = time.monotonic() - started_at
        if rc != 0:
            safe_error = re.sub(r"[\r\n\t]+", " ", err).strip()[:300]
            logger.warning("NordVPN connect failed (exit %s): %s", rc, safe_error)

        timed_out = _connect_timed_out(rc, out, err, elapsed)
        return {
            "ok": rc == 0,
            "action": "connect",
            "state": "connecting" if rc == 0 else "error",
            "target": target,
            "exit_code": rc,
            "error_code": (
                None
                if rc == 0
                else "vpn_connect_timeout"
                if timed_out
                else "provider_connect_failed"
            ),
        }

    async def connect_country(
        self,
        country_code: str,
        *,
        server_hostname: str | None = None,
        timeout: float = 40,
    ) -> dict:
        try:
            target = build_connect_target(country_code, server_hostname)
        except ValueError:
            return {
                "ok": False,
                "action": "connect",
                "state": "error",
                "target": None,
                "exit_code": None,
                "error_code": "invalid_target",
            }
        return await self.connect(target, timeout=timeout)

    async def disconnect(self, *, timeout: float = 15):
        if not shutil.which("nordvpn"):
            return {
                "ok": False,
                "action": "disconnect",
                "state": "error",
                "target": None,
                "error_code": "provider_cli_unavailable",
            }
        rc, _out, _err = await command(
            "nordvpn",
            "disconnect",
            timeout=timeout,
        )

        return {
            "ok": rc == 0,
            "action": "disconnect",
            "state": "disconnecting" if rc == 0 else "error",
            "target": None,
            "error_code": (
                None
                if rc == 0
                else "vpn_disconnect_timeout"
                if rc == 124
                else "provider_disconnect_failed"
            ),
        }

    async def recover_daemon(self) -> dict:
        """Restart exactly nordvpnd; no user-controlled executable, unit, or arguments."""
        rc, _out, _error = await command(
            "/usr/bin/systemctl", "restart", "nordvpnd.service", timeout=15
        )
        if rc != 0:
            return {"ok": False, "error_code": "provider_recovery_failed"}
        active_rc, _, _ = await command(
            "/usr/bin/systemctl", "is-active", "nordvpnd.service", timeout=5
        )
        if active_rc != 0:
            return {"ok": False, "error_code": "provider_recovery_failed"}
        status = await self.status(timeout=6)
        responsive = status.get("available") is True and status.get("state") in {
            "connected",
            "disconnected",
        }
        return {
            "ok": responsive,
            "error_code": None if responsive else "provider_recovery_healthcheck_failed",
            "status": status,
        }


provider = NordVPN()
