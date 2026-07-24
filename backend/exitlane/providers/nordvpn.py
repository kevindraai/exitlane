from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import re
import shutil
import time
import urllib.parse
from pathlib import Path

from exitlane.core import command

from .base import InstallationState, Provider, ProviderMetadata

logger = logging.getLogger(__name__)
SERVER_HOSTNAME_PATTERN = re.compile(r"^([a-z]{2}[0-9]+)\.nordvpn\.com$")
CONNECT_FAILURE_TIMEOUT_SECONDS = 25
TOKEN_LOGIN_TIMEOUT_SECONDS = 15
SIGN_OUT_TIMEOUT_SECONDS = 15
TOKEN_ERROR_CODES = frozenset(
    {
        "already_logged_in",
        "invalid_token_format",
        "invalid_token",
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


def classify_token_login_failure(return_code: int, output: str, error: str) -> str:
    """Classify known CLI failures without returning uncontrolled provider text."""
    if return_code == 124:
        return "timeout"
    if return_code == 127:
        return "command_unavailable"
    message = f"{output}\n{error}".casefold()
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
            "token has expired",
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
        "77": "insufficient_privileges",
    }.get(unit.get("ExecMainStatus", ""), "installation_failed")


_country_catalog_cache: list[dict] = []
INSTALL_UNIT = "exitlane-provider-install-nordvpn.service"
INSTALL_START_TIMEOUT_SECONDS = 10
_installation_starting = False


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
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="NordVPN",
        description="NordVPN Linux client",
        icon="shield-check",
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

    async def installation_status(self) -> dict:
        if not _supports_managed_installation():
            return {
                "state": InstallationState.UNSUPPORTED,
                "phase": "unsupported",
                "error_code": "unsupported_platform",
            }

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
        installed = shutil.which("nordvpn") is not None
        if installed:
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
                    "phase": "failed",
                    "error_code": "provider_daemon_failed",
                }
            daemon_rc, _, _ = await command("systemctl", "is-active", "nordvpnd", timeout=5)
            if daemon_rc == 0:
                provider_rc, provider_out, provider_err = await command(
                    "nordvpn", "status", timeout=5
                )
                provider_output = f"{provider_out}\n{provider_err}".casefold()
                if provider_rc == 0 or any(
                    marker in provider_output for marker in ("not logged in", "not signed in")
                ):
                    return {
                        "state": InstallationState.AVAILABLE,
                        "phase": "validating",
                        "error_code": None,
                    }
                return {
                    "state": InstallationState.FAILED,
                    "phase": "failed",
                    "error_code": "provider_installation_validation_failed",
                }
            return {
                "state": InstallationState.DAEMON_INACTIVE,
                "phase": "starting_daemon",
                "error_code": "provider_daemon_failed",
            }

        if _installation_starting or active_state in {"activating", "active"}:
            return {
                "state": InstallationState.INSTALLING,
                "phase": "installing_client",
                "error_code": None,
            }
        if active_state == "failed":
            return {
                "state": InstallationState.FAILED,
                "phase": "failed",
                "error_code": _installation_error_code(unit),
            }
        return {
            "state": InstallationState.NOT_INSTALLED,
            "phase": "not_installed",
            "error_code": None,
        }

    async def start_installation(self) -> dict:
        global _installation_starting
        status = await self.installation_status()
        if status["state"] == InstallationState.UNSUPPORTED:
            return {"ok": False, "error_code": "unsupported_platform"}
        if status["state"] == InstallationState.INSTALLING or _installation_starting:
            return {"ok": False, "error_code": "installation_in_progress"}

        _installation_starting = True
        try:
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
        return {"ok": True, "state": InstallationState.INSTALLING}

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
            reason="tunnel_unavailable" if not connected else "tunnel_interface_unknown",
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
            "city": values.get("City", ""),
            "server": values.get(
                "Hostname",
                values.get("Server", ""),
            ),
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

        rc, out, err = await command(
            "nordvpn",
            "login",
            "--token",
            token,
            timeout=TOKEN_LOGIN_TIMEOUT_SECONDS,
            environment=_provider_cli_environment(),
        )
        classified = classify_token_login_failure(rc, out, err)
        error = None if rc == 0 and classified == "provider_error" else classified

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

    async def defaults(self):
        requested_settings = [
            {
                "setting": "technology",
                "value": "NordLynx",
                "expected_key": "Technology",
                "expected_value": "NORDLYNX",
            },
            {
                "setting": "routing",
                "value": "on",
                "expected_key": "Routing",
                "expected_value": "enabled",
            },
            {
                "setting": "lan-discovery",
                "value": "on",
                "expected_key": "LAN Discovery",
                "expected_value": "enabled",
            },
            {
                "setting": "autoconnect",
                "value": "on",
                "expected_key": "Auto-connect",
                "expected_value": "enabled",
            },
            {
                "setting": "firewall",
                "value": "on",
                "expected_key": "Firewall",
                "expected_value": "enabled",
            },
            {
                "setting": "killswitch",
                "value": "off",
                "expected_key": "Kill Switch",
                "expected_value": "disabled",
            },
            {
                "setting": "analytics",
                "value": "off",
                "expected_key": "User Consent",
                "expected_value": "disabled",
            },
        ]

        command_results = {}

        for item in requested_settings:
            rc, out, err = await command(
                "nordvpn",
                "set",
                item["setting"],
                item["value"],
            )

            command_results[item["setting"]] = {
                "return_code": rc,
                "output": (out or err).strip(),
            }

        settings_rc, settings_out, settings_err = await command(
            "nordvpn",
            "settings",
        )

        if settings_rc != 0:
            return [
                {
                    "setting": item["setting"],
                    "ok": False,
                    "output": (settings_err or settings_out or "Could not read NordVPN settings"),
                }
                for item in requested_settings
            ]

        actual_settings = parse(settings_out)
        results = []

        for item in requested_settings:
            actual_value = actual_settings.get(
                item["expected_key"],
                "",
            )

            verified = actual_value.casefold() == item["expected_value"].casefold()

            command_result = command_results[item["setting"]]

            results.append(
                {
                    "setting": item["setting"],
                    "ok": verified,
                    "requested": item["value"],
                    "actual": actual_value,
                    "output": command_result["output"],
                    "return_code": command_result["return_code"],
                }
            )

        return results

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

    async def connect_country(self, country_code: str, *, timeout: float = 40) -> dict:
        try:
            target = build_connect_target(country_code)
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
