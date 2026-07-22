from __future__ import annotations

import re
import shutil
import asyncio
import http.client
import json
import logging
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from exitlane.core import command

from .base import Provider

logger = logging.getLogger(__name__)
SERVER_HOSTNAME_PATTERN = re.compile(r"^([a-z]{2}[0-9]+)\.nordvpn\.com$")
CONNECT_FAILURE_TIMEOUT_SECONDS = 25


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


_install_job: dict[str, Any] = {
    "running": False,
    "finished": False,
    "ok": None,
    "message": "",
    "logs": [],
    "started_at": None,
    "finished_at": None,
}
_country_catalog_cache: list[dict] = []


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reset_install_job() -> None:
    _install_job.update(
        {
            "running": True,
            "finished": False,
            "ok": None,
            "message": "NordVPN-installatie gestart",
            "logs": [],
            "started_at": _utc_now(),
            "finished_at": None,
        }
    )


def _append_install_log(message: str) -> None:
    if message:
        _install_job["logs"].append(message)

    _install_job["logs"] = _install_job["logs"][-100:]


class NordVPN(Provider):
    id = "nordvpn"
    display_name = "NordVPN"

    async def status(self, *, timeout: float = 8):
        if not shutil.which("nordvpn"):
            in_container = Path("/.dockerenv").exists()
            return {
                "installed": False,
                "available": False,
                "daemon_active": False,
                "authenticated": False,
                "connected": False,
                "state": "unavailable",
                "error_code": (
                    "unsupported_container_runtime" if in_container else "provider_cli_unavailable"
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

        return {
            "installed": True,
            "available": status_rc == 0,
            "daemon_active": daemon_rc == 0,
            "authenticated": (account_rc == 0 and "not logged in" not in account_output.lower()),
            "connected": (status_rc == 0 and values.get("Status", "").lower() == "connected"),
            "state": values.get("Status", "error").lower() if status_rc == 0 else "error",
            "error_code": None if status_rc == 0 else "provider_status_unavailable",
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
        }

    def install_status(self) -> dict:
        return dict(_install_job)

    async def start_install(self) -> dict:
        if _install_job["running"]:
            return {
                "ok": False,
                "message": "NordVPN-installatie draait al",
            }

        _reset_install_job()
        asyncio.create_task(self._run_install_job())

        return {
            "ok": True,
            "message": "NordVPN-installatie gestart",
        }

    async def _run_install_job(self) -> None:
        try:
            if shutil.which("nordvpn"):
                status = await self.status()

                _install_job.update(
                    {
                        "running": False,
                        "finished": True,
                        "ok": True,
                        "message": "NordVPN is al geïnstalleerd",
                        "finished_at": _utc_now(),
                    }
                )
                _append_install_log("NordVPN-client is al aanwezig.")
                _append_install_log(f"Daemon actief: {status.get('daemon_active', False)}")
                return

            _append_install_log("NordVPN-releasepakket downloaden…")

            script = r"""
set -Eeuo pipefail

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

release_deb="$tmp_dir/nordvpn-release.deb"

echo "Releasepakket downloaden"
curl -fsSL \
  https://repo.nordvpn.com/deb/nordvpn/debian/pool/main/n/nordvpn-release/nordvpn-release_1.0.0_all.deb \
  -o "$release_deb"

echo "Repositorypakket installeren"
dpkg -i "$release_deb"

echo "APT-bestanden leesbaar maken"
find /etc/apt/trusted.gpg.d \
  -maxdepth 1 \
  -type f \
  -iname '*nord*' \
  -exec chmod 0644 {} \;

find /etc/apt/sources.list.d \
  -maxdepth 1 \
  -type f \
  -iname '*nord*' \
  -exec chmod 0644 {} \;

echo "Pakketlijsten vernieuwen"
apt-get update

echo "NordVPN installeren"
DEBIAN_FRONTEND=noninteractive apt-get install -y nordvpn

echo "NordVPN-daemon starten"
systemctl enable --now nordvpnd

echo "Installatie afgerond"
"""

            rc, out, err = await command(
                "bash",
                "-c",
                script,
                timeout=300,
            )

            for line in out.splitlines():
                _append_install_log(line)

            for line in err.splitlines():
                _append_install_log(line)

            installed = shutil.which("nordvpn") is not None
            daemon_rc, daemon_out, daemon_err = await command(
                "systemctl",
                "is-active",
                "nordvpnd",
            )

            ok = rc == 0 and installed and daemon_rc == 0

            if daemon_out:
                _append_install_log(f"NordVPN-daemon: {daemon_out.strip()}")

            if daemon_err:
                _append_install_log(daemon_err)

            _install_job.update(
                {
                    "running": False,
                    "finished": True,
                    "ok": ok,
                    "message": (
                        "NordVPN succesvol geïnstalleerd" if ok else "NordVPN-installatie mislukt"
                    ),
                    "finished_at": _utc_now(),
                }
            )

        except Exception as error:
            _append_install_log(str(error))

            _install_job.update(
                {
                    "running": False,
                    "finished": True,
                    "ok": False,
                    "message": "NordVPN-installatie mislukt",
                    "finished_at": _utc_now(),
                }
            )

    async def login_token(self, token):
        if not re.fullmatch(
            r"[A-Za-z0-9._~-]{20,512}",
            token,
        ):
            return {
                "ok": False,
                "message": "invalid token format",
            }

        rc, out, err = await command(
            "nordvpn",
            "login",
            "--token",
            token,
        )

        return {
            "ok": rc == 0,
            "stdout": out,
            "stderr": err,
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
        rc, out, err = await command(
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
                {"id": item["id"], "country_code": item["code"].upper(), "provider_name": item["name"]}
                for item in data if item.get("id") is not None and item.get("code")
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
            for item in data if item.get("hostname")
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
                None if rc == 0 else "vpn_connect_timeout" if timed_out else "provider_connect_failed"
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
                None if rc == 0 else "vpn_disconnect_timeout" if rc == 124 else "provider_disconnect_failed"
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
            "connected", "disconnected"
        }
        return {
            "ok": responsive,
            "error_code": None if responsive else "provider_recovery_healthcheck_failed",
            "status": status,
        }


provider = NordVPN()
