from __future__ import annotations

import re
import shutil
import asyncio
from datetime import datetime, timezone
from typing import Any
from exitlane.core import command

from .base import Provider


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

    async def status(self):
        if not shutil.which("nordvpn"):
            return {
                "installed": False,
                "daemon_active": False,
                "authenticated": False,
                "connected": False,
            }

        daemon_rc, _, _ = await command(
            "systemctl",
            "is-active",
            "nordvpnd",
        )

        status_rc, status_out, status_err = await command(
            "nordvpn",
            "status",
        )
        values = parse(status_out or status_err)

        account_rc, account_out, account_err = await command(
            "nordvpn",
            "account",
        )

        account_output = account_out or account_err

        return {
            "installed": True,
            "daemon_active": daemon_rc == 0,
            "authenticated": (account_rc == 0 and "not logged in" not in account_output.lower()),
            "connected": (status_rc == 0 and values.get("Status", "").lower() == "connected"),
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
        results = []

        settings = [
            ("technology", "NordLynx"),
            ("routing", "on"),
            ("lan-discovery", "on"),
            ("firewall", "on"),
            ("killswitch", "off"),
            ("ipv6", "off"),
            ("analytics", "off"),
        ]

        for key, value in settings:
            rc, out, err = await command(
                "nordvpn",
                "set",
                key,
                value,
            )

            results.append(
                {
                    "setting": key,
                    "ok": rc == 0,
                    "output": out or err,
                }
            )

        return results

    async def countries(self):
        rc, out, _ = await command(
            "nordvpn",
            "countries",
        )

        if rc != 0:
            return []

        return sorted(out.split())

    async def connect(self, target=None):
        args = ["nordvpn", "connect"]

        if target:
            if not re.fullmatch(
                r"[A-Za-z0-9 _.-]{1,80}",
                target,
            ):
                return {
                    "ok": False,
                    "message": "invalid target",
                }

            args.append(target)

        rc, out, err = await command(
            *args,
            timeout=90,
        )

        return {
            "ok": rc == 0,
            "stdout": out,
            "stderr": err,
        }

    async def disconnect(self):
        rc, out, err = await command(
            "nordvpn",
            "disconnect",
        )

        return {
            "ok": rc == 0,
            "stdout": out,
            "stderr": err,
        }


provider = NordVPN()
