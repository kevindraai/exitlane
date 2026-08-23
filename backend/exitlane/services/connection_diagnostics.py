from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from exitlane.core import command
from exitlane.services import speedtest_installation

STATUSES = frozenset({"pending", "running", "passed", "warning", "failed"})
TERMINAL_STATUSES = frozenset({"passed", "warning", "failed"})
PROBE_DEFINITIONS = (
    ("exitlane_network", "device_exitlane"),
    ("vpn_interface", "exitlane_vpn"),
    ("vpn_handshake", "exitlane_vpn"),
    ("vpn_route", "exitlane_vpn"),
    ("dns_resolution", "vpn_internet"),
    ("internet_reachability", "vpn_internet"),
    ("public_ip", "vpn_internet"),
)
MAX_RUNS = 20
_runs: dict[str, dict] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _probe(probe_id: str, segment: str) -> dict:
    return {
        "id": probe_id,
        "segment": segment,
        "status": "pending",
        "code": "pending",
        "detail": None,
        "observed_at": None,
        "duration_ms": None,
    }


def _result(status: str, code: str, detail: dict | None = None) -> dict:
    if status not in TERMINAL_STATUSES:
        raise ValueError("Diagnostic result must be terminal")
    return {"status": status, "code": code, "detail": detail or {}}


def _safe_target(target: str) -> str:
    value = target.strip().rstrip(".").casefold()
    if not value or len(value) > 253:
        raise ValueError("invalid_diagnostic_target")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("invalid_diagnostic_target")
    return value


async def probe_exitlane_network() -> dict:
    rc, output, _error = await command("ip", "route", "get", "1.1.1.1", timeout=5)
    if rc == 127:
        return _result("warning", "network_tool_unavailable")
    if rc != 0:
        return _result("failed", "default_route_unavailable")
    match = re.search(r"\bdev\s+([A-Za-z0-9_.-]{1,15})\b", output)
    if not match:
        return _result("failed", "default_route_unparseable")
    return _result("passed", "default_route_available", {"interface": match.group(1)})


async def probe_vpn_interface(provider_status: dict) -> dict:
    if not provider_status.get("connected"):
        return _result("failed", "vpn_disconnected")
    technology = str(provider_status.get("technology", "")).casefold()
    interface = "nordlynx" if "nordlynx" in technology else None
    if not interface:
        return _result("warning", "vpn_interface_unknown")
    rc, _output, _error = await command("ip", "link", "show", "dev", interface, timeout=5)
    if rc == 0:
        return _result("passed", "vpn_interface_active", {"interface": interface})
    return _result("failed", "vpn_interface_inactive", {"interface": interface})


async def probe_vpn_handshake(provider_status: dict) -> dict:
    if not provider_status.get("connected"):
        return _result("failed", "vpn_disconnected")
    technology = str(provider_status.get("technology", "")).casefold()
    if "nordlynx" not in technology:
        return _result("warning", "vpn_handshake_not_exposed")
    rc, output, _error = await command("wg", "show", "nordlynx", "latest-handshakes", timeout=5)
    if rc == 127:
        return _result("warning", "wireguard_tool_unavailable")
    if rc != 0:
        return _result("warning", "vpn_handshake_unavailable")
    timestamps = [int(value) for value in re.findall(r"\t([0-9]+)(?:\n|$)", output)]
    latest = max(timestamps, default=0)
    if latest <= 0:
        return _result("warning", "vpn_handshake_missing")
    age = max(0, int(datetime.now(UTC).timestamp()) - latest)
    status = "passed" if age <= 180 else "warning"
    code = "vpn_handshake_recent" if status == "passed" else "vpn_handshake_stale"
    return _result(status, code, {"age_seconds": age})


async def probe_vpn_route(provider_status: dict) -> dict:
    if not provider_status.get("connected"):
        return _result("failed", "vpn_disconnected")
    rc, output, _error = await command("ip", "route", "get", "1.1.1.1", timeout=5)
    if rc != 0:
        return _result("failed", "internet_route_unavailable")
    technology = str(provider_status.get("technology", "")).casefold()
    expected = "nordlynx" if "nordlynx" in technology else None
    match = re.search(r"\bdev\s+([A-Za-z0-9_.-]{1,15})\b", output)
    actual = match.group(1) if match else None
    if expected and actual == expected:
        return _result("passed", "vpn_route_active", {"interface": actual})
    return _result("warning", "vpn_route_unconfirmed", {"interface": actual})


async def dns_lookup(target: str = "api.nordvpn.com") -> dict:
    hostname = _safe_target(target)
    rc, output, _error = await command("getent", "ahosts", hostname, timeout=6)
    if rc == 127:
        return _result("warning", "dns_tool_unavailable", {"target": hostname})
    addresses: list[str] = []
    if rc == 0:
        for value in re.findall(r"^(\S+)", output, re.MULTILINE):
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if normalized not in addresses:
                addresses.append(normalized)
    if not addresses:
        return _result("failed", "dns_resolution_failed", {"target": hostname})
    return _result(
        "passed", "dns_resolution_passed", {"target": hostname, "addresses": addresses[:4]}
    )


async def ping(target: str = "1.1.1.1") -> dict:
    destination = _safe_target(target)
    rc, output, _error = await command("ping", "-n", "-c", "1", "-W", "3", destination, timeout=5)
    if rc == 127:
        return _result("warning", "ping_tool_unavailable", {"target": destination})
    latency = re.search(r"time[=<]([0-9.]+)\s*ms", output)
    if rc != 0:
        return _result("failed", "internet_unreachable", {"target": destination})
    detail: dict[str, object] = {"target": destination}
    if latency:
        detail["latency_ms"] = round(float(latency.group(1)), 1)
    return _result("passed", "internet_reachable", detail)


async def external_ip() -> dict:
    rc, output, _error = await command(
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "8",
        "https://api.ipify.org",
        timeout=10,
    )
    if rc == 127:
        return _result("warning", "public_ip_tool_unavailable")
    try:
        address = str(ipaddress.ip_address(output.strip())) if rc == 0 else None
    except ValueError:
        address = None
    if not address:
        return _result("failed", "public_ip_unavailable")
    return _result("passed", "public_ip_available", {"address": address})


async def speedtest(
    *,
    confirm_personal_noncommercial: bool = False,
    accept_license: bool = False,
    accept_gdpr: bool = False,
    confirm_bandwidth: bool = False,
) -> dict:
    available, _error = await speedtest_installation._official_cli_state()
    if not available:
        snapshot = await speedtest_installation.status()
        return _result(
            "warning",
            "speedtest_tool_unavailable",
            {
                "available": False,
                "supported_runtime": snapshot["supported_runtime"],
                "can_install": snapshot["can_install"],
                "requires_terms_confirmation": snapshot["requires_terms_confirmation"],
            },
        )
    if not all((confirm_personal_noncommercial, accept_license, accept_gdpr, confirm_bandwidth)):
        return _result(
            "warning",
            "speedtest_terms_confirmation_required",
            {"requires_terms_confirmation": True},
        )
    rc, output, _error = await command(
        speedtest_installation.OFFICIAL_EXECUTABLE,
        "--accept-license",
        "--accept-gdpr",
        "--format=json",
        timeout=120,
    )
    if rc != 0:
        return _result("failed", "speedtest_failed")
    try:
        payload = json.loads(output)
        detail = {
            "latency_ms": round(float(payload["ping"]["latency"]), 1),
            "download_mbps": round(float(payload["download"]["bandwidth"]) * 8 / 1_000_000, 1),
            "upload_mbps": round(float(payload["upload"]["bandwidth"]) * 8 / 1_000_000, 1),
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _result("failed", "speedtest_result_invalid")
    return _result("passed", "speedtest_passed", detail)


def _overall(probes: list[dict]) -> str:
    statuses = {probe["status"] for probe in probes}
    if "running" in statuses:
        return "running"
    if "pending" in statuses:
        return "pending"
    if "failed" in statuses:
        return "failed"
    if "warning" in statuses:
        return "warning"
    if statuses <= {"passed"}:
        return "passed"
    return "passed"


def snapshot(run_id: str) -> dict | None:
    run = _runs.get(run_id)
    if run is None:
        return None
    probes = [{**probe, "detail": dict(probe["detail"] or {})} for probe in run["probes"]]
    return {**run, "status": _overall(probes), "probes": probes}


async def _execute(run_id: str, status_loader: Callable[[], Awaitable[dict]]) -> None:
    run = _runs.get(run_id)
    if run is None:
        return
    run["started_at"] = _now()
    try:
        provider_status = await status_loader()
    except Exception:  # noqa: BLE001 - provider failure becomes a diagnostic result.
        provider_status = {"connected": False}
    functions = {
        "exitlane_network": probe_exitlane_network,
        "vpn_interface": lambda: probe_vpn_interface(provider_status),
        "vpn_handshake": lambda: probe_vpn_handshake(provider_status),
        "vpn_route": lambda: probe_vpn_route(provider_status),
        "dns_resolution": dns_lookup,
        "internet_reachability": ping,
        "public_ip": external_ip,
    }

    async def execute_probe(probe: dict) -> None:
        probe["status"] = "running"
        started = asyncio.get_running_loop().time()
        try:
            result = await functions[probe["id"]]()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - each probe must fail independently and safely.
            result = _result("failed", "probe_unavailable")
        probe.update(
            **result,
            observed_at=_now(),
            duration_ms=round((asyncio.get_running_loop().time() - started) * 1000),
        )

    await asyncio.gather(*(execute_probe(probe) for probe in run["probes"]))
    run["completed_at"] = _now()


def start(status_loader: Callable[[], Awaitable[dict]]) -> dict:
    run_id = str(uuid.uuid4())
    _runs[run_id] = {
        "run_id": run_id,
        "connection_id": "provider:nordvpn",
        "created_at": _now(),
        "started_at": None,
        "completed_at": None,
        "probes": [_probe(probe_id, segment) for probe_id, segment in PROBE_DEFINITIONS],
    }
    while len(_runs) > MAX_RUNS:
        _runs.pop(next(iter(_runs)))
    asyncio.create_task(_execute(run_id, status_loader))
    return snapshot(run_id) or {}


async def action(
    name: str,
    target: str | None = None,
    *,
    confirm_personal_noncommercial: bool = False,
    accept_license: bool = False,
    accept_gdpr: bool = False,
    confirm_bandwidth: bool = False,
) -> dict:
    if name == "ping":
        return await ping(target or "1.1.1.1")
    if name == "dns":
        return await dns_lookup(target or "api.nordvpn.com")
    if name == "external-ip":
        return await external_ip()
    if name == "speedtest":
        return await speedtest(
            confirm_personal_noncommercial=confirm_personal_noncommercial,
            accept_license=accept_license,
            accept_gdpr=accept_gdpr,
            confirm_bandwidth=confirm_bandwidth,
        )
    raise KeyError(name)


def reset_for_tests() -> None:
    _runs.clear()
