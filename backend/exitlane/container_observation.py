"""Bounded container facts; never represent host metrics as container facts."""
from __future__ import annotations

import os
import shutil
import socket
import time
from pathlib import Path

_STARTED = time.monotonic()


def _integer(path: Path):
    try:
        raw = path.read_text(encoding="ascii")
        if len(raw) > 128 or not raw.strip().isdecimal():
            return None
        return int(raw.strip())
    except (OSError, ValueError):
        return None


async def system_status(data: Path, *, cgroup: Path = Path("/sys/fs/cgroup")):
    from exitlane.services.dashboard import SystemStatus
    used = _integer(cgroup / "memory.current")
    total = _integer(cgroup / "memory.max")
    try:
        disk = shutil.disk_usage(data)
    except OSError:
        disk = None
    return SystemStatus(
        available=used is not None or disk is not None,
        hostname=socket.gethostname(), cpu_percent=None,
        memory_used_bytes=used, memory_total_bytes=total,
        memory_percent=round(used / total * 100, 1) if used is not None and total else None,
        disk_used_bytes=disk.used if disk else None, disk_total_bytes=disk.total if disk else None,
        disk_percent=round(disk.used / disk.total * 100, 1) if disk and disk.total else None,
        uptime_seconds=max(0, time.monotonic() - _STARTED), load_average=None,
        metric_scope="container", error=None if used is not None or disk else "container_metrics_unavailable",
    )


async def diagnostics(network):
    from exitlane import core
    checks = [
        {"name": "Container root", "ok": os.geteuid() == 0, "detail": "container namespace"},
        {"name": "TUN", "ok": Path("/dev/net/tun").exists(), "detail": "/dev/net/tun"},
    ]
    for tool in ("ip", "wg", "wg-quick", "nft", "ping"):
        path = shutil.which(tool)
        checks.append({"name": tool, "ok": bool(path), "detail": path or "unavailable"})
    rc, output, _error = await core.command("ip", "-4", "route", "show", "default", timeout=5)
    checks.append({"name": "Management route", "ok": rc == 0 and "default via " in output,
                   "detail": "namespace management route"})
    # Before first-run ingress there is no protected interface to forward. Never
    # synthesize keys or claim a provider dataplane has been qualified here.
    if network is not None:
        try:
            await network.observe_guard()
        except RuntimeError:
            observed = False
        else:
            observed = True
        checks.append({"name": "Protected policy", "ok": observed,
                       "detail": "provider-or-block policy"})
    return checks


async def connection_run(run_id, status_loader):
    """Reuse the shared run DTO, with direct-provider proof rather than host probes."""
    from exitlane.services import connection_diagnostics as shared
    run = shared._runs.get(run_id)
    if run is None:
        return
    run["started_at"] = shared._now()
    try:
        snapshot = await status_loader()
    except RuntimeError:
        snapshot = {"connected": False}
    run["connection_id"] = snapshot.get("connection_id", "provider:unavailable")
    connected = snapshot.get("connected") is True
    interface = snapshot.get("tunnel_interface")
    # Connected is the shared D3 exact committed-peer/route/UDP+TCP DNS/lossless
    # dataplane observation. Handshake alone never produces this fact.
    results = {
        "exitlane_network": ("passed", "container_management_available", {}),
        "vpn_interface": ("passed" if connected else "failed", "provider_interface_verified" if connected else "vpn_disconnected", {"interface": interface} if connected else {}),
        "vpn_handshake": ("passed" if connected else "failed", "provider_dataplane_verified" if connected else "vpn_disconnected", {}),
        "vpn_route": ("passed" if connected else "failed", "provider_policy_verified" if connected else "vpn_disconnected", {}),
        "dns_resolution": ("passed" if connected else "failed", "provider_dns_verified" if connected else "vpn_disconnected", {}),
        "internet_reachability": ("passed" if connected else "failed", "provider_dataplane_verified" if connected else "vpn_disconnected", {}),
        "public_ip": ("warning", "provider_public_ip_unavailable", {}),
    }
    for probe in run["probes"]:
        status, code, detail = results[probe["id"]]
        probe.update(status=status, code=code, detail=detail, observed_at=shared._now(), duration_ms=0)
    run["completed_at"] = shared._now()
