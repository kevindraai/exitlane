from __future__ import annotations

import asyncio
import os
import shutil
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Literal

from pydantic import BaseModel, Field

DISK_WARNING_PERCENT = 85.0
DISK_CRITICAL_PERCENT = 95.0
MEMORY_WARNING_PERCENT = 85.0
HANDSHAKE_WARNING_SECONDS = 180


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HealthStatus(BaseModel):
    status: Literal["healthy", "warning", "error"]
    issues: list[str] = Field(default_factory=list)


class VPNStatus(BaseModel):
    available: bool
    installed: bool = False
    authenticated: bool = False
    connected: bool = False
    country: str | None = None
    city: str | None = None
    server: str | None = None
    external_ip: str | None = None
    target: str | None = None
    updated_at: datetime | None = None
    error: str | None = None


class WireGuardStatus(BaseModel):
    available: bool
    configured: bool = False
    active: bool = False
    connected: bool = False
    client: str | None = None
    peer_count: int = 0
    latest_handshake_at: datetime | None = None
    received_bytes: int = 0
    sent_bytes: int = 0
    endpoint: str | None = None
    error: str | None = None


class SystemStatus(BaseModel):
    available: bool = True
    hostname: str | None
    cpu_percent: float | None
    memory_percent: float | None
    memory_used_bytes: int | None
    memory_total_bytes: int | None
    disk_percent: float | None
    disk_used_bytes: int | None
    disk_total_bytes: int | None
    uptime_seconds: float | None
    load_average: tuple[float, float, float] | None
    temperature_celsius: float | None = None
    error: str | None = None


class DashboardResponse(BaseModel):
    health: HealthStatus
    vpn: VPNStatus
    wireguard: WireGuardStatus
    system: SystemStatus
    version: str
    generated_at: datetime


def determine_health(
    vpn: VPNStatus,
    wireguard: WireGuardStatus,
    system: SystemStatus,
    now: datetime | None = None,
) -> HealthStatus:
    """Apply the dashboard's explicit, centrally testable health rules."""
    now = now or utc_now()
    warnings: list[str] = []
    errors: list[str] = []
    unavailable_sources = (
        int(not vpn.available) + int(not wireguard.available) + int(not system.available)
    )

    if unavailable_sources >= 2:
        errors.append("multiple_status_sources_unavailable")
    else:
        if not vpn.available:
            warnings.append("vpn_status_unavailable")
        if not wireguard.available:
            warnings.append("wireguard_status_unavailable")
        if not system.available:
            warnings.append("system_status_unavailable")

    if vpn.available and not vpn.connected:
        warnings.append("vpn_disconnected")

    if wireguard.available:
        if wireguard.configured and not wireguard.active:
            errors.append("wireguard_inactive")
        elif wireguard.active:
            handshake_age = (
                None
                if wireguard.latest_handshake_at is None
                else (now - wireguard.latest_handshake_at).total_seconds()
            )
            if handshake_age is None or handshake_age > HANDSHAKE_WARNING_SECONDS:
                warnings.append("wireguard_handshake_stale")

    if system.disk_percent is not None and system.disk_percent >= DISK_CRITICAL_PERCENT:
        errors.append("disk_usage_critical")
    elif system.disk_percent is not None and system.disk_percent >= DISK_WARNING_PERCENT:
        warnings.append("disk_usage_high")

    if system.memory_percent is not None and system.memory_percent >= MEMORY_WARNING_PERCENT:
        warnings.append("memory_usage_high")

    if errors:
        return HealthStatus(status="error", issues=errors + warnings)
    if warnings:
        return HealthStatus(status="warning", issues=warnings)
    return HealthStatus(status="healthy", issues=[])


def _read_cpu_ticks() -> tuple[int, int] | None:
    try:
        values = [
            int(value) for value in Path("/proc/stat").read_text().splitlines()[0].split()[1:]
        ]
    except (OSError, ValueError, IndexError):
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def _memory_status() -> tuple[int, int, float] | None:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0]) * 1024
        total = values["MemTotal"]
    except (OSError, ValueError, KeyError):
        return None
    if total <= 0:
        return None
    used = total - values.get("MemAvailable", values.get("MemFree", 0))
    return used, total, round(used / total * 100, 1)


async def system_status(disk_path: Path = Path("/")) -> SystemStatus:
    first = _read_cpu_ticks()
    await asyncio.sleep(0.1)
    second = _read_cpu_ticks()
    cpu_percent = None
    if first and second and second[0] > first[0]:
        busy_delta = (second[0] - first[0]) - (second[1] - first[1])
        cpu_percent = round(max(0.0, busy_delta / (second[0] - first[0]) * 100), 1)

    memory = _memory_status()
    memory_used, memory_total, memory_percent = memory or (None, None, None)
    try:
        disk = shutil.disk_usage(disk_path)
        disk_percent = round(disk.used / disk.total * 100, 1) if disk.total else None
        disk_used = disk.used
        disk_total = disk.total
    except OSError:
        disk_percent = disk_used = disk_total = None
    try:
        uptime = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        uptime = None
    try:
        load_average = tuple(round(value, 2) for value in os.getloadavg())
    except OSError:
        load_average = None

    available = any(
        value is not None
        for value in (cpu_percent, memory_percent, disk_percent, uptime, load_average)
    )
    return SystemStatus(
        available=available,
        hostname=socket.gethostname(),
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        memory_used_bytes=memory_used,
        memory_total_bytes=memory_total,
        disk_percent=disk_percent,
        disk_used_bytes=disk_used,
        disk_total_bytes=disk_total,
        uptime_seconds=uptime,
        load_average=load_average,
        temperature_celsius=None,
        error=None if available else "system_status_unavailable",
    )


async def build_dashboard(
    provider_status: Callable[[], Awaitable[dict]],
    wireguard_status: Callable[[], Awaitable[dict]],
    version: str,
    system_status_call: Callable[[], Awaitable[SystemStatus]] | None = None,
) -> DashboardResponse:
    generated_at = utc_now()
    system_status_call = system_status_call or system_status
    provider_result, wireguard_result, system = await asyncio.gather(
        provider_status(), wireguard_status(), system_status_call(), return_exceptions=True
    )

    if isinstance(provider_result, BaseException) or not isinstance(provider_result, dict):
        vpn = VPNStatus(available=False, error="provider_status_unavailable")
    else:
        vpn = VPNStatus(
            available=True,
            installed=bool(provider_result.get("installed")),
            authenticated=bool(provider_result.get("authenticated")),
            connected=bool(provider_result.get("connected")),
            country=provider_result.get("country") or None,
            city=provider_result.get("city") or None,
            server=provider_result.get("server") or None,
            external_ip=provider_result.get("external_ip") or None,
            target=provider_result.get("country") or provider_result.get("server") or None,
            updated_at=generated_at,
        )

    if isinstance(wireguard_result, BaseException) or not isinstance(wireguard_result, dict):
        wireguard = WireGuardStatus(available=False, error="wireguard_status_unavailable")
    else:
        peers = wireguard_result.get("peers") or []
        if not isinstance(peers, list):
            peers = []
        # This sprint deliberately shows the first configured peer while reporting the total count.
        primary_peer = peers[0] if peers and isinstance(peers[0], dict) else {}
        latest = int(wireguard_result.get("latest_handshake", 0) or 0)
        wireguard = WireGuardStatus(
            available=True,
            configured=bool(wireguard_result.get("configured")),
            active=bool(wireguard_result.get("active")),
            connected=bool(wireguard_result.get("connected")),
            client=wireguard_result.get("client") or None,
            peer_count=len(peers),
            latest_handshake_at=datetime.fromtimestamp(latest, timezone.utc) if latest else None,
            received_bytes=int(primary_peer.get("received_bytes", 0) or 0),
            sent_bytes=int(primary_peer.get("sent_bytes", 0) or 0),
            endpoint=primary_peer.get("endpoint") or None,
            error="wireguard_inactive" if not wireguard_result.get("active") else None,
        )

    if isinstance(system, BaseException) or not isinstance(system, SystemStatus):
        system = SystemStatus(
            available=False,
            hostname=None,
            cpu_percent=None,
            memory_percent=None,
            memory_used_bytes=None,
            memory_total_bytes=None,
            disk_percent=None,
            disk_used_bytes=None,
            disk_total_bytes=None,
            uptime_seconds=None,
            load_average=None,
            error="system_status_unavailable",
        )
    health = determine_health(vpn, wireguard, system, generated_at)
    return DashboardResponse(
        health=health,
        vpn=vpn,
        wireguard=wireguard,
        system=system,
        version=version,
        generated_at=generated_at,
    )
