from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Awaitable, Callable

from exitlane import core
from exitlane.core import set_setting, setting

PROVIDER = "nordvpn"
CACHE_TTL = timedelta(minutes=5)
QUICK_COUNTRIES = ("NL", "BE", "DE", "FR", "GB")
COUNTRY_NAMES = {
    "AT": "Oostenrijk",
    "AU": "Australië",
    "BE": "België",
    "BR": "Brazilië",
    "CA": "Canada",
    "CH": "Zwitserland",
    "CZ": "Tsjechië",
    "DE": "Duitsland",
    "DK": "Denemarken",
    "ES": "Spanje",
    "FI": "Finland",
    "FR": "Frankrijk",
    "GB": "Verenigd Koninkrijk",
    "GR": "Griekenland",
    "HK": "Hongkong",
    "HU": "Hongarije",
    "IE": "Ierland",
    "IN": "India",
    "IS": "IJsland",
    "IT": "Italië",
    "JP": "Japan",
    "KR": "Zuid-Korea",
    "LU": "Luxemburg",
    "MX": "Mexico",
    "NL": "Nederland",
    "NO": "Noorwegen",
    "NZ": "Nieuw-Zeeland",
    "PL": "Polen",
    "PT": "Portugal",
    "RO": "Roemenië",
    "SE": "Zweden",
    "SG": "Singapore",
    "SK": "Slowakije",
    "TR": "Turkije",
    "US": "Verenigde Staten",
    "ZA": "Zuid-Afrika",
}


def flag(code: str) -> str:
    return "".join(chr(127397 + ord(character)) for character in code)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cached(
    country_code: str,
    *,
    provider_id: str = PROVIDER,
    fresh_only: bool = True,
) -> list[dict]:
    cutoff = (_now() - CACHE_TTL).isoformat()
    query = """SELECT server, latency_ms, status, measured_at FROM vpn_latency_cache
               WHERE provider=? AND country_code=?"""
    params: list[object] = [provider_id, country_code]
    if fresh_only:
        query += " AND measured_at>=?"
        params.append(cutoff)
    query += " ORDER BY latency_ms IS NULL, latency_ms, measured_at DESC"
    with sqlite3.connect(core.DB) as connection:
        rows = connection.execute(query, params).fetchall()
    return [
        {"server": row[0], "latency_ms": row[1], "status": row[2], "measured_at": row[3]}
        for row in rows
    ]


def country_summary(
    code: str,
    *,
    connected_code: str | None = None,
    provider_name: str | None = None,
    provider_id: str = PROVIDER,
) -> dict:
    cached = _cached(code, provider_id=provider_id)
    best = next((item for item in cached if item["latency_ms"] is not None), None)
    newest = cached[0] if cached else None
    return {
        "country_code": code,
        "name": COUNTRY_NAMES.get(code, provider_name or code),
        "flag": flag(code),
        "latency_ms": best["latency_ms"] if best else None,
        "latency_measured_at": (best or newest or {}).get("measured_at"),
        "latency_status": (best or newest or {}).get("status", "unknown"),
        "is_connected": code == connected_code,
        "is_recent": code == setting("vpn.last_country"),
    }


def server_latency(server: str | None) -> dict:
    if not server:
        return {"latency_ms": None, "latency_measured_at": None}
    with sqlite3.connect(core.DB) as connection:
        row = connection.execute(
            """SELECT latency_ms, measured_at FROM vpn_latency_cache
               WHERE provider=? AND server=? AND measured_at>=?""",
            (PROVIDER, server, (_now() - CACHE_TTL).isoformat()),
        ).fetchone()
    return {
        "latency_ms": row[0] if row else None,
        "latency_measured_at": row[1] if row else None,
    }


async def tcp_latency(hostname: str, *, attempts: int = 3, timeout: float = 1.5) -> dict:
    """Fallback probe: TCP connect to port 443 of an already resolved station address."""
    measurements: list[float] = []
    for _ in range(attempts):
        started = asyncio.get_running_loop().time()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 443), timeout=timeout
            )
            measurements.append((asyncio.get_running_loop().time() - started) * 1000)
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            continue
    return {
        "latency_ms": round(median(measurements)) if measurements else None,
        "status": "reachable" if measurements else "unreachable",
        "method": "tcp",
    }


async def measure_latency(endpoint: str, *, attempts: int = 3, timeout: float = 1.0) -> dict:
    """Measure median ICMP RTT, with TCP/443 fallback when ICMP is unavailable or blocked."""
    try:
        ipaddress.ip_address(endpoint)
    except ValueError:
        return {"latency_ms": None, "status": "unknown", "method": None}

    if shutil.which("ping"):
        rc, output, _error = await core.command(
            "ping",
            "-n",
            "-c",
            str(attempts),
            "-W",
            str(max(1, round(timeout))),
            endpoint,
            timeout=(attempts * (timeout + 1)),
        )
        samples = [float(value) for value in re.findall(r"time[=<]([0-9.]+)\s*ms", output)]
        if rc == 0 and samples:
            return {
                "latency_ms": round(median(samples)),
                "status": "reachable",
                "method": "icmp",
            }

    return await tcp_latency(endpoint, attempts=attempts, timeout=timeout)


async def measure_servers(
    country_code: str,
    servers: list[dict],
    *,
    force: bool = False,
    measurer: Callable[[str], Awaitable[dict]] | None = None,
) -> list[dict]:
    code = country_code.upper()
    if not force:
        cached = _cached(code)
        if cached:
            return cached

    candidates = [item for item in servers if item.get("hostname")][:5]
    measurer = measurer or measure_latency
    results = await asyncio.gather(
        *(measurer(item.get("station") or item["hostname"]) for item in candidates)
    )
    measured_at = _now().isoformat()
    rows = []
    for server, result in zip(candidates, results, strict=True):
        row = {"server": server["hostname"], "measured_at": measured_at, **result}
        rows.append(row)
    with sqlite3.connect(core.DB) as connection:
        connection.executemany(
            """INSERT INTO vpn_latency_cache
               (provider, country_code, server, latency_ms, status, measured_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(provider, server) DO UPDATE SET
                 country_code=excluded.country_code, latency_ms=excluded.latency_ms,
                 status=excluded.status, measured_at=excluded.measured_at""",
            [
                (PROVIDER, code, row["server"], row["latency_ms"], row["status"], measured_at)
                for row in rows
            ],
        )
    return sorted(rows, key=lambda item: (item["latency_ms"] is None, item["latency_ms"] or 0))


async def select_server(country_code: str, servers: list[dict]) -> dict | None:
    measured = await measure_servers(country_code, servers)
    best = next((item for item in measured if item["latency_ms"] is not None), None)
    if best:
        return best
    fallback = next((item for item in servers if item.get("hostname")), None)
    if fallback:
        return {"server": fallback["hostname"], "latency_ms": None, "status": "unknown"}
    return None


def remember_country(country_code: str) -> None:
    set_setting("vpn.last_country", country_code.upper())
