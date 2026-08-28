from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import sqlite3
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from statistics import median

from exitlane import core
from exitlane.core import set_setting, setting

PROVIDER = "nordvpn"
CACHE_TTL = timedelta(minutes=5)
QUICK_COUNTRIES = ("NL", "BE", "DE", "FR", "GB")
NORDVPN_SERVER_PATTERN = re.compile(r"^(?P<country>[a-z]{2})[0-9]+\.nordvpn\.com$")
SAFE_SERVER_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
)
_active_server_measurements: dict[tuple[str, str, str], asyncio.Task[dict]] = {}
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
    return datetime.now(UTC)


def normalize_server_hostname(server: str | None) -> str | None:
    if not isinstance(server, str):
        return None
    normalized = server.strip().rstrip(".").casefold()
    return normalized or None


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
        "is_recent": code
        == setting(
            f"vpn.last_country.{provider_id}",
            setting("vpn.last_country") if provider_id == PROVIDER else None,
        ),
    }


def server_latency(server: str | None, *, provider_id: str = PROVIDER) -> dict:
    normalized = normalize_server_hostname(server)
    if not normalized:
        return {"latency_ms": None, "latency_measured_at": None}
    with sqlite3.connect(core.DB) as connection:
        row = connection.execute(
            """SELECT latency_ms, measured_at FROM vpn_latency_cache
               WHERE provider=?
                 AND lower(rtrim(trim(server), '.'))=?
                 AND measured_at>=?
               ORDER BY measured_at DESC LIMIT 1""",
            (provider_id, normalized, (_now() - CACHE_TTL).isoformat()),
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
        except (TimeoutError, OSError):
            continue
    return {
        "latency_ms": round(median(measurements)) if measurements else None,
        "status": "reachable" if measurements else "unreachable",
        "method": "tcp",
    }


async def _measure_active_server(
    hostname: str,
    *,
    country_code: str,
    provider_id: str,
    endpoint: str,
    measurer: Callable[[str], Awaitable[dict]],
) -> dict:
    if not SAFE_SERVER_PATTERN.fullmatch(hostname) or not re.fullmatch(
        r"[A-Z]{2}", country_code
    ):
        return {"latency_ms": None, "latency_measured_at": None}
    result = await measurer(endpoint)
    measured_at = _now().isoformat()
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            """INSERT INTO vpn_latency_cache
               (provider, country_code, server, latency_ms, status, measured_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(provider, server) DO UPDATE SET
                 country_code=excluded.country_code, latency_ms=excluded.latency_ms,
                 status=excluded.status, measured_at=excluded.measured_at""",
            (
                provider_id,
                country_code,
                hostname,
                result.get("latency_ms"),
                result.get("status", "unknown"),
                measured_at,
            ),
        )
    return {
        "latency_ms": result.get("latency_ms"),
        "latency_measured_at": measured_at,
    }


async def ensure_active_server_latency(
    server: str | None,
    *,
    provider_id: str = PROVIDER,
    country_code: str | None = None,
    endpoint: str | None = None,
    measurer: Callable[[str], Awaitable[dict]] | None = None,
) -> dict:
    """Return or measure fresh RTT telemetry for the exact connected server."""
    hostname = normalize_server_hostname(server)
    cached = server_latency(hostname, provider_id=provider_id)
    if cached["latency_measured_at"] is not None or hostname is None:
        return cached
    derived_country = country_code
    if derived_country is None and provider_id == PROVIDER:
        match = NORDVPN_SERVER_PATTERN.fullmatch(hostname)
        derived_country = match.group("country").upper() if match else None
    if (
        not SAFE_SERVER_PATTERN.fullmatch(hostname)
        or not isinstance(derived_country, str)
        or not re.fullmatch(r"[A-Z]{2}", derived_country)
    ):
        return cached

    measurement_endpoint = endpoint or hostname
    key = (str(core.DB.resolve()), provider_id, hostname)
    task = _active_server_measurements.get(key)
    if task is None:
        task = asyncio.create_task(
            _measure_active_server(
                hostname,
                country_code=derived_country,
                provider_id=provider_id,
                endpoint=measurement_endpoint,
                measurer=measurer or tcp_latency,
            )
        )
        _active_server_measurements[key] = task

        def clear_completed(completed: asyncio.Task[dict]) -> None:
            if _active_server_measurements.get(key) is completed:
                _active_server_measurements.pop(key, None)

        task.add_done_callback(clear_completed)
    try:
        return await asyncio.shield(task)
    finally:
        if task.done() and _active_server_measurements.get(key) is task:
            _active_server_measurements.pop(key, None)


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
    provider_id: str = PROVIDER,
    measurer: Callable[[str], Awaitable[dict]] | None = None,
) -> list[dict]:
    code = country_code.upper()
    if not force:
        cached = _cached(code, provider_id=provider_id)
        if cached:
            return cached

    candidates = [
        {**item, "hostname": normalize_server_hostname(item.get("hostname"))}
        for item in servers
        if normalize_server_hostname(item.get("hostname"))
    ][:5]
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
                (
                    provider_id,
                    code,
                    row["server"],
                    row["latency_ms"],
                    row["status"],
                    measured_at,
                )
                for row in rows
            ],
        )
    return sorted(rows, key=lambda item: (item["latency_ms"] is None, item["latency_ms"] or 0))


async def select_server(
    country_code: str,
    servers: list[dict],
    *,
    provider_id: str = PROVIDER,
) -> dict | None:
    measured = await measure_servers(country_code, servers, provider_id=provider_id)
    best = next((item for item in measured if item["latency_ms"] is not None), None)
    if best:
        return best
    fallback = next((item for item in servers if item.get("hostname")), None)
    if fallback:
        return {"server": fallback["hostname"], "latency_ms": None, "status": "unknown"}
    return None


def remember_country(country_code: str, *, provider_id: str = PROVIDER) -> None:
    code = country_code.upper()
    set_setting(f"vpn.last_country.{provider_id}", code)
    if provider_id == PROVIDER:
        set_setting("vpn.last_country", code)
