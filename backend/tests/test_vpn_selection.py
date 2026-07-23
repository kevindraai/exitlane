import asyncio
import sqlite3

from exitlane import core
from exitlane.services import vpn_selection


def initialise_database(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "DB", tmp_path / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", tmp_path / "wireguard")
    core.init()


def test_measurements_are_cached_and_best_reachable_server_is_selected(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)
    calls = []

    async def measure(hostname):
        calls.append(hostname)
        values = {"nl1.example": 25, "nl2.example": 12}
        return {"latency_ms": values[hostname], "status": "reachable"}

    servers = [{"hostname": "nl1.example"}, {"hostname": "nl2.example"}]
    first = asyncio.run(vpn_selection.measure_servers("NL", servers, measurer=measure))
    second = asyncio.run(vpn_selection.measure_servers("NL", servers, measurer=measure))

    assert [item["server"] for item in first] == ["nl2.example", "nl1.example"]
    assert second[0]["latency_ms"] == 12
    assert calls == ["nl1.example", "nl2.example"]


def test_unreachable_candidates_fall_back_to_provider_recommendation(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)

    async def unreachable(_hostname):
        return {"latency_ms": None, "status": "unreachable"}

    monkeypatch.setattr(vpn_selection, "tcp_latency", unreachable)
    servers = [{"hostname": "be1.example"}, {"hostname": "be2.example"}]
    selected = asyncio.run(vpn_selection.select_server("BE", servers))

    assert selected == {"server": "be1.example", "latency_ms": None, "status": "unknown"}


def test_last_country_and_latency_schema_are_persistent(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)
    vpn_selection.remember_country("gb")

    assert core.setting("vpn.last_country") == "GB"
    with sqlite3.connect(core.DB) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(vpn_latency_cache)")}
    assert {"provider", "country_code", "server", "latency_ms", "status", "measured_at"} <= columns


def test_country_summary_keeps_provider_latency_caches_separate(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)
    measured_at = vpn_selection._now().isoformat()
    with sqlite3.connect(core.DB) as connection:
        connection.executemany(
            """INSERT INTO vpn_latency_cache
               (provider, country_code, server, latency_ms, status, measured_at)
               VALUES (?, 'NL', ?, ?, 'reachable', ?)""",
            [
                ("nordvpn", "nl1.example", 12, measured_at),
                ("other", "nl2.example", 48, measured_at),
            ],
        )

    assert vpn_selection.country_summary("NL", provider_id="nordvpn")["latency_ms"] == 12
    assert vpn_selection.country_summary("NL", provider_id="other")["latency_ms"] == 48


def test_icmp_latency_uses_median_without_dns_lookup(monkeypatch):
    calls = []

    async def command(*args, **kwargs):
        calls.append(args)
        return 0, """64 bytes: time=21.4 ms
64 bytes: time=19.4 ms
64 bytes: time=20.6 ms""", ""

    monkeypatch.setattr(vpn_selection.shutil, "which", lambda _name: "/usr/bin/ping")
    monkeypatch.setattr(core, "command", command)

    result = asyncio.run(vpn_selection.measure_latency("37.120.143.219"))

    assert result == {"latency_ms": 21, "status": "reachable", "method": "icmp"}
    assert calls[0][-1] == "37.120.143.219"


def test_invalid_latency_endpoint_is_not_executed(monkeypatch):
    async def command(*args, **kwargs):
        raise AssertionError("must not execute")

    monkeypatch.setattr(core, "command", command)

    result = asyncio.run(vpn_selection.measure_latency("server; reboot"))

    assert result == {"latency_ms": None, "status": "unknown", "method": None}


def test_tcp_fallback_uses_validated_station_ip(monkeypatch):
    async def command(*args, **kwargs):
        return 1, "", "blocked"

    async def tcp(endpoint, **kwargs):
        assert endpoint == "37.120.143.219"
        return {"latency_ms": 23, "status": "reachable", "method": "tcp"}

    monkeypatch.setattr(vpn_selection.shutil, "which", lambda _name: "/usr/bin/ping")
    monkeypatch.setattr(core, "command", command)
    monkeypatch.setattr(vpn_selection, "tcp_latency", tcp)

    result = asyncio.run(vpn_selection.measure_latency("37.120.143.219"))

    assert result == {"latency_ms": 23, "status": "reachable", "method": "tcp"}
