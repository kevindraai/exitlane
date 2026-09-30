import asyncio
import sqlite3

import pytest

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


def test_deleted_server_is_not_selected_from_latency_cache(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)

    async def measure(_hostname):
        return {"latency_ms": 12, "status": "reachable"}

    asyncio.run(
        vpn_selection.measure_servers(
            "NL",
            [{"hostname": "removed.example"}],
            provider_id="proton",
            measurer=measure,
        )
    )
    monkeypatch.setattr(vpn_selection, "measure_latency", measure)
    selected = asyncio.run(
        vpn_selection.select_server(
            "NL",
            [{"hostname": "remaining.example", "station": "185.1.2.3"}],
            provider_id="proton",
        )
    )
    assert selected["server"] == "remaining.example"


def test_new_server_is_measured_when_cached_country_is_incomplete(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)
    calls = []

    async def measure(hostname):
        calls.append(hostname)
        return {
            "latency_ms": {"old.example": 30, "new.example": 10}[hostname],
            "status": "reachable",
        }

    asyncio.run(
        vpn_selection.measure_servers(
            "NL",
            [{"hostname": "old.example"}],
            provider_id="proton",
            measurer=measure,
        )
    )
    result = asyncio.run(
        vpn_selection.measure_servers(
            "NL",
            [{"hostname": "old.example"}, {"hostname": "new.example"}],
            provider_id="proton",
            measurer=measure,
        )
    )
    assert result[0]["server"] == "new.example"
    assert "new.example" in calls


def test_unreachable_candidates_fall_back_to_provider_recommendation(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)

    async def unreachable(_hostname):
        return {"latency_ms": None, "status": "unreachable"}

    monkeypatch.setattr(vpn_selection, "measure_latency", unreachable)
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


def test_exact_normalized_server_latency_is_used_without_country_substitution(
    tmp_path, monkeypatch
):
    initialise_database(tmp_path, monkeypatch)
    measured_at = vpn_selection._now().isoformat()
    with sqlite3.connect(core.DB) as connection:
        connection.executemany(
            """INSERT INTO vpn_latency_cache
               (provider, country_code, server, latency_ms, status, measured_at)
               VALUES ('nordvpn', 'FR', ?, ?, 'reachable', ?)""",
            [
                ("FR825.NORDVPN.COM.", 27, measured_at),
                ("fr900.nordvpn.com", 11, measured_at),
            ],
        )

    assert vpn_selection.server_latency("  fr825.nordvpn.com  ")["latency_ms"] == 27
    assert vpn_selection.server_latency("fr825.nordvpn.com.")["latency_ms"] == 27
    assert vpn_selection.server_latency("fr825")["latency_ms"] is None
    assert vpn_selection.server_latency("fr901.nordvpn.com")["latency_ms"] is None


def test_active_server_measurement_is_deduplicated_and_persisted(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)
    calls = []
    release = asyncio.Event()

    async def measure(hostname):
        calls.append(hostname)
        await release.wait()
        return {"latency_ms": 23, "status": "reachable", "method": "tcp"}

    async def run():
        first = asyncio.create_task(
            vpn_selection.ensure_active_server_latency(" FR825.NORDVPN.COM. ", measurer=measure)
        )
        second = asyncio.create_task(
            vpn_selection.ensure_active_server_latency("fr825.nordvpn.com", measurer=measure)
        )
        await asyncio.sleep(0)
        release.set()
        return await asyncio.gather(first, second)

    results = asyncio.run(run())

    assert calls == ["fr825.nordvpn.com"]
    assert [item["latency_ms"] for item in results] == [23, 23]
    assert vpn_selection.server_latency("fr825.nordvpn.com")["latency_ms"] == 23


def test_failed_active_server_measurement_is_cached_as_optional_telemetry(tmp_path, monkeypatch):
    initialise_database(tmp_path, monkeypatch)
    calls = []

    async def unreachable(hostname):
        calls.append(hostname)
        return {"latency_ms": None, "status": "unreachable", "method": "tcp"}

    first = asyncio.run(
        vpn_selection.ensure_active_server_latency("fr825.nordvpn.com", measurer=unreachable)
    )
    second = asyncio.run(
        vpn_selection.ensure_active_server_latency("fr825.nordvpn.com", measurer=unreachable)
    )

    assert first["latency_ms"] is None
    assert first["latency_measured_at"] is not None
    assert second == first
    assert calls == ["fr825.nordvpn.com"]


def test_icmp_latency_uses_median_without_dns_lookup(monkeypatch):
    calls = []

    async def command(*args, **kwargs):
        calls.append(args)
        return (
            0,
            """64 bytes: time=21.4 ms
64 bytes: time=19.4 ms
64 bytes: time=20.6 ms""",
            "",
        )

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


@pytest.mark.parametrize(
    "endpoint",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "ff02::1",
        "2606:4700:4700::1111%eth0",
        None,
    ],
)
def test_non_global_literal_latency_endpoint_is_not_executed(monkeypatch, endpoint):
    async def command(*_args, **_kwargs):
        raise AssertionError("must not execute")

    async def tcp(*_args, **_kwargs):
        raise AssertionError("must not connect")

    monkeypatch.setattr(core, "command", command)
    monkeypatch.setattr(vpn_selection, "tcp_latency", tcp)

    assert asyncio.run(vpn_selection.measure_latency(endpoint)) == {
        "latency_ms": None,
        "status": "unknown",
        "method": None,
    }


def test_hostname_latency_resolves_only_public_ipv4(monkeypatch):
    calls = []

    async def run_resolver(function, *args):
        return function(*args)

    def resolve(host, port, family, kind):
        assert (host, port, family, kind) == (
            "nl.protonvpn.example",
            None,
            vpn_selection.socket.AF_INET,
            vpn_selection.socket.SOCK_DGRAM,
        )
        return [(family, kind, 0, "", ("185.1.2.3", 0))]

    async def command(*args, **_kwargs):
        calls.append(args)
        return 0, "64 bytes: time=17.2 ms", ""

    monkeypatch.setattr(vpn_selection.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(vpn_selection.asyncio, "to_thread", run_resolver)
    monkeypatch.setattr(vpn_selection.shutil, "which", lambda _name: "/usr/bin/ping")
    monkeypatch.setattr(core, "command", command)
    result = asyncio.run(vpn_selection.measure_latency("nl.protonvpn.example"))
    assert result["latency_ms"] == 17
    assert calls[0][-1] == "185.1.2.3"

    monkeypatch.setattr(
        vpn_selection.socket,
        "getaddrinfo",
        lambda *_args: [
            (vpn_selection.socket.AF_INET, vpn_selection.socket.SOCK_DGRAM, 0, "", ("10.0.0.1", 0))
        ],
    )
    assert asyncio.run(vpn_selection.measure_latency("nl.protonvpn.example"))["status"] == "unknown"
    assert len(calls) == 1


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
