import asyncio
from types import SimpleNamespace

import pytest

from exitlane import main


@pytest.fixture(autouse=True)
def reset_vpn_operation():
    main.vpn_operations.reset_for_tests()


def request():
    return SimpleNamespace(state=SimpleNamespace(user={"id": 1, "username": "admin"}))


def configure(monkeypatch, *, status, selection=None):
    calls = []
    events = []

    async def catalog(_provider=None):
        return [{"id": 153, "country_code": "NL", "provider_name": "Netherlands"}]

    async def servers(_country_id):
        return [{"hostname": "nl1155.nordvpn.com", "station": "192.0.2.1"}]

    async def connect_country(country_code, **_kwargs):
        calls.append(country_code)
        return {
            "ok": True,
            "action": "connect",
            "state": "connecting",
            "target": country_code.lower(),
            "exit_code": 0,
            "error_code": None,
        }

    async def provider_status(**_kwargs):
        return status

    async def select(_code, _servers, **_options):
        return selection or {"server": "nl1155.nordvpn.com", "latency_ms": 17}

    monkeypatch.setattr(main, "_vpn_catalog", catalog)
    monkeypatch.setattr(main.provider, "servers", servers)
    monkeypatch.setattr(main.provider, "connect_country", connect_country)
    monkeypatch.setattr(main.provider, "status", provider_status)
    monkeypatch.setattr(main, "select_server", select)
    monkeypatch.setattr(
        main,
        "server_latency",
        lambda server, **_options: {
            "latency_ms": 31 if server == status.get("server") else None,
            "latency_measured_at": "measured" if server == status.get("server") else None,
        },
    )
    monkeypatch.setattr(main, "country_summary", lambda *args, **kwargs: {"name": "Nederland"})
    monkeypatch.setattr(
        main, "remember_country", lambda code, **_options: calls.append(f"remember:{code}")
    )
    monkeypatch.setattr(main, "record_event", lambda code, **values: events.append((code, values)))
    return calls, events


def test_success_requires_status_and_reports_actual_server(monkeypatch):
    calls, events = configure(
        monkeypatch,
        status={
            "available": True,
            "authenticated": True,
            "connected": True,
            "country": "Netherlands",
            "country_code": "NL",
            "city": "Amsterdam",
            "server": "nl987.nordvpn.com",
        },
    )

    result = asyncio.run(
        main.connect_vpn_country(main.CountryConnect(country_code="NL"), request())
    )

    assert calls == ["NL", "remember:NL"]
    assert result["success"] is True
    assert result["server"] == "nl987.nordvpn.com"
    assert result["latency_ms"] == 31
    assert result["vpn"]["latency_ms"] == 31
    assert events[0][0] == "provider.connect_started"
    assert events[0][1]["metadata"]["target"] == "Nederland"
    assert events[-1][0] == "provider.connected"
    assert events[-1][1]["metadata"]["server"] == "nl987.nordvpn.com"


def test_reconnect_returns_latency_for_fresh_actual_server(monkeypatch):
    monkeypatch.setattr(main, "setting", lambda *_args: "nordvpn")
    configure(
        monkeypatch,
        status={
            "available": True,
            "authenticated": True,
            "connected": True,
            "country": "Netherlands",
            "country_code": "NL",
            "city": "Amsterdam",
            "server": "nl999.nordvpn.com",
        },
    )

    result = asyncio.run(
        main.reconnect_vpn_provider(
            "nordvpn",
            main.ProviderReconnect(country_code="NL"),
            request(),
        )
    )

    assert result["success"] is True
    assert result["server"] == "nl999.nordvpn.com"
    assert result["latency_ms"] == 31
    assert result["vpn"]["latency_ms"] == 31


def test_exit_zero_without_connected_status_is_failure(monkeypatch):
    calls, events = configure(
        monkeypatch,
        status={
            "available": True,
            "authenticated": True,
            "connected": False,
            "country": "",
            "server": "",
        },
    )

    result = asyncio.run(
        main.connect_vpn_country(main.CountryConnect(country_code="NL"), request())
    )

    assert calls == ["NL"]
    assert result["success"] is False
    assert result["status"] == "error"
    assert result["error_code"] == "not_connected"
    assert events[-1][0] == "provider.connect_failed"
    assert events[-1][1]["metadata"]["reason"] == "not_connected"


def test_connect_waits_for_pending_selection_and_uses_latency_fallback(monkeypatch):
    calls, _events = configure(
        monkeypatch,
        status={
            "available": True,
            "authenticated": True,
            "connected": True,
            "country": "Netherlands",
            "country_code": "NL",
            "city": "Amsterdam",
            "server": "nl987.nordvpn.com",
        },
        selection={
            "server": "nl1155.nordvpn.com",
            "latency_ms": None,
            "status": "unknown",
        },
    )

    result = asyncio.run(
        main.connect_vpn_country(main.CountryConnect(country_code="NL"), request())
    )

    assert result["success"] is True
    assert calls == ["NL", "remember:NL"]
    assert result["vpn"]["operation"]["selection"]["state"] == "fallback"
