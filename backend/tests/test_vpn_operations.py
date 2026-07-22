import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import exitlane.main as main
from exitlane.providers.nordvpn import NordVPN
from exitlane.services import vpn_operations


@pytest.fixture(autouse=True)
def reset_operation():
    vpn_operations.reset_for_tests()


def request():
    return SimpleNamespace(state=SimpleNamespace(user={"id": 1, "username": "admin"}))


def test_conflicting_actions_are_rejected_with_current_operation():
    vpn_operations.begin("connecting", country_code="NL")

    response = asyncio.run(main.disconnect_vpn(request()))

    assert response.status_code == 409
    assert b'"error":"vpn_action_in_progress"' in response.body
    assert b'"state":"connecting"' in response.body
    assert b'"requested_country_code":"NL"' in response.body


def test_disconnected_snapshot_clears_stale_country_fields():
    snapshot = main._vpn_snapshot(
        {
            "available": True,
            "connected": False,
            "state": "disconnected",
            "country": "Netherlands",
            "city": "Amsterdam",
            "server": "nl987.nordvpn.com",
        }
    )

    assert snapshot["country_code"] is None
    assert snapshot["country"] is None
    assert snapshot["city"] is None
    assert snapshot["server"] is None


def test_nordvpn_uk_hostname_maps_to_catalogue_gb_code():
    snapshot = main._vpn_snapshot(
        {
            "available": True,
            "connected": True,
            "state": "connected",
            "country": "United Kingdom",
            "server": "uk2087.nordvpn.com",
        }
    )

    assert snapshot["country_code"] == "GB"
    assert snapshot["operation"]["state"] == "connected"


def test_recovery_is_limited_to_two_attempts_per_ten_minutes():
    started = datetime(2026, 1, 1, tzinfo=UTC)
    vpn_operations.record_recovery(started)
    vpn_operations.record_recovery(started + timedelta(minutes=1))

    assert vpn_operations.recovery_allowed(started + timedelta(minutes=9)) is False
    assert vpn_operations.recovery_allowed(started + timedelta(minutes=11)) is True


def test_daemon_recovery_uses_only_fixed_commands(monkeypatch):
    commands = []

    async def command(*args, timeout):
        commands.append((args, timeout))
        return 0, "active", ""

    async def status(_self, *, timeout):
        commands.append((("status",), timeout))
        return {"available": True, "state": "disconnected"}

    monkeypatch.setattr("exitlane.providers.nordvpn.command", command)
    monkeypatch.setattr(NordVPN, "status", status)

    result = asyncio.run(NordVPN().recover_daemon())

    assert result["ok"] is True
    assert commands == [
        (("/usr/bin/systemctl", "restart", "nordvpnd.service"), 15),
        (("/usr/bin/systemctl", "is-active", "nordvpnd.service"), 5),
        (("status",), 6),
    ]


def test_failed_recovery_healthcheck_is_not_success(monkeypatch):
    async def command(*_args, timeout):
        return 0, "active", ""

    async def status(_self, *, timeout):
        return {"available": False, "state": "error"}

    monkeypatch.setattr("exitlane.providers.nordvpn.command", command)
    monkeypatch.setattr(NordVPN, "status", status)

    result = asyncio.run(NordVPN().recover_daemon())

    assert result == {
        "ok": False,
        "error_code": "provider_recovery_healthcheck_failed",
        "status": {"available": False, "state": "error"},
    }


def test_non_timeout_failure_never_restarts_daemon(monkeypatch):
    async def catalog():
        return [{"id": 153, "country_code": "NL", "provider_name": "Netherlands"}]

    async def servers(_country_id):
        return []

    async def connect(_code, *, timeout):
        assert timeout == 40
        return {"ok": False, "exit_code": 1, "error_code": "provider_connect_failed"}

    async def status(*, timeout):
        assert timeout == 6
        return {"available": True, "connected": False, "state": "disconnected"}

    async def unexpected_recovery():
        pytest.fail("recovery must only run after a connect timeout")

    monkeypatch.setattr(main, "_vpn_catalog", catalog)
    monkeypatch.setattr(main.provider, "servers", servers)
    monkeypatch.setattr(main.provider, "connect_country", connect)
    monkeypatch.setattr(main.provider, "status", status)
    monkeypatch.setattr(main.provider, "recover_daemon", unexpected_recovery)
    monkeypatch.setattr(main, "select_server", lambda *_args: asyncio.sleep(0, result=None))
    monkeypatch.setattr(main, "country_summary", lambda *_args, **_kwargs: {"name": "Nederland"})
    monkeypatch.setattr(main, "record_event", lambda *_args, **_kwargs: None)

    result = asyncio.run(main.connect_vpn_country(main.CountryConnect(country_code="NL"), request()))

    assert result["success"] is False
    assert result["vpn"]["connected"] is False
    assert result["operation_state"] == "failed"


def test_timeout_recovers_and_retries_exactly_once(monkeypatch):
    connects = []
    recoveries = []
    events = []

    async def catalog():
        return [{"id": 153, "country_code": "NL", "provider_name": "Netherlands"}]

    async def servers(_country_id):
        return []

    async def connect(code, *, timeout):
        connects.append((code, timeout))
        if len(connects) == 1:
            return {"ok": False, "exit_code": 124, "error_code": "vpn_connect_timeout"}
        return {"ok": True, "exit_code": 0, "error_code": None}

    statuses = iter(
        [
            {"available": True, "connected": False, "state": "disconnected"},
            {
                "available": True,
                "connected": True,
                "state": "connected",
                "country": "Netherlands",
                "server": "nl987.nordvpn.com",
            },
        ]
    )

    async def status(*, timeout):
        assert timeout == 6
        return next(statuses)

    async def recover():
        recoveries.append(True)
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main, "_vpn_catalog", catalog)
    monkeypatch.setattr(main.provider, "servers", servers)
    monkeypatch.setattr(main.provider, "connect_country", connect)
    monkeypatch.setattr(main.provider, "status", status)
    monkeypatch.setattr(main.provider, "recover_daemon", recover)
    monkeypatch.setattr(main, "select_server", lambda *_args: asyncio.sleep(0, result=None))
    monkeypatch.setattr(main, "country_summary", lambda *_args, **_kwargs: {"name": "Nederland"})
    monkeypatch.setattr(
        main,
        "record_event",
        lambda code, **values: events.append((code, values)),
    )
    monkeypatch.setattr(main, "remember_country", lambda *_args: None)

    result = asyncio.run(main.connect_vpn_country(main.CountryConnect(country_code="NL"), request()))

    assert connects == [("NL", 40), ("NL", 40)]
    assert recoveries == [True]
    assert result["success"] is True
    assert result["recovered"] is True
    assert result["vpn"]["operation"]["state"] == "connected"
    assert [code for code, _values in events].count("provider.recovery_started") == 1
    assert [code for code, _values in events].count("provider.retry_started") == 1
