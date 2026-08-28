import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from exitlane import main
from exitlane.providers.nordvpn import NordVPN
from exitlane.services import vpn_operations


@pytest.fixture(autouse=True)
def reset_operation():
    vpn_operations.reset_for_tests()


def request():
    return SimpleNamespace(state=SimpleNamespace(user={"id": 1, "username": "admin"}))


def test_conflicting_actions_are_rejected_with_current_operation(monkeypatch):
    async def unexpected_provider_call(*_args, **_kwargs):
        pytest.fail("provider status or command must not run for an operation conflict")

    monkeypatch.setattr(main, "_fresh_vpn_status", unexpected_provider_call)
    monkeypatch.setattr(main.provider, "disconnect", unexpected_provider_call)
    vpn_operations.begin("connecting", country_code="NL")

    response = asyncio.run(main.disconnect_vpn(request()))

    assert response.status_code == 409
    assert b'"error":"vpn_action_in_progress"' in response.body
    assert b'"state":"connecting"' in response.body
    assert b'"requested_country_code":"NL"' in response.body
    assert b"token" not in response.body.lower()
    assert b"secret" not in response.body.lower()


@pytest.mark.parametrize(
    ("name", "action"),
    [
        (
            "connect",
            lambda: main.connect_nordvpn(main.Connect(target=None), request()),
        ),
        (
            "reconnect",
            lambda: main.connect_nordvpn(main.Connect(target="recommended"), request()),
        ),
        (
            "location",
            lambda: main.connect_vpn_country(main.CountryConnect(country_code="NL"), request()),
        ),
        ("disconnect", lambda: main.disconnect_vpn(request())),
    ],
)
def test_all_vpn_mutations_claim_before_provider_preconditions(monkeypatch, name, action):
    calls = []

    async def unexpected_provider_call(*_args, **_kwargs):
        calls.append(name)
        pytest.fail("provider work must not run for an operation conflict")

    monkeypatch.setattr(main, "_fresh_vpn_status", unexpected_provider_call)
    monkeypatch.setattr(main, "_vpn_catalog", unexpected_provider_call)
    monkeypatch.setattr(main.provider, "connect", unexpected_provider_call)
    monkeypatch.setattr(main.provider, "connect_country", unexpected_provider_call)
    monkeypatch.setattr(main.provider, "disconnect", unexpected_provider_call)
    monkeypatch.setattr(main.provider, "servers", unexpected_provider_call)
    vpn_operations.begin("connecting", country_code="BE")

    response = asyncio.run(action())

    assert response.status_code == 409
    assert b'"error":"vpn_action_in_progress"' in response.body
    assert b'"requested_country_code":"BE"' in response.body
    assert calls == []


def test_latency_measurement_does_not_conflict_with_connect(monkeypatch):
    async def authenticated(_provider=None):
        return {"authenticated": True, "connected": False}

    async def catalog(_provider=None):
        return [{"id": 153, "country_code": "NL", "provider_name": "Netherlands"}]

    async def servers(_country_id):
        return [{"hostname": "nl1.nordvpn.com", "station": "192.0.2.1"}]

    async def measured(_code, _servers, *, force, provider_id):
        assert force is True
        assert provider_id == "nordvpn"
        return [{"server": "nl1.nordvpn.com", "latency_ms": 12}]

    monkeypatch.setattr(main, "_require_provider_authentication", authenticated)
    monkeypatch.setattr(main, "_vpn_catalog", catalog)
    monkeypatch.setattr(main.provider, "servers", servers)
    monkeypatch.setattr(main, "measure_servers", measured)
    monkeypatch.setattr(main, "country_summary", lambda *_args, **_kwargs: {"latency_ms": 12})
    vpn_operations.begin("connecting", country_code="BE")

    result = asyncio.run(main.measure_vpn_country("NL"))

    assert result["latency_ms"] == 12
    assert vpn_operations.snapshot()["state"] == "connecting"


@pytest.mark.parametrize(
    ("authentication_state", "expected_error"),
    [
        ("unknown", "provider_state_unknown"),
        ("signed_out", "provider_authentication_required"),
    ],
)
def test_failed_provider_precondition_releases_operation_claim(
    monkeypatch, authentication_state, expected_error
):
    async def provider_state():
        return {
            "authenticated": authentication_state == "signed_in",
            "installed": True,
            "connected": False,
            "management": {
                "authentication": {"state": authentication_state},
            },
        }

    monkeypatch.setattr(main, "_fresh_vpn_status", provider_state)

    with pytest.raises(main.HTTPException) as error:
        asyncio.run(main.disconnect_vpn(request()))

    assert error.value.detail == expected_error
    assert vpn_operations.snapshot()["state"] not in vpn_operations.ACTIVE_STATES
    vpn_operations.begin("disconnecting")


def test_valid_action_can_start_after_failed_provider_precondition(monkeypatch):
    statuses = iter(
        [
            {
                "installed": True,
                "authenticated": False,
                "connected": False,
                "management": {"authentication": {"state": "unknown"}},
            },
            {
                "installed": True,
                "authenticated": True,
                "connected": True,
                "management": {"authentication": {"state": "signed_in"}},
            },
            {
                "installed": True,
                "authenticated": True,
                "connected": False,
                "management": {"authentication": {"state": "signed_in"}},
            },
        ]
    )

    async def provider_state():
        return next(statuses)

    async def disconnect(*, timeout):
        assert timeout == 15
        return {"ok": True}

    monkeypatch.setattr(main, "_fresh_vpn_status", provider_state)
    monkeypatch.setattr(main.provider, "disconnect", disconnect)
    monkeypatch.setattr(main, "record_event", lambda *_args, **_kwargs: None)

    with pytest.raises(main.HTTPException):
        asyncio.run(main.disconnect_vpn(request()))
    result = asyncio.run(main.disconnect_vpn(request()))

    assert result["success"] is True
    assert result["operation_state"] == "idle"


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


def test_snapshot_uses_country_code_normalized_by_provider_boundary():
    snapshot = main._vpn_snapshot(
        {
            "available": True,
            "connected": True,
            "state": "connected",
            "country": "United Kingdom",
            "country_code": "GB",
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


def test_connection_states_are_isolated_and_stale_selection_is_ignored():
    vpn_operations.begin("connecting", country_code="NL")
    first = vpn_operations.begin_selection("NL")
    second = vpn_operations.begin_selection("BE")

    assert vpn_operations.finish_selection(first, server="nl1.nordvpn.com") is False
    assert vpn_operations.finish_selection(second, server="be1.nordvpn.com", fallback=True) is True
    assert vpn_operations.snapshot()["selection"] == {
        "state": "fallback",
        "country_code": "BE",
        "server": "be1.nordvpn.com",
        "generation": second,
    }

    vpn_operations.begin("connecting", connection_id="wireguard:branch-office")
    assert vpn_operations.snapshot()["requested_country_code"] == "NL"
    assert vpn_operations.snapshot("wireguard:branch-office")["kind"] == "wireguard"
    assert len(vpn_operations.snapshots()) == 2


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
    async def catalog(_provider=None):
        return [{"id": 153, "country_code": "NL", "provider_name": "Netherlands"}]

    async def servers(_country_id):
        return []

    async def connect(_code, *, timeout, server_hostname=None):
        assert timeout == 40
        return {"ok": False, "exit_code": 1, "error_code": "provider_connect_failed"}

    async def status(*, timeout):
        assert timeout == 6
        return {
            "available": True,
            "authenticated": True,
            "connected": False,
            "state": "disconnected",
        }

    async def unexpected_recovery():
        pytest.fail("recovery must only run after a connect timeout")

    monkeypatch.setattr(main, "_vpn_catalog", catalog)
    monkeypatch.setattr(main.provider, "servers", servers)
    monkeypatch.setattr(main.provider, "connect_country", connect)
    monkeypatch.setattr(main.provider, "status", status)
    monkeypatch.setattr(main.provider, "recover_daemon", unexpected_recovery)
    monkeypatch.setattr(
        main, "select_server", lambda *_args, **_kwargs: asyncio.sleep(0, result=None)
    )
    monkeypatch.setattr(main, "country_summary", lambda *_args, **_kwargs: {"name": "Nederland"})
    monkeypatch.setattr(main, "record_event", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        main.connect_vpn_country(main.CountryConnect(country_code="NL"), request())
    )

    assert result["success"] is False
    assert result["vpn"]["connected"] is False
    assert result["operation_state"] == "failed"


def test_timeout_recovers_and_retries_exactly_once(monkeypatch):
    connects = []
    recoveries = []
    events = []

    async def catalog(_provider=None):
        return [{"id": 153, "country_code": "NL", "provider_name": "Netherlands"}]

    async def servers(_country_id):
        return []

    async def connect(code, *, timeout, server_hostname=None):
        connects.append((code, timeout))
        if len(connects) == 1:
            return {"ok": False, "exit_code": 124, "error_code": "vpn_connect_timeout"}
        return {"ok": True, "exit_code": 0, "error_code": None}

    statuses = iter(
        [
            {
                "available": True,
                "authenticated": True,
                "connected": False,
                "state": "disconnected",
            },
            {
                "available": True,
                "authenticated": True,
                "connected": False,
                "state": "disconnected",
            },
            {
                "available": True,
                "authenticated": True,
                "connected": False,
                "state": "disconnected",
            },
            {
                "available": True,
                "authenticated": True,
                "connected": True,
                "state": "connected",
                "country": "Netherlands",
                "country_code": "NL",
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
    monkeypatch.setattr(
        main, "select_server", lambda *_args, **_kwargs: asyncio.sleep(0, result=None)
    )
    monkeypatch.setattr(main, "country_summary", lambda *_args, **_kwargs: {"name": "Nederland"})
    monkeypatch.setattr(
        main,
        "record_event",
        lambda code, **values: events.append((code, values)),
    )
    monkeypatch.setattr(main, "remember_country", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        main.connect_vpn_country(main.CountryConnect(country_code="NL"), request())
    )

    assert connects == [("NL", 40), ("NL", 40)]
    assert recoveries == [True]
    assert result["success"] is True
    assert result["recovered"] is True
    assert result["vpn"]["operation"]["state"] == "connected"
    assert [code for code, _values in events].count("provider.recovery_started") == 1
    assert [code for code, _values in events].count("provider.retry_started") == 1
