import asyncio

import pytest

from exitlane.providers import nordvpn


def test_connect_response_is_machine_readable_and_hides_cli_output(monkeypatch):
    async def command(*args, **kwargs):
        return 0, "Connected to secret server", "internal stderr"

    monkeypatch.setattr(nordvpn, "command", command)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")
    response = asyncio.run(nordvpn.NordVPN().connect("NL"))
    assert response == {
        "ok": True,
        "action": "connect",
        "state": "connecting",
        "target": "NL",
        "exit_code": 0,
        "error_code": None,
    }
    assert "stdout" not in response
    assert "stderr" not in response


def test_disconnect_failure_has_safe_error_code(monkeypatch):
    async def command(*args, **kwargs):
        return 1, "", "/private/path: secret"

    monkeypatch.setattr(nordvpn, "command", command)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")
    response = asyncio.run(nordvpn.NordVPN().disconnect())
    assert response["state"] == "error"
    assert response["error_code"] == "provider_disconnect_failed"
    assert "/private/path" not in str(response)


def test_status_matches_connected_cli_output(monkeypatch):
    async def command(*args, **kwargs):
        if args == ("systemctl", "is-active", "nordvpnd"):
            return 0, "active", ""
        if args == ("nordvpn", "status"):
            return 0, """Status: Connected
Server: Belgium #255
Hostname: be255.nordvpn.com
IP: 164.5.253.223
Country: Belgium
City: Brussels
Current technology: NORDLYNX""", ""
        return 0, "Subscription: Active", ""

    monkeypatch.setattr(nordvpn, "command", command)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    status = asyncio.run(nordvpn.NordVPN().status())

    assert status["available"] is True
    assert status["connected"] is True
    assert status["server"] == "be255.nordvpn.com"
    assert status["country"] == "Belgium"


def test_actions_fail_safely_when_cli_is_outside_runtime(monkeypatch):
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: None)

    status = asyncio.run(nordvpn.NordVPN().status())
    connect = asyncio.run(nordvpn.NordVPN().connect("BE"))
    disconnect = asyncio.run(nordvpn.NordVPN().disconnect())

    assert status["available"] is False
    assert status["state"] == "unavailable"
    assert connect["error_code"] == "provider_cli_unavailable"
    assert disconnect["error_code"] == "provider_cli_unavailable"


@pytest.mark.parametrize(("country_code", "expected"), [("NL", "nl"), ("GB", "gb")])
def test_country_connect_target_is_lowercase_iso_code(country_code, expected):
    assert nordvpn.build_connect_target(country_code) == expected


def test_explicit_server_hostname_is_converted_to_compact_identifier():
    assert nordvpn.build_connect_target("NL", "nl1155.nordvpn.com") == "nl1155"


@pytest.mark.parametrize(
    "hostname",
    ["example.com", "nl.nordvpn.com", "nl1155.evil.example", "nl1155.nordvpn.com; reboot"],
)
def test_invalid_explicit_server_hostnames_are_rejected(hostname):
    with pytest.raises(ValueError):
        nordvpn.build_connect_target("NL", hostname)


def test_arbitrary_country_connect_arguments_are_rejected():
    with pytest.raises(ValueError):
        nordvpn.build_connect_target("NL; reboot")


def test_country_connection_never_passes_hostname_to_cli(monkeypatch):
    commands = []

    async def command(*args, **kwargs):
        commands.append(args)
        return 0, "Connected", ""

    monkeypatch.setattr(nordvpn, "command", command)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    response = asyncio.run(nordvpn.NordVPN().connect_country("NL"))

    connect_command = commands[0]
    assert connect_command == ("nordvpn", "connect", "nl")
    assert ".nordvpn.com" not in connect_command
    assert response["exit_code"] == 0


def test_native_connect_rejects_full_hostname_before_command(monkeypatch):
    async def command(*args, **kwargs):
        raise AssertionError("invalid target must not execute")

    monkeypatch.setattr(nordvpn, "command", command)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    response = asyncio.run(nordvpn.NordVPN().connect("nl1155.nordvpn.com"))

    assert response["ok"] is False
    assert response["error_code"] == "invalid_target"
