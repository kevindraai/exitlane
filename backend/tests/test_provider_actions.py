import asyncio

from exitlane.providers import nordvpn


def test_connect_response_is_machine_readable_and_hides_cli_output(monkeypatch):
    async def command(*args, **kwargs):
        return 0, "Connected to secret server", "internal stderr"

    monkeypatch.setattr(nordvpn, "command", command)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")
    response = asyncio.run(nordvpn.NordVPN().connect("Netherlands"))
    assert response == {
        "ok": True,
        "action": "connect",
        "state": "connecting",
        "target": "Netherlands",
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
