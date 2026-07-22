import asyncio

from exitlane.providers import nordvpn


def test_connect_response_is_machine_readable_and_hides_cli_output(monkeypatch):
    async def command(*args, **kwargs):
        return 0, "Connected to secret server", "internal stderr"

    monkeypatch.setattr(nordvpn, "command", command)
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
    response = asyncio.run(nordvpn.NordVPN().disconnect())
    assert response["state"] == "error"
    assert response["error_code"] == "provider_disconnect_failed"
    assert "/private/path" not in str(response)
