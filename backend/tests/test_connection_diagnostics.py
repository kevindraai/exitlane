import asyncio

import pytest

from exitlane.services import connection_diagnostics as diagnostics


@pytest.fixture(autouse=True)
def reset_runs():
    diagnostics.reset_for_tests()


def test_safe_manual_targets_reject_shell_and_option_injection():
    for value in ("; reboot", "-c 100 example.com", "name with spaces", ""):
        with pytest.raises(ValueError, match="invalid_diagnostic_target"):
            diagnostics._safe_target(value)
    assert diagnostics._safe_target("Example.COM.") == "example.com"
    assert diagnostics._safe_target("2001:db8::1") == "2001:db8::1"


def test_network_dns_ping_and_public_ip_results_are_structured(monkeypatch):
    async def fake_command(*args, timeout):
        del timeout
        if args[:3] == ("ip", "route", "get"):
            return 0, "1.1.1.1 via 192.0.2.1 dev nordlynx src 192.0.2.2", ""
        if args[:2] == ("getent", "ahosts"):
            return 0, "192.0.2.10 STREAM api.nordvpn.com\n", ""
        if args[0] == "ping":
            return 0, "64 bytes time=12.4 ms", ""
        if args[0] == "curl":
            return 0, "198.51.100.4", ""
        raise AssertionError(args)

    monkeypatch.setattr(diagnostics, "command", fake_command)
    network, dns, ping, public_ip = asyncio.run(
        _gather(
            diagnostics.probe_exitlane_network(),
            diagnostics.dns_lookup(),
            diagnostics.ping(),
            diagnostics.external_ip(),
        )
    )

    assert network == {
        "status": "passed",
        "code": "default_route_available",
        "detail": {"interface": "nordlynx"},
    }
    assert dns["detail"]["addresses"] == ["192.0.2.10"]
    assert ping["detail"]["latency_ms"] == 12.4
    assert public_ip["detail"]["address"] == "198.51.100.4"
    assert {item["status"] for item in (network, dns, ping, public_ip)} == {"passed"}


async def _gather(*tasks):
    return await asyncio.gather(*tasks)


def test_connection_run_exposes_pending_running_and_terminal_states(monkeypatch):
    gate = asyncio.Event()

    async def delayed_pass():
        await gate.wait()
        return diagnostics._result("passed", "ok")

    async def exercise():
        monkeypatch.setattr(diagnostics, "probe_exitlane_network", delayed_pass)
        monkeypatch.setattr(diagnostics, "probe_vpn_interface", lambda _status: delayed_pass())
        monkeypatch.setattr(diagnostics, "probe_vpn_handshake", lambda _status: delayed_pass())
        monkeypatch.setattr(diagnostics, "probe_vpn_route", lambda _status: delayed_pass())
        monkeypatch.setattr(diagnostics, "dns_lookup", delayed_pass)
        monkeypatch.setattr(diagnostics, "ping", delayed_pass)
        monkeypatch.setattr(diagnostics, "external_ip", delayed_pass)

        async def status():
            return {"connected": True, "technology": "NordLynx"}

        created = diagnostics.start(status)
        assert created["status"] == "pending"
        for _ in range(3):
            await asyncio.sleep(0)
            if diagnostics.snapshot(created["run_id"])["status"] == "running":
                break
        running = diagnostics.snapshot(created["run_id"])
        assert running["status"] == "running"
        assert {probe["status"] for probe in running["probes"]} == {"running"}
        gate.set()
        for _ in range(3):
            await asyncio.sleep(0)
        complete = diagnostics.snapshot(created["run_id"])
        assert complete["status"] == "passed"
        assert complete["completed_at"] is not None

    asyncio.run(exercise())


def test_speedtest_is_only_an_explicit_action(monkeypatch):
    calls = []

    async def explicit(**_confirmations):
        calls.append("speedtest")
        return diagnostics._result("warning", "speedtest_tool_unavailable")

    monkeypatch.setattr(diagnostics, "speedtest", explicit)
    result = asyncio.run(diagnostics.action("speedtest"))

    assert result["status"] == "warning"
    assert calls == ["speedtest"]


def test_run_stays_non_terminal_until_every_probe_finishes():
    assert (
        diagnostics._overall([{"status": "failed"}, {"status": "running"}, {"status": "pending"}])
        == "running"
    )
    assert diagnostics._overall([{"status": "failed"}, {"status": "pending"}]) == "pending"
    assert diagnostics._overall([{"status": "failed"}, {"status": "passed"}]) == "failed"
