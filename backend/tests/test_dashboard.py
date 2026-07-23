from datetime import datetime, timedelta, timezone

from exitlane.services.dashboard import (
    DashboardResponse,
    SystemStatus,
    VPNStatus,
    WireGuardStatus,
    build_dashboard,
    determine_health,
    system_status,
)


def system(memory=20.0, disk=20.0):
    return SystemStatus(
        hostname="exitlane-test",
        cpu_percent=5.0,
        memory_percent=memory,
        memory_used_bytes=20,
        memory_total_bytes=100,
        disk_percent=disk,
        disk_used_bytes=20,
        disk_total_bytes=100,
        uptime_seconds=100,
        load_average=(0.1, 0.2, 0.3),
    )


def test_health_is_healthy_when_all_explicit_statuses_are_good():
    now = datetime.now(timezone.utc)
    result = determine_health(
        VPNStatus(available=True, connected=True),
        WireGuardStatus(
            available=True,
            configured=True,
            active=True,
            connected=True,
            latest_handshake_at=now - timedelta(seconds=10),
        ),
        system(),
        now,
    )
    assert result.status == "healthy"
    assert result.issues == []


def test_health_warns_for_disconnected_vpn_stale_handshake_and_resources():
    now = datetime.now(timezone.utc)
    result = determine_health(
        VPNStatus(available=True, connected=False),
        WireGuardStatus(available=True, configured=True, active=True),
        system(memory=90, disk=90),
        now,
    )
    assert result.status == "warning"
    assert result.issues == [
        "vpn_disconnected",
        "wireguard_handshake_stale",
        "disk_usage_high",
        "memory_usage_high",
    ]


def test_health_errors_for_inactive_configured_wireguard_and_critical_disk():
    result = determine_health(
        VPNStatus(available=True, connected=True),
        WireGuardStatus(available=True, configured=True, active=False),
        system(disk=96),
    )
    assert result.status == "error"
    assert result.issues == ["wireguard_inactive", "disk_usage_critical"]


def test_health_thresholds_are_exact():
    vpn = VPNStatus(available=True, connected=True)
    now = datetime.now(timezone.utc)
    wireguard = WireGuardStatus(
        available=True,
        configured=True,
        active=True,
        connected=True,
        latest_handshake_at=now,
    )
    assert determine_health(vpn, wireguard, system(memory=84.9, disk=84.9), now).status == "healthy"
    assert determine_health(vpn, wireguard, system(memory=85, disk=84.9), now).issues == [
        "memory_usage_high"
    ]
    assert determine_health(vpn, wireguard, system(memory=20, disk=85), now).issues == [
        "disk_usage_high"
    ]
    assert determine_health(vpn, wireguard, system(memory=20, disk=95), now).issues == [
        "disk_usage_critical"
    ]


def test_error_has_priority_and_keeps_multiple_stable_issue_codes():
    result = determine_health(
        VPNStatus(available=False),
        WireGuardStatus(available=True, configured=True, active=False),
        system(memory=90, disk=96),
    )
    assert result.status == "error"
    assert result.issues == [
        "wireguard_inactive",
        "disk_usage_critical",
        "vpn_status_unavailable",
        "memory_usage_high",
    ]


def test_provider_unavailable_is_warning_without_internal_details():
    result = determine_health(
        VPNStatus(available=False, error="provider_status_unavailable"),
        WireGuardStatus(available=False, error="wireguard_status_unavailable"),
        system(),
    )
    assert result.status == "error"
    assert result.issues == ["multiple_status_sources_unavailable"]


def test_dashboard_keeps_partial_provider_failure_available(monkeypatch):
    import asyncio

    async def failed_provider():
        raise RuntimeError("secret command output")

    async def wireguard():
        return {"configured": True, "active": True, "connected": False, "peers": []}

    async def fake_system():
        return system()

    monkeypatch.setattr("exitlane.services.dashboard.system_status", fake_system)
    response = asyncio.run(build_dashboard(failed_provider, wireguard, "1.2.3"))
    assert isinstance(response, DashboardResponse)
    assert response.vpn.available is False
    assert response.vpn.error == "provider_status_unavailable"
    assert "secret" not in response.model_dump_json()


def test_dashboard_preserves_ipv6_long_values_and_uses_first_of_multiple_peers(monkeypatch):
    import asyncio

    long_server = "server-" + "x" * 300
    ipv6_endpoint = "[2001:db8:85a3::8a2e:370:7334]:51820"

    async def provider():
        return {"connected": True, "server": long_server, "external_ip": "2001:db8::1"}

    async def wireguard():
        return {
            "configured": True,
            "active": True,
            "connected": True,
            "latest_handshake": 1,
            "peers": [
                {"endpoint": ipv6_endpoint, "received_bytes": 10, "sent_bytes": 20},
                {"endpoint": "second.example:51820", "received_bytes": 30, "sent_bytes": 40},
            ],
        }

    async def fake_system():
        return system()

    response = asyncio.run(build_dashboard(provider, wireguard, "1", fake_system))
    assert response.vpn.server == long_server
    assert response.vpn.external_ip == "2001:db8::1"
    assert response.wireguard.peer_count == 2
    assert response.wireguard.endpoint == ipv6_endpoint
    assert response.wireguard.received_bytes == 10


def test_system_failure_returns_explicit_null_metrics_without_leaking_details():
    import asyncio

    async def provider():
        return {"connected": True}

    async def wireguard():
        return {"configured": True, "active": True, "connected": False, "peers": []}

    async def failed_system():
        raise OSError("/secret/filesystem/path")

    response = asyncio.run(build_dashboard(provider, wireguard, "1", failed_system))
    assert response.system.available is False
    assert response.system.memory_percent is None
    assert response.system.disk_total_bytes is None
    assert response.system.uptime_seconds is None
    assert response.system.temperature_celsius is None
    assert "/secret" not in response.model_dump_json()


def test_dashboard_timestamps_are_timezone_aware_iso_8601(monkeypatch):
    import asyncio

    async def provider():
        return {"connected": True}

    async def wireguard():
        return {"active": True, "latest_handshake": 1, "peers": []}

    async def fake_system():
        return system()

    response = asyncio.run(build_dashboard(provider, wireguard, "1", fake_system))
    assert response.generated_at.utcoffset() == timedelta(0)
    payload = response.model_dump_json()
    assert '"generated_at":"' in payload
    assert 'Z"' in payload


def test_system_status_tolerates_missing_proc_fields_and_uses_requested_filesystem(monkeypatch):
    import asyncio
    from collections import namedtuple
    from pathlib import Path

    seen = []
    usage = namedtuple("usage", "total used free")

    def read_text(path, *args, **kwargs):
        if str(path) == "/proc/stat":
            return "cpu  malformed\n"
        raise OSError("missing proc field")

    def disk_usage(path):
        seen.append(path)
        return usage(100, 25, 75)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr("exitlane.services.dashboard.shutil.disk_usage", disk_usage)
    monkeypatch.setattr(
        "exitlane.services.dashboard.os.getloadavg", lambda: (_ for _ in ()).throw(OSError())
    )
    requested = Path("/var/lib/exitlane")
    result = asyncio.run(system_status(requested))
    assert seen == [requested]
    assert result.cpu_percent is None
    assert result.memory_percent is None
    assert result.uptime_seconds is None
    assert result.load_average is None
    assert result.disk_percent == 25.0
    assert result.temperature_celsius is None


def test_wireguard_internal_error_message_is_replaced_with_stable_code():
    import asyncio

    async def provider():
        return {"connected": True}

    async def wireguard():
        return {"active": False, "message": "/secret/path: permission denied"}

    async def fake_system():
        return system()

    response = asyncio.run(build_dashboard(provider, wireguard, "1", fake_system))
    assert response.wireguard.error == "wireguard_inactive"
    assert "/secret" not in response.model_dump_json()
