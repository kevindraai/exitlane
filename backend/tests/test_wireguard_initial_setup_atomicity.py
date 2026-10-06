"""The first ingress must have a retriable pre-migration state after failure."""

import asyncio
import os
import sqlite3
from dataclasses import replace

import pytest

from exitlane import core, main
from exitlane.services import wireguard, wireguard_peers


@pytest.fixture
def isolated_setup(tmp_path, monkeypatch, synthetic_wireguard_keys):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    wg_dir = data / "wireguard"
    for module in (core, main):
        monkeypatch.setattr(module, "DB", database)
        monkeypatch.setattr(module, "WG_DIR", wg_dir)
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(wireguard, "WG_DIR", wg_dir)
    monkeypatch.setattr(main, "_wireguard_generation_lock", None)
    core.init()

    async def activate(_interface):
        return None

    async def command(*args, **_kwargs):
        if args[:3] == ("ip", "link", "show"):
            return 1, "", "Device not found"
        return 0, "", ""

    async def reconcile():
        return None

    monkeypatch.setattr(main, "activate_wireguard_interface", activate)
    monkeypatch.setattr(main, "command", command)
    monkeypatch.setattr(main, "_reconcile_management_routes_or_503", activate)
    monkeypatch.setattr(main.management_routing, "reconcile", reconcile)
    monkeypatch.setattr(main, "record_event", lambda *_args, **_kwargs: None)
    return database, wg_dir


def _request():
    return main.WireGuard(
        endpoint="192.0.2.10",
        subnet="10.90.0.0/24",
        dns="1.1.1.1",
        port=51820,
        interface="wg0",
        client="router",
    )


def _http_request():
    return main.Request({"type": "http", "method": "POST", "path": "/api/ingress/wireguard"})


def _assert_original(database, wg_dir):
    assert core.setting("wireguard_configured", False) is False
    assert not (wg_dir / "wg0.conf").exists()
    assert not (wg_dir / "router.conf").exists()
    assert not main._initial_wireguard_journal().exists()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM wireguard_ingress_profile").fetchone()[0] == 0
        )


@pytest.mark.parametrize("failure", ["activate", "settings", "routes"])
def test_initial_setup_failure_rolls_back_every_stage(isolated_setup, monkeypatch, failure):
    database, wg_dir = isolated_setup
    if failure == "activate":

        async def fail(_interface):
            raise RuntimeError("synthetic private activation failure")

        monkeypatch.setattr(main, "activate_wireguard_interface", fail)
    elif failure == "settings":

        def fail(_values):
            raise core.SettingsStorageError("synthetic storage failure")

        monkeypatch.setattr(main, "set_settings", fail)
    else:

        async def fail(_actor):
            raise main.HTTPException(status_code=503, detail="management_routing_failed")

        monkeypatch.setattr(main, "_reconcile_management_routes_or_503", fail)

    with pytest.raises((main.HTTPException, core.SettingsStorageError)) as error:
        asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    assert "synthetic private" not in str(error.value)
    _assert_original(database, wg_dir)


def test_initial_setup_success_preserves_identity_and_rejects_duplicate(isolated_setup):
    database, wg_dir = isolated_setup
    result = asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    server = (wg_dir / "wg0.conf").read_bytes()
    client = (wg_dir / "router.conf").read_bytes()
    peer = wireguard_peers.list_peers()[0]
    assert result["client_config"].encode() == client
    assert peer["is_default"] == 1
    assert core.setting("wireguard_configured") is True
    assert not main._initial_wireguard_journal().exists()
    retry = asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    assert retry.status_code == 409
    assert len(wireguard_peers.list_peers()) == 1
    assert (wg_dir / "wg0.conf").read_bytes() == server
    assert (wg_dir / "router.conf").read_bytes() == client
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0] == 1


@pytest.mark.parametrize("committed", [False, True])
def test_startup_recovers_interrupted_initial_setup(isolated_setup, committed):
    database, wg_dir = isolated_setup
    journal = {
        "interface": "wg0",
        "client": "router",
        "subnet": "10.90.0.0/24",
        "activation_attempted": False,
        "settings": {},
        "phase": "committed" if committed else "pending",
    }
    main._write_initial_wireguard_journal(journal)
    asyncio.run(
        wireguard.create(
            endpoint="192.0.2.10",
            subnet="10.90.0.0/24",
            dns="1.1.1.1",
            interface="wg0",
            client="router",
        )
    )
    asyncio.run(wireguard_peers.migrate_legacy("wg0", "router"))
    if committed:
        core.set_settings(
            {
                "wireguard_configured": True,
                "wireguard_interface": "wg0",
                "wireguard_client_name": "router",
                "wireguard_subnet": "10.90.0.0/24",
            }
        )
        server = (wg_dir / "wg0.conf").read_bytes()
        client = (wg_dir / "router.conf").read_bytes()
    asyncio.run(main._recover_initial_wireguard_setup())
    assert not main._initial_wireguard_journal().exists()
    if committed:
        assert len(wireguard_peers.list_peers()) == 1
        assert (wg_dir / "wg0.conf").read_bytes() == server
        assert (wg_dir / "router.conf").read_bytes() == client
    else:
        _assert_original(database, wg_dir)


def test_pending_marker_rolls_back_even_after_settings_commit(isolated_setup):
    database, wg_dir = isolated_setup
    main._write_initial_wireguard_journal(
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/24",
            "activation_attempted": False,
            "settings": {},
            "phase": "pending",
        }
    )
    asyncio.run(
        wireguard.create(
            endpoint="192.0.2.10",
            subnet="10.90.0.0/24",
            dns="1.1.1.1",
            interface="wg0",
            client="router",
        )
    )
    asyncio.run(wireguard_peers.migrate_legacy("wg0", "router"))
    core.set_settings(
        {
            "wireguard_configured": True,
            "wireguard_interface": "wg0",
            "wireguard_client_name": "router",
            "wireguard_subnet": "10.90.0.0/24",
        }
    )
    asyncio.run(main._recover_initial_wireguard_setup())
    _assert_original(database, wg_dir)


@pytest.mark.parametrize("published", [False, True])
def test_commit_marker_write_failure_reenters_correct_side(isolated_setup, monkeypatch, published):
    database, wg_dir = isolated_setup
    original = main._write_initial_wireguard_journal

    def fail_marker(record):
        if record["phase"] == "committed":
            if published:
                original(record)
            raise OSError("synthetic fsync failure")
        original(record)

    monkeypatch.setattr(main, "_write_initial_wireguard_journal", fail_marker)
    if published:
        result = asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
        assert result["interface"] == "wg0"
    else:
        with pytest.raises(main.HTTPException, match="wireguard_recovery_failed"):
            asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    monkeypatch.setattr(main, "_write_initial_wireguard_journal", original)
    if published:
        assert core.setting("wireguard_configured") is True
        assert len(wireguard_peers.list_peers()) == 1
        assert (wg_dir / "wg0.conf").exists()
        assert (wg_dir / "router.conf").exists()
        assert not main._initial_wireguard_journal().exists()
    else:
        _assert_original(database, wg_dir)


@pytest.mark.parametrize("path", ["/api/ingress/wireguard/peers", "/api/vpn/connect"])
def test_unresolved_initial_intent_blocks_later_peer_and_provider_writers(
    isolated_setup, monkeypatch, path
):
    main._write_initial_wireguard_journal(
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/24",
            "activation_attempted": False,
            "settings": {},
            "phase": "pending",
        }
    )
    monkeypatch.setattr(main, "request_origin_rejection", lambda _request: None)
    monkeypatch.setattr(main, "session_user", lambda _token: {"id": 1, "username": "synthetic"})
    called = False

    async def next_request(_request):
        nonlocal called
        called = True
        return main.JSONResponse({"ok": True})

    request = main.Request({"type": "http", "method": "POST", "path": path, "headers": []})
    result = asyncio.run(main.require_authentication(request, next_request))
    assert result.status_code == 503
    assert result.body == b'{"detail":"wireguard_recovery_required"}'
    assert not called


def test_ambiguous_marker_and_failed_rollback_cannot_admit_later_peer_writer(
    isolated_setup, monkeypatch
):
    original = main._write_initial_wireguard_journal

    def fail_marker(record):
        if record["phase"] == "committed":
            raise OSError("synthetic fsync failure")
        original(record)

    async def fail_rollback(_journal):
        raise OSError("synthetic rollback failure")

    monkeypatch.setattr(main, "_write_initial_wireguard_journal", fail_marker)
    monkeypatch.setattr(main, "_rollback_initial_wireguard_setup", fail_rollback)
    with pytest.raises(main.HTTPException, match="wireguard_recovery_failed"):
        asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    assert main._initial_wireguard_journal().exists()
    monkeypatch.setattr(main, "request_origin_rejection", lambda _request: None)
    monkeypatch.setattr(main, "session_user", lambda _token: {"id": 1, "username": "synthetic"})

    async def forbidden(_request):
        pytest.fail("peer mutation reached handler while initial intent was unresolved")

    request = main.Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/ingress/wireguard/peers",
            "headers": [],
        }
    )
    assert asyncio.run(main.require_authentication(request, forbidden)).status_code == 503


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "world_readable"])
def test_unsafe_journal_is_refused_without_recovery_mutation(isolated_setup, unsafe):
    _, wg_dir = isolated_setup
    main._write_initial_wireguard_journal(
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/24",
            "activation_attempted": False,
            "settings": {},
            "phase": "pending",
        }
    )
    journal_path = main._initial_wireguard_journal()
    if unsafe == "symlink":
        target = wg_dir.parent / "private-journal-target"
        target.write_bytes(journal_path.read_bytes())
        target.chmod(0o600)
        journal_path.unlink()
        journal_path.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(journal_path, wg_dir.parent / "other-journal-link")
    else:
        journal_path.chmod(0o644)
    with pytest.raises(wireguard.WireGuardConfigurationError, match="wireguard_recovery_failed"):
        asyncio.run(main._recover_initial_wireguard_setup())
    assert journal_path.exists()
    assert core.setting("wireguard_configured", False) is False
    assert not (wg_dir / "wg0.conf").exists()


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "world_readable"])
def test_unsafe_initial_config_is_not_deleted_during_recovery(isolated_setup, unsafe):
    database, wg_dir = isolated_setup
    main._write_initial_wireguard_journal(
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/24",
            "activation_attempted": False,
            "settings": {},
            "phase": "pending",
        }
    )
    server = wg_dir / "wg0.conf"
    server.write_text("synthetic private file", encoding="ascii")
    server.chmod(0o600)
    if unsafe == "symlink":
        target = wg_dir.parent / "private-config-target"
        target.write_bytes(server.read_bytes())
        target.chmod(0o600)
        server.unlink()
        server.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(server, wg_dir.parent / "other-config-link")
    else:
        server.chmod(0o644)
    with pytest.raises(wireguard.WireGuardConfigurationError, match="wireguard_recovery_failed"):
        asyncio.run(main._recover_initial_wireguard_setup())
    assert main._initial_wireguard_journal().exists()
    assert server.exists()
    assert core.setting("wireguard_configured", False) is False
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0] == 0


def test_startup_keeps_committed_identity_when_routing_cannot_reconcile(
    isolated_setup, monkeypatch
):
    _, wg_dir = isolated_setup
    main._write_initial_wireguard_journal(
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/24",
            "activation_attempted": False,
            "settings": {},
            "phase": "committed",
        }
    )
    asyncio.run(
        wireguard.create(
            endpoint="192.0.2.10",
            subnet="10.90.0.0/24",
            dns="1.1.1.1",
            interface="wg0",
            client="router",
        )
    )
    asyncio.run(wireguard_peers.migrate_legacy("wg0", "router"))
    core.set_settings(
        {
            "wireguard_configured": True,
            "wireguard_interface": "wg0",
            "wireguard_client_name": "router",
            "wireguard_subnet": "10.90.0.0/24",
        }
    )
    before = ((wg_dir / "wg0.conf").read_bytes(), (wg_dir / "router.conf").read_bytes())

    async def fail(_actor=None):
        raise main.management_routing.ManagementRoutingError(
            "protected_destination_route_unavailable"
        )

    monkeypatch.setattr(main.management_routing, "reconcile", fail)
    with pytest.raises(wireguard.WireGuardConfigurationError, match="wireguard_recovery_failed"):
        asyncio.run(main._recover_initial_wireguard_setup())
    assert main._initial_wireguard_journal().exists()
    assert core.setting("wireguard_configured") is True
    assert len(wireguard_peers.list_peers()) == 1
    assert ((wg_dir / "wg0.conf").read_bytes(), (wg_dir / "router.conf").read_bytes()) == before


def test_first_setup_refuses_an_existing_native_interface(isolated_setup, monkeypatch, tmp_path):
    database, wg_dir = isolated_setup
    monkeypatch.setattr(
        main.runtime, "paths", replace(main.runtime.paths, application_data=database.parent)
    )
    monkeypatch.setattr(main, "SYSTEM_WIREGUARD_DIR", tmp_path / "system-wireguard")

    async def active(*args, **_kwargs):
        assert args[:2] == ("systemctl", "is-active")
        return 0, "", ""

    monkeypatch.setattr(main, "command", active)
    with pytest.raises(main.HTTPException) as error:
        asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    assert error.value.detail == "wireguard_configuration_invalid"
    _assert_original(database, wg_dir)


def test_failed_native_activation_keeps_config_until_interface_is_down(isolated_setup, monkeypatch):
    database, wg_dir = isolated_setup
    commands = []
    link_live = True

    async def activation_failed(_interface):
        raise RuntimeError("synthetic service health check failure")

    async def command(*args, **_kwargs):
        nonlocal link_live
        commands.append(args)
        if args[:2] == ("systemctl", "disable"):
            assert (wg_dir / "wg0.conf").exists()
            return 0, "", ""
        if args[:3] == ("ip", "link", "show"):
            return (0 if link_live else 1), "", ""
        if args[:2] == ("wg-quick", "down"):
            assert (wg_dir / "wg0.conf").exists()
            link_live = False
            return 0, "", ""
        pytest.fail("unexpected rollback command")

    monkeypatch.setattr(main, "activate_wireguard_interface", activation_failed)
    monkeypatch.setattr(main, "command", command)
    with pytest.raises(main.HTTPException) as error:
        asyncio.run(main.create_wireguard_ingress(_request(), _http_request()))
    assert error.value.detail == "wireguard_reload_failed"
    assert link_live is False
    assert any(item[:2] == ("wg-quick", "down") for item in commands)
    _assert_original(database, wg_dir)
