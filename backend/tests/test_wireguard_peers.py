import asyncio
import sqlite3

import pytest

from exitlane import core, lifecycle
from exitlane.services import wireguard, wireguard_peers


@pytest.fixture
def migrated(tmp_path, monkeypatch, synthetic_wireguard_keys):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(wireguard, "WG_DIR", data / "wireguard")
    core.init()

    async def prepare():
        await wireguard.create(
            endpoint="192.0.2.5", subnet="10.98.240.0/29", dns="1.1.1.1",
            interface="wg0", client="UniFi-Gateway",
        )
        before = {path.name: path.read_bytes() for path in core.WG_DIR.iterdir()}
        assert await wireguard_peers.migrate_legacy("wg0", "UniFi-Gateway")
        assert not await wireguard_peers.migrate_legacy("wg0", "UniFi-Gateway")
        assert before == {path.name: path.read_bytes() for path in core.WG_DIR.iterdir()}
        core.set_settings({
            "wireguard_configured": True,
            "wireguard_interface": "wg0",
            "wireguard_client_name": "UniFi-Gateway",
        })
        return before

    return asyncio.run(prepare())


def test_legacy_migration_preserves_byte_exact_keys_and_is_idempotent(migrated):
    rows = wireguard_peers.list_peers()
    assert len(rows) == 1
    assert rows[0]["name"] == "UniFi-Gateway"
    assert rows[0]["tunnel_ip"] == "10.98.240.2"
    assert rows[0]["is_default"] == 1
    assert b"PrivateKey = " in migrated["wg0.conf"]
    assert b"PrivateKey = " in migrated["UniFi-Gateway.conf"]


def test_create_edit_regenerate_revoke_delete_and_empty_pool_recovery(migrated):
    original_server = core.WG_DIR.joinpath("wg0.conf").read_text()
    original_client = core.WG_DIR.joinpath("UniFi-Gateway.conf").read_bytes()
    syncs = []

    async def sync(interface):
        syncs.append((interface, core.WG_DIR.joinpath("wg0.conf").read_text()))

    async def scenario():
        first = wireguard_peers.list_peers()[0]
        a = await wireguard_peers.create("wg0", "Deluge - Synology", "NAS container", sync)
        b = await wireguard_peers.create("wg0", "Laptop Kevin", "", sync)
        assert a["peer"]["tunnel_ip"] == "10.98.240.3"
        assert b["peer"]["tunnel_ip"] == "10.98.240.4"
        assert a["filename"] == "exitlane-deluge-synology.conf"
        assert len(wireguard_peers._server(core.WG_DIR.joinpath("wg0.conf").read_text())[1]) == 3
        assert core.WG_DIR.joinpath("UniFi-Gateway.conf").read_bytes() == original_client
        assert wireguard._value(original_server, "PrivateKey", section="Interface") == wireguard._value(
            core.WG_DIR.joinpath("wg0.conf").read_text(), "PrivateKey", section="Interface"
        )
        edited = await wireguard_peers.update("wg0", a["peer"]["peer_id"], "Deluge NAS", "changed")
        assert edited["public_key"] == a["peer"]["public_key"]
        assert edited["tunnel_ip"] == a["peer"]["tunnel_ip"]
        rotated = await wireguard_peers.regenerate("wg0", a["peer"]["peer_id"], sync)
        assert rotated["peer"]["public_key"] != a["peer"]["public_key"]
        assert rotated["peer"]["tunnel_ip"] == a["peer"]["tunnel_ip"]
        assert wireguard_peers.get_peer(b["peer"]["peer_id"])["public_key"] == b["peer"]["public_key"]
        await wireguard_peers.revoke("wg0", a["peer"]["peer_id"], sync)
        with pytest.raises(wireguard_peers.PeerError, match="wireguard_peer_revoked"):
            await wireguard_peers.configuration("wg0", a["peer"]["peer_id"])
        with pytest.raises(wireguard_peers.PeerError, match="wireguard_peer_must_revoke_first"):
            await wireguard_peers.delete("wg0", b["peer"]["peer_id"])
        await wireguard_peers.delete("wg0", a["peer"]["peer_id"])
        await wireguard_peers.revoke("wg0", b["peer"]["peer_id"], sync)
        await wireguard_peers.delete("wg0", b["peer"]["peer_id"])
        await wireguard_peers.revoke("wg0", first["peer_id"], sync)
        await wireguard_peers.delete("wg0", first["peer_id"])
        assert not wireguard_peers.list_peers()
        assert not await wireguard_peers.migrate_legacy("wg0", "UniFi-Gateway")
        replacement = await wireguard_peers.create("wg0", "Replacement", "", sync)
        assert replacement["peer"]["tunnel_ip"] == "10.98.240.2"

    asyncio.run(scenario())
    assert len(syncs) == 7


def test_exhaustion_and_revoked_ip_stays_reserved(migrated):
    async def sync(_interface):
        return None

    async def scenario():
        created = [await wireguard_peers.create("wg0", str(index), "", sync) for index in range(4)]
        assert {item["peer"]["tunnel_ip"] for item in created} == {
            "10.98.240.3", "10.98.240.4", "10.98.240.5", "10.98.240.6"
        }
        with pytest.raises(wireguard_peers.PeerError, match="wireguard_address_pool_exhausted"):
            await wireguard_peers.create("wg0", "Overflow", "", sync)
        await wireguard_peers.revoke("wg0", created[0]["peer"]["peer_id"], sync)
        with pytest.raises(wireguard_peers.PeerError, match="wireguard_address_pool_exhausted"):
            await wireguard_peers.create("wg0", "Still full", "", sync)

    asyncio.run(scenario())


def test_sync_failure_restores_database_files_and_kernel_callback(migrated):
    server = core.WG_DIR.joinpath("wg0.conf").read_bytes()
    rows = wireguard_peers.list_peers()
    calls = []

    async def sync(_interface):
        calls.append(core.WG_DIR.joinpath("wg0.conf").read_bytes())
        if len(calls) == 1:
            raise RuntimeError("synthetic activation failure with private marker")

    with pytest.raises(wireguard_peers.PeerError, match="wireguard_peer_mutation_failed"):
        asyncio.run(wireguard_peers.create("wg0", "Fails", "", sync))
    assert len(calls) == 2
    assert core.WG_DIR.joinpath("wg0.conf").read_bytes() == server
    assert wireguard_peers.list_peers() == rows
    assert sorted(path.name for path in core.WG_DIR.iterdir()) == ["UniFi-Gateway.conf", "wg0.conf"]


def test_cancelled_sync_restores_database_files_and_runtime(migrated):
    server = core.WG_DIR.joinpath("wg0.conf").read_bytes()
    rows = wireguard_peers.list_peers()
    calls = []

    async def sync(_interface):
        calls.append(core.WG_DIR.joinpath("wg0.conf").read_bytes())
        if len(calls) == 1:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(wireguard_peers.create("wg0", "Cancelled", "", sync))
    assert len(calls) == 2
    assert core.WG_DIR.joinpath("wg0.conf").read_bytes() == server
    assert wireguard_peers.list_peers() == rows
    assert sorted(path.name for path in core.WG_DIR.iterdir()) == ["UniFi-Gateway.conf", "wg0.conf"]


def test_malformed_state_blocks_mutations_without_repair(migrated):
    server_path = core.WG_DIR / "wg0.conf"
    original = server_path.read_bytes()
    server_path.write_bytes(original.replace(b"10.98.240.2/32", b"10.98.240.1/32"))
    server_path.chmod(0o600)

    async def sync(_interface):
        raise AssertionError("malformed state must not reach runtime")

    with pytest.raises(wireguard_peers.PeerError, match="wireguard_configuration_invalid"):
        asyncio.run(wireguard_peers.create("wg0", "Blocked", "", sync))
    assert server_path.read_bytes() != original
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0] == 1


def test_encrypted_backup_restore_preserves_two_peers_and_revocation(
    migrated, tmp_path, monkeypatch
):
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    secret = config_dir / "secret.key"
    secret.write_bytes(b"k" * 32)
    secret.chmod(0o600)
    monkeypatch.setattr(lifecycle, "CONFIG_DIR", config_dir)

    async def sync(_interface):
        return None

    async def prepare():
        active = await wireguard_peers.create("wg0", "NAS", "", sync)
        revoked = await wireguard_peers.create("wg0", "Test", "", sync)
        await wireguard_peers.revoke("wg0", revoked["peer"]["peer_id"], sync)
        return active, revoked

    active, revoked = asyncio.run(prepare())
    original_rows = wireguard_peers.list_peers()
    original_files = {path.name: path.read_bytes() for path in core.WG_DIR.iterdir()}
    backup = tmp_path / "multipeer.elb"
    lifecycle.create_backup(
        backup, "correct horse battery staple", effective_user_id=0,
        lock_path=tmp_path / "lifecycle.lock",
    )
    assert b"PrivateKey" not in backup.read_bytes()
    asyncio.run(wireguard_peers.update("wg0", active["peer"]["peer_id"], "Mutated", ""))
    lifecycle.restore_backup(
        backup, "correct horse battery staple", confirmation="RESTORE EXITLANE",
        effective_user_id=0, lock_path=tmp_path / "lifecycle.lock",
    )
    assert wireguard_peers.list_peers() == original_rows
    assert {path.name: path.read_bytes() for path in core.WG_DIR.iterdir()} == original_files
    assert wireguard_peers.get_peer(revoked["peer"]["peer_id"])["status"] == "revoked"
    assert wireguard_peers.get_peer(active["peer"]["peer_id"])["status"] == "active"


@pytest.mark.parametrize("uppercase_tables", [False, True])
def test_restore_rejects_backup_with_revoked_peer_still_on_server(
    migrated, tmp_path, monkeypatch, uppercase_tables
):
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    secret = config_dir / "secret.key"
    secret.write_bytes(b"k" * 32)
    secret.chmod(0o600)
    monkeypatch.setattr(lifecycle, "CONFIG_DIR", config_dir)

    async def sync(_interface):
        return None

    async def prepare():
        peer = await wireguard_peers.create("wg0", "Revoked", "", sync)
        await wireguard_peers.revoke("wg0", peer["peer"]["peer_id"], sync)
        return peer["peer"]

    revoked = asyncio.run(prepare())
    server_path = core.WG_DIR / "wg0.conf"
    valid_server = server_path.read_bytes()
    server_path.write_bytes(valid_server + (
        f"\n[Peer]\nPublicKey = {revoked['public_key']}\n"
        f"AllowedIPs = {revoked['tunnel_ip']}/32\nPersistentKeepalive = 25\n"
    ).encode())
    server_path.chmod(0o600)
    if uppercase_tables:
        with sqlite3.connect(core.DB) as connection:
            connection.execute('ALTER TABLE wireguard_peers RENAME TO intermediate_peers')
            connection.execute('ALTER TABLE intermediate_peers RENAME TO "WIREGUARD_PEERS"')
            connection.execute(
                'ALTER TABLE wireguard_ingress_profile RENAME TO intermediate_profile'
            )
            connection.execute(
                'ALTER TABLE intermediate_profile RENAME TO "WIREGUARD_INGRESS_PROFILE"'
            )
    backup = tmp_path / "invalid-multipeer.elb"
    lifecycle.create_backup(
        backup, "correct horse battery staple", effective_user_id=0,
        lock_path=tmp_path / "lifecycle.lock",
    )
    server_path.write_bytes(valid_server)
    server_path.chmod(0o600)
    if uppercase_tables:
        with sqlite3.connect(core.DB) as connection:
            connection.execute('ALTER TABLE "WIREGUARD_PEERS" RENAME TO intermediate_peers')
            connection.execute('ALTER TABLE intermediate_peers RENAME TO wireguard_peers')
            connection.execute(
                'ALTER TABLE "WIREGUARD_INGRESS_PROFILE" RENAME TO intermediate_profile'
            )
            connection.execute(
                'ALTER TABLE intermediate_profile RENAME TO wireguard_ingress_profile'
            )
    rows = wireguard_peers.list_peers()
    with pytest.raises(lifecycle.LifecycleError, match="wireguard_configuration_invalid"):
        lifecycle.restore_backup(
            backup, "correct horse battery staple", confirmation="RESTORE EXITLANE",
            effective_user_id=0, lock_path=tmp_path / "lifecycle.lock",
        )
    assert server_path.read_bytes() == valid_server
    assert wireguard_peers.list_peers() == rows


def test_backup_lock_rejects_concurrent_peer_change(migrated):
    async def sync(_interface):
        raise AssertionError("locked mutation reached runtime")

    with (
        wireguard_peers.state_lock(),
        pytest.raises(wireguard_peers.PeerError, match="wireguard_generation_in_progress"),
    ):
        asyncio.run(wireguard_peers.create("wg0", "Blocked", "", sync))


@pytest.mark.parametrize("name", ["..", "../secret", "bad\nname", "bad\u202ename", "bad\u0085name"])
def test_unsafe_display_names_are_rejected(name):
    with pytest.raises(wireguard_peers.PeerError, match="wireguard_peer_invalid_name"):
        wireguard_peers.validate_name(name)
