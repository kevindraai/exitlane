import asyncio
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.services import wireguard, wireguard_peers


@pytest.fixture
def client(tmp_path, monkeypatch, synthetic_wireguard_keys):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(wireguard, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", core.DB)
    monkeypatch.setattr(main, "WG_DIR", core.WG_DIR)
    monkeypatch.setattr(main, "_wireguard_generation_lock", None)
    core.init()
    asyncio.run(wireguard.create(
        endpoint="192.0.2.5", subnet="10.98.240.0/29", dns="1.1.1.1",
        interface="wg0", client="UniFi-Gateway",
    ))
    core.set_settings({
        "wireguard_configured": True, "wireguard_interface": "wg0",
        "wireguard_client_name": "UniFi-Gateway", "wireguard_subnet": "10.98.240.0/29",
        "wireguard_endpoint": "192.0.2.5", "wireguard_port": 51820,
    })

    async def sync(_interface):
        return None

    async def active(_interface, *, runner):
        return True

    async def command(*args, **_kwargs):
        if args[:3] == ("wg", "show", "wg0"):
            rows = wireguard_peers.list_peers()
            peer = next((row for row in rows if row["status"] == "active"), None)
            if peer:
                dump = (
                    "server\tpublic\t51820\toff\n"
                    f"{peer['public_key']}\t(none)\t198.51.100.7:51820\t0\t{int(time.time()) - 5}\t123\t456\t25\n"
                )
                return 0, dump, ""
            return 0, "server\tpublic\t51820\toff\n", ""
        return 1, "", ""

    monkeypatch.setattr(main, "sync_wireguard_interface", sync)
    monkeypatch.setattr(main.runtime, "observe_ingress", active)
    monkeypatch.setattr(main, "command", command)
    with TestClient(main.app) as test_client:
        digest, salt = core.hash_password("correct horse battery staple")
        with sqlite3.connect(core.DB) as connection:
            connection.execute(
                "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
                ("admin", digest, salt),
            )
        response = test_client.post("/api/auth/login", json={
            "username": "admin", "password": "correct horse battery staple",
        })
        assert response.status_code == 200
        yield test_client


def test_peer_api_full_lifecycle_and_private_config(client):
    legacy = client.get("/api/ingress/wireguard/config")
    assert legacy.status_code == 200
    original = legacy.json()["configuration"]
    assert "PrivateKey = " in original
    listing = client.get("/api/ingress/wireguard/peers")
    assert listing.status_code == 200
    assert len(listing.json()["peers"]) == 1
    assert "configuration" not in listing.text
    assert "PrivateKey" not in listing.text
    assert listing.json()["recent_peers"] == 1
    assert listing.json()["peers"][0]["runtime_status"] == "active_recently"
    assert listing.json()["peers"][0]["received_bytes"] == 123
    assert listing.json()["peers"][0]["endpoint"] == "198.51.100.7:51820"

    response = client.post("/api/ingress/wireguard/peers", json={
        "name": "Deluge - Synology", "description": "NAS container",
    })
    assert response.status_code == 201
    payload = response.json()
    peer_id = payload["peer"]["peer_id"]
    old_key = payload["peer"]["public_key"]
    assert payload["filename"] == "exitlane-deluge-synology.conf"
    assert payload["peer"]["tunnel_ip"] == "10.98.240.3"
    assert payload["configuration"] != original
    assert "PrivateKey" not in client.get("/api/ingress/wireguard/peers").text
    assert client.get(f"/api/ingress/wireguard/peers/{peer_id}").json()["name"] == "Deluge - Synology"

    config_path = f"/api/ingress/wireguard/peers/{peer_id}/config"
    reveal = client.get(config_path)
    download = client.get(config_path + "/download")
    qr = client.get(config_path + "/qr")
    assert reveal.json()["configuration"] == download.text
    assert qr.headers["content-type"].startswith("image/svg+xml")
    assert 'filename="exitlane-deluge-synology.conf"' in download.headers["content-disposition"]
    for item in (reveal, download, qr):
        assert item.headers["cache-control"] == "no-store, private"
        assert item.headers["pragma"] == "no-cache"

    renamed = client.patch(f"/api/ingress/wireguard/peers/{peer_id}", json={
        "name": "Deluge NAS", "description": "renamed",
    })
    assert renamed.status_code == 200
    assert renamed.json()["public_key"] == old_key
    assert renamed.json()["tunnel_ip"] == "10.98.240.3"
    assert client.delete(f"/api/ingress/wireguard/peers/{peer_id}").status_code == 409
    rotated = client.post(f"/api/ingress/wireguard/peers/{peer_id}/regenerate")
    assert rotated.status_code == 200
    assert rotated.json()["peer"]["public_key"] != old_key
    assert rotated.json()["peer"]["tunnel_ip"] == "10.98.240.3"
    assert original == client.get("/api/ingress/wireguard/config").json()["configuration"]

    revoked = client.post(f"/api/ingress/wireguard/peers/{peer_id}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["peer"]["status"] == "revoked"
    assert client.get(config_path).status_code == 409
    assert client.get(config_path + "/download").status_code == 409
    assert client.get(config_path + "/qr").status_code == 409
    assert client.get(f"/api/ingress/wireguard/peers/{peer_id}").json()["runtime_status"] == "revoked"
    assert client.delete(f"/api/ingress/wireguard/peers/{peer_id}").status_code == 200
    assert client.get(f"/api/ingress/wireguard/peers/{peer_id}").status_code == 404
    with sqlite3.connect(core.DB) as connection:
        events = [json.loads(row[0]) for row in connection.execute(
            "SELECT metadata_json FROM events WHERE code LIKE 'wireguard.peer_%'"
        )]
    assert len(events) == 5
    assert all(set(item) == {"peer_id", "name"} for item in events)
    assert "PrivateKey" not in str(events)


def test_peer_routes_require_auth_and_same_origin(client):
    client.post("/api/auth/logout")
    for path in ("/api/ingress/wireguard/peers", "/api/ingress/wireguard/peers/abc/config"):
        assert client.get(path).status_code == 401
    assert client.post("/api/ingress/wireguard/peers", json={"name": "No auth"}).status_code == 401
    assert client.post("/api/auth/login", json={
        "username": "admin", "password": "correct horse battery staple",
    }).status_code == 200
    response = client.post(
        "/api/ingress/wireguard/peers", json={"name": "Cross origin"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert len(client.get("/api/ingress/wireguard/peers").json()["peers"]) == 1


@pytest.mark.parametrize("name", [
    "../device", "bad\nname", "bad\u202ename", "\nName", "Name\t", "\u0085Name",
])
def test_peer_api_rejects_unsafe_names(client, name):
    response = client.post("/api/ingress/wireguard/peers", json={"name": name})
    assert response.status_code == 400
    assert response.json() == {"error": "wireguard_peer_invalid_name"}


@pytest.mark.parametrize("description", ["hello\r", "\tdevice", "note\u202e"])
def test_peer_api_rejects_unsafe_descriptions(client, description):
    response = client.post("/api/ingress/wireguard/peers", json={
        "name": "Safe device", "description": description,
    })
    assert response.status_code == 400
    assert response.json() == {"error": "wireguard_peer_invalid_description"}


def test_old_named_download_cannot_expose_revoked_default(client):
    peer_id = client.get("/api/ingress/wireguard/peers").json()["peers"][0]["peer_id"]
    assert client.get("/api/ingress/wireguard/client/UniFi-Gateway").status_code == 200
    assert client.post(f"/api/ingress/wireguard/peers/{peer_id}/revoke").status_code == 200
    assert client.get("/api/ingress/wireguard/client/UniFi-Gateway").status_code == 404
    assert client.get("/api/ingress/wireguard/config").json()["available"] is False


def test_runtime_status_maps_stale_never_and_revoked_by_public_key(client, monkeypatch):
    first = wireguard_peers.list_peers()[0]
    second = client.post("/api/ingress/wireguard/peers", json={"name": "Never"}).json()["peer"]
    third = client.post("/api/ingress/wireguard/peers", json={"name": "Revoked"}).json()["peer"]
    assert client.post(f"/api/ingress/wireguard/peers/{third['peer_id']}/revoke").status_code == 200
    old = int(time.time()) - main.WIREGUARD_RECENT_SECONDS - 50

    async def dump(*args, **_kwargs):
        if args[:3] == ("wg", "show", "wg0"):
            return 0, (
                "server\tpublic\t51820\toff\n"
                f"{first['public_key']}\t(none)\t203.0.113.9:12345\t0\t{old}\t7\t8\t25\n"
                f"{second['public_key']}\t(none)\t(none)\t0\t0\t0\t0\t25\n"
            ), ""
        return 1, "", ""

    monkeypatch.setattr(main, "command", dump)
    response = client.get("/api/ingress/wireguard/peers")
    assert response.status_code == 200
    peers = {peer["peer_id"]: peer for peer in response.json()["peers"]}
    assert peers[first["peer_id"]]["runtime_status"] == "inactive"
    assert peers[first["peer_id"]]["handshake_age"] >= main.WIREGUARD_RECENT_SECONDS
    assert peers[first["peer_id"]]["endpoint"] == "203.0.113.9:12345"
    assert peers[first["peer_id"]]["received_bytes"] == 7
    assert peers[second["peer_id"]]["runtime_status"] == "never_connected"
    assert peers[third["peer_id"]]["runtime_status"] == "revoked"
    assert response.json()["recent_peers"] == 0
    assert client.get("/api/ingress/wireguard/status").json()["connected"] is False


def test_failed_legacy_migration_cannot_regenerate_or_download_invalid_state(client):
    with sqlite3.connect(core.DB) as connection:
        connection.execute("DELETE FROM wireguard_peers")
        connection.execute("DELETE FROM wireguard_ingress_profile")
    server = core.WG_DIR.joinpath("wg0.conf").read_bytes()
    client_path = core.WG_DIR / "UniFi-Gateway.conf"
    client_path.write_bytes(client_path.read_bytes().replace(b"10.98.240.2/32", b"10.98.240.3/32"))
    client_path.chmod(0o600)
    response = client.post("/api/ingress/wireguard/config/regenerate")
    assert response.status_code == 409
    assert response.json() == {"error": "wireguard_configuration_invalid"}
    assert client.get("/api/ingress/wireguard/config").status_code == 409
    assert client.get("/api/ingress/wireguard/client/UniFi-Gateway").status_code == 409
    assert core.WG_DIR.joinpath("wg0.conf").read_bytes() == server
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0] == 0
