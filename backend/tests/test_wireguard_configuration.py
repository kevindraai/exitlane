import asyncio
import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.services import wireguard

SERVER_PRIVATE_OLD = "server-private-old"
SERVER_PUBLIC_OLD = "server-public-old"
CLIENT_PRIVATE_OLD = "client-private-old"
CLIENT_PUBLIC_OLD = "client-public-old"
SERVER_PRIVATE_NEW = "server-private-new"
SERVER_PUBLIC_NEW = "server-public-new"
CLIENT_PRIVATE_NEW = "client-private-new"
CLIENT_PUBLIC_NEW = "client-public-new"


@pytest.fixture
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    wg_dir = data / "wireguard"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", wg_dir)
    monkeypatch.setattr(main, "DB", database)
    monkeypatch.setattr(main, "WG_DIR", wg_dir)
    monkeypatch.setattr(wireguard, "WG_DIR", wg_dir)
    monkeypatch.setattr(main, "_wireguard_generation_lock", None)
    with TestClient(main.app) as test_client:
        digest, salt = core.hash_password("correct horse battery staple")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        yield test_client


def login(client):
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )


def configuration(private_key, peer_key):
    return f"[Interface]\nPrivateKey = {private_key}\n\n[Peer]\nPublicKey = {peer_key}\n"


def test_configuration_endpoints_require_authentication(client):
    for path in (
        "/api/ingress/wireguard/config",
        "/api/ingress/wireguard/config/download",
        "/api/ingress/wireguard/config/regenerate",
    ):
        response = client.post(path) if path.endswith("regenerate") else client.get(path)
        assert response.status_code == 401


def test_current_configuration_and_empty_state_are_private(client, monkeypatch):
    assert login(client).status_code == 200

    async def missing():
        return None

    monkeypatch.setattr(main, "_current_wireguard_configuration", missing)
    response = client.get("/api/ingress/wireguard/config")
    assert response.status_code == 200
    assert response.json() == {"available": False, "configuration": None}
    assert "no-store" in response.headers["cache-control"]

    async def existing():
        return {
            "client_name": "router",
            "filename": "exitlane-wireguard.conf",
            "client_config": "[Interface]\nPrivateKey = synthetic-secret\n",
        }

    monkeypatch.setattr(main, "_current_wireguard_configuration", existing)
    response = client.get("/api/ingress/wireguard/config")
    assert response.json()["configuration"].endswith("synthetic-secret\n")
    assert "no-store" in response.headers["cache-control"]


def test_download_matches_displayed_configuration(client, monkeypatch):
    assert login(client).status_code == 200
    config = "[Interface]\nPrivateKey = synthetic-download-secret\n"
    path = main.WG_DIR / "router.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config, encoding="utf-8")
    core.set_setting("wireguard_client_name", "router")

    async def existing():
        return {
            "client_name": "router",
            "filename": "exitlane-wireguard.conf",
            "client_config": config,
        }

    monkeypatch.setattr(main, "_current_wireguard_configuration", existing)
    displayed = client.get("/api/ingress/wireguard/config").json()["configuration"]
    response = client.get("/api/ingress/wireguard/config/download")
    assert response.status_code == 200
    assert response.text == displayed
    assert response.headers["content-type"].startswith("application/x-wireguard-profile")
    assert 'filename="exitlane-wireguard.conf"' in response.headers["content-disposition"]
    assert "no-store" in response.headers["cache-control"]


def test_qr_is_authenticated_segno_svg_and_not_cached(client, monkeypatch, caplog):
    assert client.get("/api/ingress/wireguard/config/qr").status_code == 401
    assert login(client).status_code == 200
    marker = "synthetic-private-qr-marker"

    async def existing():
        return {
            "client_name": "router",
            "filename": "exitlane-wireguard.conf",
            "client_config": f"[Interface]\nPrivateKey = {marker}\n",
        }

    monkeypatch.setattr(main, "_current_wireguard_configuration", existing)
    response = client.get("/api/ingress/wireguard/config/qr")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "no-store" in response.headers["cache-control"]
    assert b'<svg xmlns="http://www.w3.org/2000/svg"' in response.content
    assert b'class="wireguard-qr-svg"' in response.content
    assert b'class="wireguard-qr-modules"' in response.content
    assert marker not in response.text
    assert marker not in caplog.text


def test_missing_qr_uses_existing_safe_error(client, monkeypatch):
    assert login(client).status_code == 200

    async def missing():
        return None

    monkeypatch.setattr(main, "_current_wireguard_configuration", missing)
    response = client.get("/api/ingress/wireguard/config/qr")
    assert response.status_code == 404
    assert response.json() == {"error": "wireguard_configuration_missing"}


def test_qr_is_rebuilt_from_replaced_current_configuration(client, monkeypatch):
    assert login(client).status_code == 200
    current = {"value": "[Interface]\nPrivateKey = first-synthetic-key\n"}

    async def existing():
        return {
            "client_name": "router",
            "filename": "exitlane-wireguard.conf",
            "client_config": current["value"],
        }

    monkeypatch.setattr(main, "_current_wireguard_configuration", existing)
    first = client.get("/api/ingress/wireguard/config/qr").content
    current["value"] = "[Interface]\nPrivateKey = second-synthetic-key\n"
    second = client.get("/api/ingress/wireguard/config/qr").content
    assert first != second


def test_missing_download_and_invalid_configuration_use_safe_errors(client, monkeypatch):
    assert login(client).status_code == 200

    async def missing():
        return None

    monkeypatch.setattr(main, "_current_wireguard_configuration", missing)
    response = client.get("/api/ingress/wireguard/config/download")
    assert response.status_code == 404
    assert response.json() == {"error": "wireguard_configuration_missing"}

    async def invalid():
        raise wireguard.WireGuardConfigurationError("wireguard_configuration_invalid")

    monkeypatch.setattr(main, "_current_wireguard_configuration", invalid)
    response = client.get("/api/ingress/wireguard/config")
    assert response.status_code == 409
    assert response.json() == {"error": "wireguard_configuration_invalid"}
    assert "PrivateKey" not in response.text


def test_regeneration_is_post_only_and_logs_no_configuration(client, monkeypatch):
    assert login(client).status_code == 200
    for key, value in {
        "wireguard_endpoint": "192.0.2.10",
        "wireguard_subnet": "10.90.0.0/24",
        "wireguard_dns": "1.1.1.1",
        "wireguard_port": 51820,
        "wireguard_interface": "wg0",
        "wireguard_client_name": "router",
    }.items():
        core.set_setting(key, value)
    calls = []
    events = []

    async def provision(**kwargs):
        calls.append(kwargs)
        return {"client_config": "[Interface]\nPrivateKey = synthetic-new-secret\n"}

    async def current(_interface, _client):
        return {"client_config": "synthetic-current"}

    monkeypatch.setattr(main.wireguard_service, "provision", provision)
    monkeypatch.setattr(main.wireguard_service, "read_current", current)
    monkeypatch.setattr(main, "record_event", lambda code, **values: events.append((code, values)))
    assert client.get("/api/ingress/wireguard/config/regenerate").status_code == 405
    response = client.post("/api/ingress/wireguard/config/regenerate")
    assert response.status_code == 200
    assert len(calls) == 1
    assert response.json()["configuration"].endswith("synthetic-new-secret\n")
    assert "no-store" in response.headers["cache-control"]
    assert events[0][0] == "wireguard.configuration_regenerated"
    assert "synthetic-new-secret" not in str(events)


def test_wizard_and_management_share_provisioning_service(client, monkeypatch):
    calls = []

    async def provision(**kwargs):
        calls.append(kwargs)
        return {
            "interface": "wg0",
            "server_public_key": "synthetic-server-public",
            "client_public_key": "synthetic-client-public",
            "client_config": "[Interface]\nPrivateKey = synthetic-wizard-secret\n",
            "client_name": "router",
        }

    monkeypatch.setattr(main.wireguard_service, "provision", provision)
    monkeypatch.setattr(main, "record_event", lambda *_args, **_kwargs: None)
    response = client.post(
        "/api/ingress/wireguard",
        json={
            "endpoint": "192.0.2.10",
            "subnet": "10.90.0.0/24",
            "dns": "1.1.1.1",
            "port": 51820,
            "interface": "wg0",
            "client": "router",
        },
    )
    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0]["activate"] is main.activate_wireguard_interface
    assert response.json()["client_config"].endswith("synthetic-wizard-secret\n")


def test_reload_failure_returns_only_stable_error_code(client, monkeypatch):
    assert login(client).status_code == 200
    for key, value in {
        "wireguard_endpoint": "192.0.2.10",
        "wireguard_subnet": "10.90.0.0/24",
        "wireguard_dns": "1.1.1.1",
        "wireguard_port": 51820,
    }.items():
        core.set_setting(key, value)

    async def provision(**_kwargs):
        raise wireguard.WireGuardConfigurationError("wireguard_reload_failed")

    async def current(_interface, _client):
        return {"client_config": "synthetic-current"}

    monkeypatch.setattr(main.wireguard_service, "provision", provision)
    monkeypatch.setattr(main.wireguard_service, "read_current", current)
    response = client.post("/api/ingress/wireguard/config/regenerate")
    assert response.status_code == 500
    assert response.json() == {"error": "wireguard_reload_failed"}
    assert "secret" not in response.text.lower()


def test_second_regeneration_is_rejected_while_generation_is_active(client, monkeypatch):
    assert login(client).status_code == 200

    class Locked:
        @staticmethod
        def locked():
            return True

    monkeypatch.setattr(main, "wireguard_generation_lock", lambda: Locked())
    response = client.post("/api/ingress/wireguard/config/regenerate")
    assert response.status_code == 409
    assert response.json() == {"error": "wireguard_generation_in_progress"}


def test_provision_rolls_back_both_files_after_reload_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "WG_DIR", tmp_path)
    server = tmp_path / "wg0.conf"
    client = tmp_path / "router.conf"
    server.write_text("old-server", encoding="utf-8")
    client.write_text("old-client", encoding="utf-8")
    pairs = iter(
        [
            (SERVER_PRIVATE_NEW, SERVER_PUBLIC_NEW),
            (CLIENT_PRIVATE_NEW, CLIENT_PUBLIC_NEW),
        ]
    )

    async def keypair():
        return next(pairs)

    activations = []

    async def activate(interface):
        activations.append(interface)
        raise RuntimeError("reload included secret material")

    monkeypatch.setattr(wireguard, "keypair", keypair)
    with pytest.raises(wireguard.WireGuardConfigurationError) as error:
        asyncio.run(
            wireguard.provision(
                activate=activate,
                endpoint="192.0.2.10",
                interface="wg0",
                client="router",
            )
        )
    assert error.value.code == "wireguard_reload_failed"
    assert server.read_text(encoding="utf-8") == "old-server"
    assert client.read_text(encoding="utf-8") == "old-client"
    assert activations == ["wg0", "wg0"]
    assert server.stat().st_mode & 0o777 == 0o600
    assert client.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".*.conf.*"))


def test_successful_provision_replaces_keys_consistently(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "WG_DIR", tmp_path)
    pairs = iter(
        [
            (SERVER_PRIVATE_NEW, SERVER_PUBLIC_NEW),
            (CLIENT_PRIVATE_NEW, CLIENT_PUBLIC_NEW),
        ]
    )

    async def keypair():
        return next(pairs)

    activated = []
    monkeypatch.setattr(wireguard, "keypair", keypair)
    result = asyncio.run(
        wireguard.provision(
            activate=lambda interface: asyncio.sleep(0, result=activated.append(interface)),
            endpoint="192.0.2.10",
            interface="wg0",
            client="router",
        )
    )
    server_config = (tmp_path / "wg0.conf").read_text(encoding="utf-8")
    client_config = (tmp_path / "router.conf").read_text(encoding="utf-8")
    assert SERVER_PRIVATE_NEW in server_config
    assert CLIENT_PUBLIC_NEW in server_config
    assert CLIENT_PRIVATE_NEW in client_config
    assert SERVER_PUBLIC_NEW in client_config
    assert result["client_config"] == client_config
    assert activated == ["wg0"]
    assert not list(tmp_path.glob(".*.conf.*"))


def test_read_current_rejects_inconsistent_keys_and_handles_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "WG_DIR", tmp_path)
    assert asyncio.run(wireguard.read_current("wg0", "router")) is None
    (tmp_path / "wg0.conf").write_text(
        configuration(SERVER_PRIVATE_OLD, CLIENT_PUBLIC_OLD), encoding="utf-8"
    )
    (tmp_path / "router.conf").write_text(
        configuration(CLIENT_PRIVATE_OLD, "wrong-server-public"), encoding="utf-8"
    )

    async def command(*_args, input_text, timeout):
        assert timeout == 5
        mapping = {
            SERVER_PRIVATE_OLD: SERVER_PUBLIC_OLD,
            CLIENT_PRIVATE_OLD: CLIENT_PUBLIC_OLD,
        }
        return 0, mapping[input_text.strip()], ""

    monkeypatch.setattr(wireguard, "command", command)
    with pytest.raises(wireguard.WireGuardConfigurationError) as error:
        asyncio.run(wireguard.read_current("wg0", "router"))
    assert error.value.code == "wireguard_configuration_invalid"


@pytest.mark.parametrize(
    ("interface", "client"),
    [
        ("../wg0", "router"),
        ("wg0", "../router"),
        ("wg0/peer", "router"),
        ("wg0", "router.conf"),
        ("wg0", "router%2fescape"),
    ],
)
def test_configuration_paths_reject_untrusted_names(tmp_path, monkeypatch, interface, client):
    monkeypatch.setattr(wireguard, "WG_DIR", tmp_path)
    with pytest.raises(wireguard.WireGuardConfigurationError) as error:
        asyncio.run(wireguard.read_current(interface, client))
    assert error.value.code == "wireguard_configuration_invalid"
    assert list(tmp_path.iterdir()) == []


def test_configuration_path_stays_below_canonical_wireguard_root(tmp_path, monkeypatch):
    wireguard_root = tmp_path / "wireguard"
    wireguard_root.mkdir()
    monkeypatch.setattr(wireguard, "WG_DIR", wireguard_root / ".." / "wireguard")
    assert wireguard._configuration_path("router") == wireguard_root / "router.conf"
