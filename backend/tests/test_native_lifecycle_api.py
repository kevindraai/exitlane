"""Real API/crypto fixture proof; kernel/service calls remain explicit test doubles."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.services import auth_security, provider_secrets

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/qualification/native_lifecycle_api.py"
spec = importlib.util.spec_from_file_location("native_lifecycle_api", SCRIPT)
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class Adapter:
    def __init__(self, client):
        self.client = client

    def call(self, path, data=None, *, method=None, expected=200):
        response = self.client.request(
            method or ("POST" if data is not None else "GET"), path, json=data
        )
        assert response.status_code == expected, (path, response.status_code, response.text)
        return response.json()


@pytest.fixture
def appliance(tmp_path, monkeypatch, synthetic_wireguard_keys):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", core.DB)
    monkeypatch.setattr(main, "WG_DIR", core.WG_DIR)
    monkeypatch.setattr(main.wireguard_service, "WG_DIR", core.WG_DIR)

    async def diagnostics(**kwargs):
        return [{"ok": True, "name": "fixture-host"}]

    async def status(**kwargs):
        return {"installed": True, "authenticated": False, "connected": False}

    async def local_status(**kwargs):
        return {"installed": True, "connected": False, "connection_state": "disconnected"}

    async def command(*args, **kwargs):
        if args[:3] == ("ip", "-4", "route"):
            return 0, "default via 192.0.2.1 dev fixture0", ""
        if args[:3] == ("ip", "-4", "-o"):
            return 0, "2: fixture0 inet 192.0.2.2/24 scope global fixture0", ""
        raise AssertionError("unexpected host command")

    async def provision(**kwargs):
        # Only this kernel-facing part is mocked, not wizard/MFA/provider persistence.
        kwargs.pop("activate")
        kwargs.pop("rollback_runtime")
        return await main.wireguard_service.create(**kwargs)

    monkeypatch.setattr(main.runtime, "diagnostics", diagnostics)
    monkeypatch.setattr(main, "command", command)
    monkeypatch.setattr(main.wireguard_service, "provision", provision)
    for provider in main.provider_registry.all():
        monkeypatch.setattr(provider, "status", status)
    monkeypatch.setattr(main.provider, "local_status", local_status)
    with TestClient(main.app) as client:
        yield Adapter(client), tmp_path


def test_seed_real_wizard_mfa_encrypted_inactive_profile(appliance):
    client, directory = appliance
    api.seed(client, directory)
    api.verify_decryption(directory)
    assert core.setting("setup_complete") is True
    assert client.call("/api/settings")["general"]["provider_refresh_interval_seconds"] == 30
    value = json.loads((directory / "fixture.json").read_text())
    assert (directory / "fixture.json").stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(core.DB) as connection:
        secret = connection.execute("SELECT encrypted_totp_secret FROM users").fetchone()[0]
    assert value["totp"].encode() not in secret
    assert (
        provider_secrets.load("proton")["profiles"][value["profile_id"]]["config"]["endpoint_host"]
        == "qa.invalid"
    )
    assert not provider_secrets.load("proton").get("active")
    assert not provider_secrets.load("proton").get("pending")


def test_restore_probe_requires_revoked_cookie_and_real_mfa(appliance):
    client, directory = appliance
    api.seed(client, directory)
    with pytest.raises(AssertionError):
        api.restored_login(client, directory)
    with sqlite3.connect(core.DB) as connection:
        connection.execute("DELETE FROM sessions")
    api.restored_login(client, directory)
    with sqlite3.connect(core.DB) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM recovery_codes WHERE used_at IS NOT NULL"
            ).fetchone()[0]
            == 1
        )


def test_decryption_probe_rejects_wrong_valid_length_key(appliance):
    client, directory = appliance
    api.seed(client, directory)
    auth_security.master_key_path().write_bytes(b"x" * 32)
    with pytest.raises(provider_secrets.ProviderSecretError):
        api.verify_decryption(directory)


def test_local_http_client_disables_environment_proxy_and_redirects(tmp_path, monkeypatch):
    monkeypatch.setenv("http_proxy", "http://external.invalid:8888")
    monkeypatch.setenv("HTTP_PROXY", "http://external.invalid:8888")
    client = api.Client(tmp_path / "cookies")
    assert not any(
        isinstance(item, api.urllib.request.ProxyHandler) for item in client.opener.handlers
    )
    redirect = next(item for item in client.opener.handlers if isinstance(item, api.NoRedirect))
    with pytest.raises(api.ApiError, match="redirect_rejected"):
        redirect.redirect_request(None, None, 302, "", {}, "https://external.invalid")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "fifo"])
def test_private_fixture_rejects_unsafe_paths(tmp_path, kind):
    path = tmp_path / "fixture.json"
    original = tmp_path / "original"
    original.write_text("private")
    original.chmod(0o600)
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "hardlink":
        path.hardlink_to(original)
    elif kind == "public":
        path.write_text("private")
        path.chmod(0o644)
    else:
        api.os.mkfifo(path, 0o600)
    with pytest.raises((OSError, api.ApiError)):
        api.private_read(path)


def test_real_loopback_transport_retains_private_cookie_and_rejects_redirect(tmp_path, monkeypatch):
    import http.server
    import threading

    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Cookie"), self.headers.get("Origin")))
            self.send_response(302 if self.path == "/api/redirect" else 200)
            if self.path == "/api/redirect":
                self.send_header("Location", "/api/forbidden-follow")
            self.send_header("Set-Cookie", "fixture_cookie=synthetic; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *args):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr(api, "BASE", base)
        path = tmp_path / "cookies"
        try:
            assert api.Client(path).call("/api/health")["ok"]
            assert path.stat().st_mode & 0o777 == 0o600
            assert api.Client(path).call("/api/health")["ok"]
            assert seen[-1] == ("/api/health", "fixture_cookie=synthetic", base)
            with pytest.raises(api.ApiError, match="redirect_rejected"):
                api.Client(path).call("/api/redirect")
            assert all(item[0] != "/api/forbidden-follow" for item in seen)
            assert not list(tmp_path.glob(".cookies-*"))
        finally:
            server.shutdown()
            thread.join(timeout=5)
