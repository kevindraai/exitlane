"""Synthetic native qualification state, invoked only after guest/run preflight.

Uses installed application dependencies. Never contacts a VPN provider or starts a tunnel.
Private fixture files stay on the explicitly disposable guest.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import secrets
import stat
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8787"
RUNS = Path("/root/exitlane-native-qualification")


class ApiError(RuntimeError):
    pass


def require(value):
    if not value:
        raise ApiError("qualification_api_assertion_failed")


def private_read(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 2_000_000
        )
        value = stream.read(2_000_001)
        require(len(value) <= 2_000_000)
        return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise ApiError("qualification_api_redirect_rejected")


class Client:
    def __init__(self, cookie_file: Path):
        self.path = cookie_file
        self.jar = http.cookiejar.LWPCookieJar(str(cookie_file))
        if cookie_file.exists():
            private_read(cookie_file)
            self.jar.load(ignore_discard=True, ignore_expires=True)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def call(self, path, data=None, *, method=None, expected=200):
        require(path.startswith("/api/") and "?" not in path and "#" not in path)
        request = urllib.request.Request(
            BASE + path,
            data=json.dumps(data).encode() if data is not None else None,
            method=method or ("POST" if data is not None else "GET"),
            headers={"Origin": BASE, "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=45) as response:
                status, body = response.status, response.read(2_000_001)
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read(2_000_001)
        if status != expected or len(body) > 2_000_000:
            raise ApiError("qualification_api_response_invalid")
        descriptor, temporary = tempfile.mkstemp(
            dir=self.path.parent, prefix=".cookies-"
        )
        os.close(descriptor)
        try:
            self.jar.save(temporary, ignore_discard=True, ignore_expires=True)
            os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return json.loads(body)


def write_private(path: Path, value):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream)


def seed(client, directory: Path):
    import pyotp
    from exitlane.providers.wireguard_keys import _wireguard_keypair

    require(client.call("/api/diagnostics")["ok"])
    auth = {"username": "native-qualification", "password": secrets.token_urlsafe(36)}
    require(client.call("/api/setup/admin", auth)["authenticated"])
    require(client.call("/api/setup/provider/defer", {})["provider_deferred"])
    network = client.call("/api/system/network")
    client.call(
        "/api/ingress/wireguard",
        {
            "endpoint": network["endpoint"],
            "interface": "wg-qa",
            "subnet": "10.98.240.0/24",
            "client": "qualification-router",
        },
    )
    require(client.call("/api/setup/complete", {})["ok"])
    enrollment = client.call(
        "/api/auth/mfa/enrollment", {"current_password": auth["password"]}
    )
    auth["totp"] = enrollment["setup_key"]
    codes = client.call(
        "/api/auth/mfa/enrollment/confirm",
        {
            "enrollment": enrollment["enrollment"],
            "code": pyotp.TOTP(auth["totp"]).now(),
        },
    )
    auth["recovery_codes"] = codes["recovery_codes"]
    client.call(
        "/api/settings",
        {"general": {"provider_refresh_interval_seconds": 30}},
        method="PUT",
    )
    private, _ = _wireguard_keypair()
    _, peer_public = _wireguard_keypair()
    profile = (
        f"[Interface]\nPrivateKey = {private}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n"
        f"[Peer]\nPublicKey = {peer_public}\nAllowedIPs = 0.0.0.0/0\nEndpoint = qa.invalid:51820\n"
    )
    result = client.call(
        "/api/vpn/providers/proton/profiles",
        {
            "config": profile,
            "display_name": "Synthetic preservation only",
            "country_code": "NL",
        },
    )
    auth["profile_id"] = result["profile"]["id"]
    auth["profile_private_key"] = private
    write_private(directory / "fixture.json", auth)
    verify_decryption(directory)


def verify_decryption(directory: Path):
    import sqlite3

    from exitlane import core
    from exitlane.services import auth_security, provider_secrets

    auth = json.loads(private_read(directory / "fixture.json"))
    state = provider_secrets.load("proton")
    require(
        isinstance(state, dict) and not state.get("active") and not state.get("pending")
    )
    require(
        state["profiles"][auth["profile_id"]]["config"]["private_key"]
        == auth["profile_private_key"]
    )
    with sqlite3.connect(core.DB) as connection:
        row = connection.execute(
            "SELECT encrypted_totp_secret FROM users WHERE username=?",
            (auth["username"],),
        ).fetchone()
    require(row is not None)
    require(auth_security.decrypt_secret(row[0]) == auth["totp"])


def restored_login(client, directory: Path):
    verify_decryption(directory)
    client.call("/api/settings", expected=401)
    auth = json.loads(private_read(directory / "fixture.json"))
    response = client.call(
        "/api/auth/login", {"username": auth["username"], "password": auth["password"]}
    )
    require(response["mfa_required"] and not response["authenticated"])
    verified = client.call(
        "/api/auth/mfa", {"mode": "recovery", "code": auth["recovery_codes"][0]}
    )
    require(verified["authenticated"] and verified["recovery_code_used"])
    client.call("/api/settings")


def validate_run(directory: Path):
    require(
        os.geteuid() == 0
        and directory.parent == RUNS
        and directory.resolve() == directory
    )
    for item in (RUNS, directory):
        info = item.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700
        )
    identity = json.loads(private_read(directory / "identity.json"))
    require(identity.get("type") == "native-guest")
    import hashlib

    for name in (
        "native_lifecycle.py",
        "native_lifecycle_state.py",
        "native_lifecycle_api.py",
    ):
        require(
            identity.get("harness", {}).get(name)
            == hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        )


def run(action: str, directory: Path):
    validate_run(directory)
    client = Client(directory / "cookies")
    if action == "seed":
        seed(client, directory)
    elif action == "verify":
        verify_decryption(directory)
        require(client.call("/api/auth/session")["authenticated"])
    elif action == "canary":
        client.call(
            "/api/settings",
            {"general": {"provider_refresh_interval_seconds": 45}},
            method="PUT",
        )
    elif action in {"restored-login", "disaster-login"}:
        # Disaster uses a new cookie jar: DB revocation + fresh MFA, not old-cookie proof.
        restored_login(client, directory)
    else:
        raise ApiError("qualification_api_action_invalid")


if __name__ == "__main__":
    import sys

    os.umask(0o077)
    try:
        run(sys.argv[1], Path(sys.argv[2]))
    except Exception:  # noqa: BLE001 - final boundary must not print secret-bearing tracebacks
        # Child output never contains cookies, provider state, credentials or raw responses.
        raise SystemExit("qualification_api_probe_failed") from None
    print("qualification_api_probe_passed")
