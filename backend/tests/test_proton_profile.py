import asyncio
import base64
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.providers import proton, proton_profile
from exitlane.providers.wireguard_keys import _wireguard_keypair
from exitlane.services import auth_security, provider_secrets
from exitlane.services.provider_wireguard import ProviderWireGuard


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "DB", tmp_path / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", tmp_path / "wireguard")
    monkeypatch.setattr(auth_security, "master_key_path", lambda: tmp_path / "secret.key")
    core.init()
    auth_security.ensure_master_key()

    async def arm():
        return None

    async def complete(_facts):
        return None

    monkeypatch.setattr(proton.killswitch, "arm_provider_transition", arm)
    monkeypatch.setattr(proton.killswitch, "complete_provider_transition", complete)


def profile_text(*, dual_stack=False, extra=""):
    private, public = _wireguard_keypair()
    address = "10.2.0.2/32, 2a07:e340::2/128" if dual_stack else "10.2.0.2/32"
    allowed = "0.0.0.0/0, ::/0" if dual_stack else "0.0.0.0/0"
    return (
        "# Synthetic WireGuard profile, never a provider key\n"
        f"[Interface]\nPrivateKey = {private}\nAddress = {address}\nDNS = 10.2.0.1\n"
        f"[Peer]\nPublicKey = {public}\nAllowedIPs = {allowed}\n"
        f"Endpoint = 185.1.2.3:51820\n{extra}"
    )


@pytest.mark.parametrize(
    "extra",
    [
        "PostUp = touch /tmp/unsafe\n",
        "Table = auto\n",
        "[Peer]\nPublicKey = abc\n",
        "AllowedIPs = 0.0.0.0/0\n",
        "Endpoint = 127.0.0.1:51820\n",
        "PersistentKeepalive = 999\n",
    ],
)
def test_parser_rejects_unsupported_or_ambiguous_directives(extra):
    with pytest.raises(proton_profile.ProtonProfileError):
        proton_profile.parse_profile(profile_text(extra=extra))


def test_parser_accepts_dual_stack_only_under_ipv4_protection():
    parsed = proton_profile.parse_profile(profile_text(dual_stack=True))
    assert parsed.address == "10.2.0.2/32"
    assert parsed.dns_address == "10.2.0.1"
    assert parsed.endpoint_host == "185.1.2.3"
    assert "2a07" not in json.dumps(parsed.__dict__)


def test_parser_validates_optional_preshared_key_and_size():
    psk = base64.b64encode(bytes(range(32))).decode()
    parsed = proton_profile.parse_profile(profile_text(extra=f"PresharedKey = {psk}\n"))
    assert parsed.preshared_key == psk
    config = proton.Proton._config(
        {"config": parsed.__dict__},
        {"generation": "synthetic", "endpoint_address": "185.1.2.3"},
    )
    assert ProviderWireGuard.render(config).count(f"PresharedKey = {psk}") == 1
    with pytest.raises(proton_profile.ProtonProfileError):
        proton_profile.parse_profile(profile_text(extra="PresharedKey = bad\n"))
    with pytest.raises(proton_profile.ProtonProfileError):
        proton_profile.parse_profile(profile_text() + "#" * 17000)


@pytest.mark.parametrize("field", ["MTU", "Endpoint"])
def test_parser_rejects_overlong_numeric_fields(field):
    content = profile_text()
    huge = "9" * 5000
    if field == "MTU":
        content = content.replace("[Peer]", f"MTU = {huge}\n[Peer]")
    else:
        content = content.replace("185.1.2.3:51820", f"185.1.2.3:{huge}")
    with pytest.raises(proton_profile.ProtonProfileError):
        proton_profile.parse_profile(content)


class FakeWireGuard:
    def __init__(self):
        self.started = []
        self.stopped = []
        self.ready = True

    async def start(self, config, ingress):
        self.started.append(config)

    async def probe(self, config, *, timeout):
        return {"ready": self.ready, "handshake": 1700000000 if self.ready else 0}

    async def observe(self, config):
        return {"connected": self.ready, "handshake": 1700000000}

    async def arm_source(self, interface, address):
        self.stopped.append(("source", interface))

    async def stop_interface(self, interface):
        self.stopped.append(("stop", interface))

    async def disarm(self, ingress, interface):
        self.stopped.append(("disarm", interface))

    def remove_config(self, interface):
        self.stopped.append(("remove", interface))


def test_import_encrypts_secrets_and_exposes_only_safe_metadata():
    provider = proton.Proton(wireguard=FakeWireGuard())
    content = profile_text(dual_stack=True)
    result = asyncio.run(provider.import_profile(content, "NL synthetic", "NL"))
    assert result["ok"]
    profile = result["profile"]
    assert profile["country_code"] == "NL"
    assert "private_key" not in json.dumps(profile)
    assert asyncio.run(provider.list_profiles()) == [profile]
    assert content.split("PrivateKey = ")[1].splitlines()[0].encode() not in core.DB.read_bytes()
    assert (
        asyncio.run(provider.import_profile(content, "Duplicate", "NL"))["error_code"]
        == "proton_profile_duplicate"
    )
    assert provider_secrets.load("proton")["profiles"][profile["id"]]["config"]["private_key"]


def test_connect_switch_recovery_and_active_deletion_refusal(monkeypatch):
    wireguard = FakeWireGuard()
    provider = proton.Proton(wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)
    first = asyncio.run(provider.import_profile(profile_text(), "NL 1", "NL"))["profile"]["id"]
    second = asyncio.run(provider.import_profile(profile_text(), "NL 2", "NL"))["profile"]["id"]
    assert asyncio.run(provider.connect(first, timeout=1))["ok"]
    assert provider.direct_egress_intent().provider_id == "proton"
    assert asyncio.run(provider.status())["connected"]
    assert asyncio.run(provider.delete_profile(first))["error_code"] == "proton_profile_active"
    assert asyncio.run(provider.connect(second, timeout=1))["ok"]
    assert asyncio.run(provider.status())["server"] == second
    assert asyncio.run(proton.Proton(wireguard=wireguard).status())["connected"]
    assert asyncio.run(provider.disconnect())["ok"]
    assert asyncio.run(provider.reconnect(timeout=1))["target"] == second
    assert asyncio.run(provider.disconnect())["ok"]
    assert asyncio.run(provider.delete_profile(second))["ok"]
    assert wireguard.stopped[-1] == ("remove", "wg-proton")
    assert provider_secrets.load("proton").get("last_profile_id") is None


def test_invalid_profile_target_preserves_active_tunnel():
    wireguard = FakeWireGuard()
    provider = proton.Proton(wireguard=wireguard)
    identifier = asyncio.run(provider.import_profile(profile_text(), "NL synthetic", "NL"))[
        "profile"
    ]["id"]
    assert asyncio.run(provider.connect(identifier, timeout=1))["ok"]
    started = len(wireguard.started)
    assert (
        asyncio.run(provider.connect("unknown-profile", timeout=1))["error_code"]
        == "proton_profile_not_found"
    )
    assert (
        asyncio.run(provider.connect("BE", timeout=1))["error_code"] == "proton_profile_not_found"
    )
    assert len(wireguard.started) == started
    assert asyncio.run(provider.status())["connected"]


def test_failed_profile_switch_removes_plaintext_config_and_retains_guard(monkeypatch, tmp_path):
    wireguard = FakeWireGuard()
    config_file = tmp_path / "wg-proton.conf"
    actual_wireguard = ProviderWireGuard(root=tmp_path)

    def remove_config(interface):
        actual_wireguard.remove_config(interface)
        wireguard.stopped.append(("remove", interface))

    monkeypatch.setattr(wireguard, "remove_config", remove_config)
    provider = proton.Proton(wireguard=wireguard)
    first = asyncio.run(provider.import_profile(profile_text(), "NL 1"))["profile"]["id"]
    second = asyncio.run(provider.import_profile(profile_text(), "NL 2"))["profile"]["id"]
    assert asyncio.run(provider.connect(first, timeout=1))["ok"]
    config_file.write_text(profile_text())

    async def fail_probe(_config, *, timeout):
        raise proton.ProviderWireGuardError("provider_egress_apply_failed")

    monkeypatch.setattr(wireguard, "probe", fail_probe)
    assert asyncio.run(provider.connect(second, timeout=1))["ok"] is False
    assert ("remove", "wg-proton") in wireguard.stopped
    assert not config_file.exists()
    assert ("disarm", "wg-proton") not in wireguard.stopped
    state = provider_secrets.load("proton")
    assert state["pending"]["profile_id"] == first
    assert "active" not in state


def test_delete_last_profile_removes_plaintext_wireguard_config(tmp_path):
    root = tmp_path / "provider-egress"
    root.mkdir()
    provider = proton.Proton(wireguard=ProviderWireGuard(root=root))
    content = profile_text()
    identifier = asyncio.run(provider.import_profile(content, "NL synthetic"))["profile"]["id"]
    state = provider_secrets.load("proton")
    state["last_profile_id"] = identifier
    provider_secrets.save("proton", state)
    config = root / "wg-proton.conf"
    config.write_text(content)
    assert asyncio.run(provider.delete_profile(identifier))["ok"]
    assert not config.exists()


def test_failed_first_connect_clears_pending_and_routing_rules(monkeypatch):
    wireguard = FakeWireGuard()
    provider = proton.Proton(wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)
    identifier = asyncio.run(provider.import_profile(profile_text(), "NL synthetic", "NL"))[
        "profile"
    ]["id"]

    async def fail_probe(config, *, timeout):
        raise proton.ProviderWireGuardError("provider_egress_apply_failed")

    monkeypatch.setattr(wireguard, "probe", fail_probe)
    assert asyncio.run(provider.connect(identifier, timeout=1))["ok"] is False
    assert provider.direct_egress_intent() is None
    assert wireguard.stopped[-3:] == [
        ("stop", "wg-proton"),
        ("remove", "wg-proton"),
        ("disarm", "wg-proton"),
    ]


def test_failed_config_cleanup_retains_fail_closed_intent(monkeypatch):
    wireguard = FakeWireGuard()
    provider = proton.Proton(wireguard=wireguard)
    identifier = asyncio.run(provider.import_profile(profile_text(), "NL synthetic"))["profile"][
        "id"
    ]

    async def fail_probe(config, *, timeout):
        raise proton.ProviderWireGuardError("provider_egress_apply_failed")

    def fail_remove(_interface):
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(wireguard, "probe", fail_probe)
    monkeypatch.setattr(wireguard, "remove_config", fail_remove)
    assert asyncio.run(provider.connect(identifier, timeout=1))["ok"] is False
    assert provider.direct_egress_intent() is not None


def test_profile_api_requires_admin_and_never_returns_keys(monkeypatch):
    monkeypatch.setattr(main, "DB", core.DB)
    monkeypatch.setattr(main, "WG_DIR", core.WG_DIR)
    with TestClient(main.app) as client:
        content = profile_text()
        endpoint = "/api/vpn/providers/proton/profiles"
        assert client.get(endpoint).status_code == 401
        digest, salt = core.hash_password("correct horse battery staple")
        with sqlite3.connect(core.DB) as connection:
            connection.execute(
                "INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        core.set_setting("setup_provider_ids", ["proton"])
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct horse battery staple"},
            ).status_code
            == 200
        )
        imported = client.post(
            endpoint,
            json={"config": content, "display_name": "NL synthetic", "country_code": "NL"},
        )
        assert imported.status_code == 200, imported.json()
        assert core.setting("setup_provider_complete") is True
        assert core.setting("vpn.provider_id") == "proton"
        with sqlite3.connect(core.DB) as connection:
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE code='provider.profile_imported'"
                ).fetchone()[0]
                == 1
            )
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM events WHERE code='provider.session_started'"
                ).fetchone()[0]
                == 0
            )
        identifier = imported.json()["profile"]["id"]
        listing = client.get(endpoint)
        assert listing.status_code == 200
        assert listing.json()["profiles"][0]["id"] == identifier
        private_key = content.split("PrivateKey = ")[1].splitlines()[0]
        assert private_key not in json.dumps(imported.json())
        assert private_key not in json.dumps(listing.json())
        assert (
            client.post(
                endpoint,
                json={"config": content, "display_name": "Duplicate", "country_code": "NL"},
            ).status_code
            == 422
        )
        assert client.delete(f"{endpoint}/{identifier}").status_code == 200
