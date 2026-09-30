import asyncio
import base64
import json
import sqlite3
import ssl

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.providers import pia, pia_api
from exitlane.services import auth_security, provider_secrets

PEER_KEY = base64.b64encode(bytes(range(32))).decode()
SERVER = pia_api.PiaServer(
    "nl_amsterdam", "NL Amsterdam", "NL", "amsterdam401", "193.138.218.74", "193.138.218.1"
)
RESPONSE = pia_api.PiaKeyResponse("10.4.1.2/32", PEER_KEY, 1337, "10.0.0.242")


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "DB", tmp_path / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", tmp_path / "wireguard")
    monkeypatch.setattr(auth_security, "master_key_path", lambda: tmp_path / "secret.key")
    core.init()
    auth_security.ensure_master_key()

    async def arm():
        core.set_setting(pia.killswitch.SETTING_TRANSITION, True)

    async def complete(_facts):
        core.set_setting(pia.killswitch.SETTING_TRANSITION, False)

    monkeypatch.setattr(pia.killswitch, "arm_provider_transition", arm)
    monkeypatch.setattr(pia.killswitch, "complete_provider_transition", complete)


class FakeBoundary:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.fail = None
        self.calls = []

    async def token(self):
        self.calls.append("token")
        if self.fail:
            raise pia_api.PiaApiError(self.fail)
        return "a" * 40

    async def catalog(self):
        self.calls.append("catalog")
        return [SERVER]

    async def add_key(self, server, public):
        self.calls.append(("add_key", server, public))
        if self.fail:
            raise pia_api.PiaApiError(self.fail)
        return RESPONSE


class ObservedWireGuard:
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
        self.stopped.append(("source", interface, address))

    async def stop_interface(self, interface):
        self.stopped.append(("stop", interface))

    async def disarm(self, ingress, interface):
        self.stopped.append(("disarm", interface))

    def remove_config(self, interface):
        self.stopped.append(("remove", interface))


def test_pia_contract_parses_sanitized_catalog_and_rejects_unsafe_fields():
    catalog = {
        "regions": [
            {
                "id": "nl_amsterdam",
                "name": "NL Amsterdam",
                "country": "NL",
                "offline": False,
                "servers": {
                    "meta": [{"ip": "193.138.218.1"}],
                    "wg": [{"ip": "193.138.218.74", "cn": "Amsterdam401"}],
                },
            }
        ]
    }
    assert pia_api.parse_catalog(catalog) == [SERVER]
    assert SERVER.selection_id == "nl_amsterdam.amsterdam401"
    for changed in (
        {"ip": "127.0.0.1", "cn": "Amsterdam401"},
        {"ip": "193.138.218.74", "cn": "evil.example.com"},
    ):
        catalog["regions"][0]["servers"]["wg"] = [changed]
        with pytest.raises(pia_api.PiaApiError, match="provider_api_invalid_response"):
            pia_api.parse_catalog(catalog)


def test_add_key_response_requires_exact_safe_network_shape():
    valid = {
        "status": "OK",
        "peer_ip": "10.4.1.2/32",
        "server_key": PEER_KEY,
        "server_port": 1337,
        "dns_servers": ["10.0.0.242"],
    }
    assert pia_api.PiaKeyResponse.parse(valid) == RESPONSE
    assert pia_api.PiaKeyResponse.parse({**valid, "peer_ip": "10.4.1.2"}) == RESPONSE
    with pytest.raises(pia_api.PiaApiError, match="provider_api_invalid_response"):
        pia_api.PiaKeyResponse.parse(
            {**valid, "peer_pubkey": PEER_KEY},
            expected_public_key=base64.b64encode(bytes(range(1, 33))).decode(),
        )
    for field, replacement in (
        ("peer_ip", "10.4.1.2/24"),
        ("server_key", "bad"),
        ("server_port", True),
        ("dns_servers", ["127.0.0.1\nPostUp=oops"]),
        ("dns_servers", ["0.0.0.0"]),
    ):
        with pytest.raises(pia_api.PiaApiError, match="provider_api_invalid_response"):
            pia_api.PiaKeyResponse.parse({**valid, field: replacement})


def test_token_is_bounded_cached_in_memory_and_renewed(monkeypatch):
    client = pia_api.PiaApi("p1234567", "safe-password")
    requests = []

    def request(url, *, form=None, boundary=None, maximum):
        requests.append((url, form, boundary, maximum))
        return json.dumps({"token": "a" * 40}).encode()

    monkeypatch.setattr(client, "_public_request", request)
    assert asyncio.run(client.token()) == "a" * 40
    assert asyncio.run(client.token()) == "a" * 40
    assert len(requests) == 1
    assert requests[0][0] == pia_api.TOKEN_URL
    assert b'name="username"\r\n\r\np1234567\r\n' in requests[0][1]
    assert b'name="password"\r\n\r\nsafe-password\r\n' in requests[0][1]
    assert requests[0][2].startswith("exitlane-")
    client._token_deadline = 0
    assert asyncio.run(client.token()) == "a" * 40
    assert len(requests) == 2


@pytest.mark.parametrize("operation", ["token", "catalog"])
def test_pia_api_maps_excessive_json_nesting_to_safe_error(monkeypatch, operation):
    client = pia_api.PiaApi("p1234567", "safe-password")
    nested = b"[" * 10_000 + b"0" + b"]" * 10_000
    monkeypatch.setattr(client, "_public_request", lambda *_args, **_kwargs: nested)

    with pytest.raises(pia_api.PiaApiError, match="provider_api_invalid_response"):
        asyncio.run(getattr(client, operation)())


def test_token_transport_uses_multipart_and_refuses_redirect():
    client = pia_api.PiaApi()
    captured = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, maximum):
            return b'{"token":"' + b"a" * 40 + b'"}'

    class Opener:
        def open(self, request, *, timeout):
            captured.append(request)
            return Response()

    client._opener = Opener()
    client._public_request(
        pia_api.TOKEN_URL, form=b"bounded-form", boundary="exitlane-test", maximum=1024
    )
    assert captured[0].get_header("Content-type") == "multipart/form-data; boundary=exitlane-test"
    assert captured[0].data == b"bounded-form"
    assert (
        pia_api._NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.invalid")
        is None
    )


def test_add_key_uses_catalog_ip_and_hostname_verified_tls(monkeypatch):
    calls = []

    class Response:
        status = 200

        def read(self, maximum):
            assert maximum == pia_api.MAX_ACCOUNT_RESPONSE + 1
            return json.dumps(
                {
                    "status": "OK",
                    "peer_ip": RESPONSE.peer_ip,
                    "server_key": RESPONSE.server_key,
                    "server_port": RESPONSE.server_port,
                    "dns_servers": [RESPONSE.dns_address],
                }
            ).encode()

    class Connection:
        def __init__(self, hostname, address):
            calls.append(("connect", hostname, address))

        def request(self, method, path, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return Response()

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(pia_api, "_PinnedConnection", Connection)
    client = pia_api.PiaApi()
    result = client._add_key_sync(SERVER, "a" * 40, PEER_KEY)
    assert result == RESPONSE
    assert calls[0] == ("connect", SERVER.hostname, SERVER.address)
    assert calls[1][0] == "GET"
    assert calls[1][1].startswith("/addKey?pt=")
    assert "pubkey=" in calls[1][1]
    assert calls[-1] == ("close",)


def test_add_key_tls_verification_failure_is_safe(monkeypatch):
    class InvalidCertificate:
        def __init__(self, hostname, address):
            raise ssl.SSLCertVerificationError("certificate verify failed")

    monkeypatch.setattr(pia_api, "_PinnedConnection", InvalidCertificate)
    with pytest.raises(pia_api.PiaApiError) as failure:
        pia_api.PiaApi()._add_key_sync(SERVER, "a" * 40, PEER_KEY)
    assert failure.value.code == "provider_api_unavailable"
    assert "a" * 40 not in str(failure.value)


def test_add_key_maps_excessive_json_nesting_to_safe_error(monkeypatch):
    class Response:
        status = 200

        def read(self, _maximum):
            return b"[" * 10_000 + b"0" + b"]" * 10_000

    class Connection:
        def __init__(self, *_args):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(pia_api, "_PinnedConnection", Connection)
    with pytest.raises(pia_api.PiaApiError, match="provider_api_invalid_response"):
        pia_api.PiaApi()._add_key_sync(SERVER, "a" * 40, PEER_KEY)


def test_credential_boundary_rejects_control_characters_and_delimiters():
    assert pia.validate_credentials("p1234567", "safe-password") is True
    for username, password in (("bad-user", "pass"), ("user", "pa\rword"), ("user\nother", "pass")):
        assert pia.validate_credentials(username, password) is False


def test_pia_api_authentication_accepts_only_structured_pair_and_redacts(monkeypatch):
    monkeypatch.setattr(main, "DB", core.DB)
    monkeypatch.setattr(main, "WG_DIR", core.WG_DIR)
    monkeypatch.setattr(
        pia.provider, "api_factory", lambda username, password: FakeBoundary(username, password)
    )
    monkeypatch.setattr(pia.provider, "_tools_available", lambda: True)
    pia.provider._api = None
    with TestClient(main.app) as client:
        digest, salt = core.hash_password("correct horse battery staple")
        with sqlite3.connect(core.DB) as connection:
            connection.execute(
                "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
                ("admin", digest, salt),
            )
        core.set_setting("setup_complete", True)
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct horse battery staple"},
            ).status_code
            == 200
        )
        route = "/api/vpn/providers/pia/authenticate"
        assert client.post(route, json={"credential": "p1234567\nsafe-password"}).status_code == 422
        assert client.post(route, json={"username": "p1234567"}).status_code == 422
        result = client.post(route, json={"username": "p1234567", "password": "safe-password"})
        assert result.status_code == 200 and result.json()["ok"] is True
        catalog = client.get("/api/vpn/providers")
        assert catalog.status_code == 200
        assert "safe-password" not in catalog.text
        assert "p1234567" not in catalog.text
        assert catalog.json()["providers"]
    pia.provider._api = None


def test_authentication_encrypted_lifecycle_and_direct_connect(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]
    with sqlite3.connect(core.DB) as connection:
        encrypted = connection.execute(
            "SELECT encrypted_payload FROM provider_secrets WHERE provider_id='pia'"
        ).fetchone()[0]
    assert b"safe-password" not in encrypted and b"p1234567" not in encrypted
    result = asyncio.run(provider.connect("NL", timeout=1))
    assert result["ok"] is True
    assert wireguard.started[0].provider_id == "pia"
    assert wireguard.started[0].interface == "wg-pia"
    assert wireguard.started[0].endpoint_address == SERVER.address
    assert provider.direct_egress_intent().source_address == "10.4.1.2/32"
    status = asyncio.run(provider.status())
    assert status["connected"] is True and status["country_code"] == "NL"
    assert "password" not in json.dumps(status) and "private_key" not in json.dumps(status)
    assert status["server"] == SERVER.selection_id
    assert asyncio.run(provider.disconnect())["ok"] is True
    assert asyncio.run(provider.sign_out())["ok"] is True
    assert provider_secrets.load("pia") is None


def test_sign_out_inactive_pia_preserves_another_direct_provider_table(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)

    async def other_provider_owns_shared_table(_ingress, _interface):
        raise pia.ProviderWireGuardError("provider_egress_resource_conflict")

    monkeypatch.setattr(wireguard, "disarm", other_provider_owns_shared_table)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]
    assert asyncio.run(provider.sign_out())["ok"]
    assert provider_secrets.load("pia") is None


def test_initial_remote_failure_clears_safe_pending_intent_and_allows_sign_out(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]
    boundary.fail = "provider_api_unavailable"
    failed = asyncio.run(provider.connect("NL", timeout=1))
    assert failed["ok"] is False
    assert failed["error_code"] == "provider_api_unavailable"
    assert provider.direct_egress_intent() is None
    assert "pending" not in provider_secrets.load("pia")
    assert asyncio.run(provider.sign_out())["ok"]


def test_uncertain_teardown_retains_fail_closed_boot_intent(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]
    boundary.fail = "provider_api_unavailable"

    async def fail_teardown(_interface):
        raise pia.ProviderWireGuardError("provider_egress_teardown_failed")

    monkeypatch.setattr(wireguard, "stop_interface", fail_teardown)
    assert asyncio.run(provider.connect("NL", timeout=1))["ok"] is False
    assert provider.direct_egress_intent() is not None
    assert asyncio.run(provider.sign_out())["ok"] is False


def test_failed_first_tunnel_clears_pia_rules_before_provider_switch_rollback(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]

    async def failed_probe(config, *, timeout):
        raise pia.ProviderWireGuardError("provider_egress_apply_failed")

    monkeypatch.setattr(wireguard, "probe", failed_probe)
    result = asyncio.run(provider.connect("NL", timeout=1))
    assert result["ok"] is False
    assert wireguard.started
    assert wireguard.stopped[-2:] == [("stop", "wg-pia"), ("disarm", "wg-pia")]
    assert provider.direct_egress_intent() is None
    assert asyncio.run(provider.sign_out())["ok"]


def test_country_servers_preserve_region_identity_for_latency_selection():
    provider = pia.Pia(api_factory=lambda username, password: FakeBoundary(username, password))
    other = pia_api.PiaServer(
        "nl_rotterdam", "NL Rotterdam", "NL", "amsterdam401", "193.138.218.75", "193.138.218.2"
    )
    extra = pia_api.PiaServer(
        "nl_amsterdam", "NL Amsterdam", "NL", "amsterdam402", "193.138.218.76", "193.138.218.1"
    )
    provider._catalog = [SERVER, extra, other]
    provider._catalog_deadline = float("inf")
    servers = asyncio.run(provider.servers("NL"))
    assert [item["hostname"] for item in servers] == [
        SERVER.selection_id,
        other.selection_id,
        extra.selection_id,
    ]
    assert servers[0]["station"] != servers[1]["station"]
    assert asyncio.run(provider._select(other.selection_id)) == other


def test_failed_new_generation_restores_previous_proven_generation(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]
    assert asyncio.run(provider.connect("NL", timeout=1))["ok"]
    old = provider_secrets.load("pia")["active"]
    calls = 0

    async def probe(config, *, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise pia.ProviderWireGuardError("provider_egress_apply_failed")
        return {"ready": calls > 1, "handshake": 1700000000 if calls > 1 else 0}

    monkeypatch.setattr(wireguard, "probe", probe)
    result = asyncio.run(provider.connect("NL", timeout=1))
    assert result["ok"] is False
    assert provider_secrets.load("pia")["active"] == old
    assert provider_secrets.load("pia").get("pending") is None


def test_rollback_rebinds_old_key_when_new_key_displaced_peer(monkeypatch):
    boundary = FakeBoundary("p1234567", "safe-password")
    wireguard = ObservedWireGuard()
    provider = pia.Pia(api_factory=lambda username, password: boundary, wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)
    assert asyncio.run(provider.authenticate_credentials("p1234567", "safe-password"))["ok"]
    assert asyncio.run(provider.connect("NL", timeout=1))["ok"]
    previous = provider_secrets.load("pia")["active"]
    calls = 0

    async def probe(config, *, timeout):
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise pia.ProviderWireGuardError("provider_egress_apply_failed")
        return {"ready": True, "handshake": 1700000000}

    monkeypatch.setattr(wireguard, "probe", probe)
    result = asyncio.run(provider.connect("NL", timeout=1))
    assert result["ok"] is False
    assert provider_secrets.load("pia")["active"]["public_key"] == previous["public_key"]
    assert boundary.calls[-1] == ("add_key", SERVER, previous["public_key"])
