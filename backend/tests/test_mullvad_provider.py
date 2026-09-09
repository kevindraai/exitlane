import asyncio
import base64
import sqlite3

import pytest

from exitlane import core
from exitlane.providers import mullvad
from exitlane.services import auth_security, provider_secrets

ACCOUNT = "1234123412341234"
PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode()
PUBLIC_KEY = mullvad._public_key_for_private(PRIVATE_KEY)
assert PUBLIC_KEY is not None
RELAY_KEY = base64.b64encode(bytes(range(2, 34))).decode()


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "DB", tmp_path / "exitlane.db")
    monkeypatch.setattr(auth_security, "master_key_path", lambda: tmp_path / "secret.key")
    core.init()
    auth_security.ensure_master_key()

    async def arm_transition():
        core.set_setting(mullvad.killswitch.SETTING_TRANSITION, True)

    async def complete_transition(_facts):
        core.set_setting(mullvad.killswitch.SETTING_TRANSITION, False)

    monkeypatch.setattr(mullvad.killswitch, "arm_provider_transition", arm_transition)
    monkeypatch.setattr(mullvad.killswitch, "complete_provider_transition", complete_transition)


class FakeApi:
    def __init__(self, account, *, devices=None, create=None, relays=None, error=None):
        self.account = account
        self.device_values = list(devices or [])
        self.created = create
        self.relay_values = list(relays or [])
        self.error = error
        self.calls = []

    async def devices(self):
        self.calls.append("devices")
        if self.error:
            raise mullvad.MullvadApiError(self.error)
        return list(self.device_values)

    async def create_device(self, pubkey):
        self.calls.append(("create", pubkey))
        if self.error:
            raise mullvad.MullvadApiError(self.error)
        return self.created

    async def delete_device(self, identifier):
        self.calls.append(("delete", identifier))
        if self.error:
            raise mullvad.MullvadApiError(self.error)

    async def relays(self):
        self.calls.append("relays")
        if self.error:
            raise mullvad.MullvadApiError(self.error)
        return list(self.relay_values)


class FakeWireGuard:
    def __init__(self, *, ready=True):
        self.ready = ready
        self.started = []
        self.stopped = []

    async def start(self, config, ingress):
        self.started.append((config, tuple(ingress)))

    async def probe(self, config, *, timeout):
        return {"ready": self.ready, "handshake": 1700000000 if self.ready else 0}

    async def observe(self, config):
        return {"connected": self.ready, "ready": self.ready, "handshake": 1700000000}

    async def stop_interface(self, interface):
        self.stopped.append(interface)

    async def disarm(self, ingress, interface):
        self.stopped.append((tuple(ingress), interface))

    def remove_config(self, interface):
        self.stopped.append(("remove", interface))


def device(pubkey=PUBLIC_KEY):
    return mullvad.Device(
        id="eac29d25-1cd0-49bf-8f6a-6e3b99e29d93",
        name="brave-wolf",
        pubkey=pubkey,
        ipv4_address="10.67.12.34/32",
        ipv6_address="fc00:bbbb:bbbb:bb01::1234/128",
    )


def relay(hostname="nl-ams-wg-001"):
    return mullvad.Relay(
        hostname=hostname,
        country_code="nl",
        country="Netherlands",
        city_code="ams",
        city="Amsterdam",
        endpoint="193.138.218.78",
        pubkey=RELAY_KEY,
    )


def registered_state(*, active=None):
    value = {
        "version": 1,
        "registration": "registered",
        "account_number": ACCOUNT,
        "private_key": PRIVATE_KEY,
        "public_key": PUBLIC_KEY,
        "device_id": device().id,
        "device_name": device().name,
        "ipv4_address": device().ipv4_address,
        "ipv6_address": device().ipv6_address,
    }
    if active:
        value["active"] = active
    provider_secrets.save("mullvad", value)
    return value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ACCOUNT, ACCOUNT),
        ("1234 1234 1234 1234", ACCOUNT),
        (" 1234\t1234\n1234 1234 ", ACCOUNT),
        ("1234-1234-1234-1234", None),
        ("123412341234123", None),
    ],
)
def test_account_number_normalization(value, expected):
    assert mullvad.normalize_account_number(value) == expected


def test_provider_metadata_describes_direct_wireguard():
    assert mullvad.Mullvad().metadata.as_dict()["description"] == "Direct Mullvad WireGuard egress"


def test_device_and_relay_parsers_reject_unsafe_network_values():
    valid_device = {
        "id": device().id,
        "name": "brave-wolf",
        "pubkey": PUBLIC_KEY,
        "ipv4_address": "10.67.12.34/32",
        "ipv6_address": "fc00:bbbb:bbbb:bb01::1234/128",
    }
    assert mullvad.Device.parse(valid_device) == device()
    invalid = dict(valid_device, ipv4_address="10.67.12.34/24")
    with pytest.raises(mullvad.MullvadApiError, match="provider_api_invalid_response"):
        mullvad.Device.parse(invalid)

    valid_relay = {
        "type": "wireguard",
        "active": True,
        "hostname": "nl-ams-wg-001",
        "country_code": "nl",
        "country_name": "Netherlands",
        "city_code": "ams",
        "city_name": "Amsterdam",
        "ipv4_addr_in": "193.138.218.78",
        "pubkey": RELAY_KEY,
    }
    assert mullvad.Relay.parse(valid_relay) == relay()
    assert mullvad.Relay.parse(dict(valid_relay, ipv4_addr_in="192.168.1.1")) is None
    assert mullvad.Relay.parse(dict(valid_relay, active=False)) is None


def test_authenticate_persists_pending_key_before_remote_device_create(monkeypatch):
    observed = []

    class Api(FakeApi):
        async def devices(self):
            state = provider_secrets.load("mullvad")
            observed.append(None if state is None else state["registration"])
            return []

        async def create_device(self, pubkey):
            state = provider_secrets.load("mullvad")
            observed.append((state["registration"], state["public_key"]))
            return device(pubkey)

    api = Api(ACCOUNT)
    monkeypatch.setattr(mullvad, "_wireguard_keypair", lambda: (PRIVATE_KEY, PUBLIC_KEY))
    provider = mullvad.Mullvad(api_factory=lambda account: api)

    result = asyncio.run(provider.authenticate("1234 1234 1234 1234"))

    assert result == {"ok": True, "error": None}
    assert observed == [None, ("pending", PUBLIC_KEY)]
    stored = provider_secrets.load("mullvad")
    assert stored["registration"] == "registered"
    assert stored["device_id"] == device().id


def test_authenticate_reconciles_uncertain_create_by_public_key():
    provider_secrets.save(
        "mullvad",
        {
            "version": 1,
            "registration": "pending",
            "account_number": ACCOUNT,
            "private_key": PRIVATE_KEY,
            "public_key": PUBLIC_KEY,
        },
    )
    api = FakeApi(ACCOUNT, devices=[device()])
    provider = mullvad.Mullvad(api_factory=lambda account: api)

    assert asyncio.run(provider.authenticate(ACCOUNT))["ok"] is True
    assert api.calls == ["devices"]


def test_authenticate_timeout_keeps_pending_key_for_reconciliation(monkeypatch):
    class Api(FakeApi):
        async def create_device(self, pubkey):
            raise mullvad.MullvadApiError("provider_api_timeout")

    api = Api(ACCOUNT)
    monkeypatch.setattr(mullvad, "_wireguard_keypair", lambda: (PRIVATE_KEY, PUBLIC_KEY))
    provider = mullvad.Mullvad(api_factory=lambda account: api)

    assert asyncio.run(provider.authenticate(ACCOUNT)) == {
        "ok": False,
        "error": "provider_api_timeout",
    }
    state = provider_secrets.load("mullvad")
    assert state["registration"] == "pending"
    assert state["public_key"] == PUBLIC_KEY


def test_connect_uses_dedicated_interface_and_forwarded_ingress_rules(monkeypatch):
    registered_state()
    api = FakeApi(None, devices=[device()], relays=[relay()])
    wireguard = FakeWireGuard()
    monkeypatch.setattr(mullvad.killswitch, "configuration", lambda: (("wg0", "lan0"), ()))
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)

    result = asyncio.run(provider.connect("nl", timeout=1))

    assert result["ok"] is True
    config, ingress = wireguard.started[0]
    assert config.interface == "wg-mullvad"
    assert config.address == "10.67.12.34/32"
    assert config.endpoint_address == "193.138.218.78"
    assert config.mtu == 1380
    assert ingress == ("wg0", "lan0")
    state = provider_secrets.load("mullvad")
    assert "pending" not in state
    assert state["active"]["relay"]["hostname"] == "nl-ams-wg-001"


def test_connect_keeps_transition_guard_when_firewall_release_fails(monkeypatch):
    registered_state()
    api = FakeApi(None, devices=[device()], relays=[relay()])
    wireguard = FakeWireGuard()

    async def fail_release(_facts):
        raise mullvad.killswitch.KillswitchError("firewall_apply_failed")

    monkeypatch.setattr(mullvad.killswitch, "complete_provider_transition", fail_release)
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)

    result = asyncio.run(provider.connect("nl", timeout=1))

    assert result["ok"] is False
    assert result["error_code"] == "firewall_apply_failed"
    assert provider_secrets.load("mullvad")["active"]["relay"]["hostname"] == relay().hostname
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is True


def test_status_requires_exact_local_wireguard_observation(monkeypatch):
    active = {"generation": "a" * 32, "relay": relay().__dict__, "handshake": 1}
    registered_state(active=active)
    wireguard = FakeWireGuard(ready=True)
    provider = mullvad.Mullvad(wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)

    status = asyncio.run(provider.status())

    assert status["connected"] is True
    assert status["tunnel_interface"] == "wg-mullvad"
    assert status["management"]["authentication"]["state"] == "signed_in"


def test_disconnect_disarms_provider_rules_under_temporary_guard():
    registered_state(active={"generation": "a" * 32, "relay": relay().__dict__, "handshake": 1})
    wireguard = FakeWireGuard()
    provider = mullvad.Mullvad(wireguard=wireguard)

    result = asyncio.run(provider.disconnect())

    assert result["ok"] is True
    assert "active" not in provider_secrets.load("mullvad")
    assert "wg-mullvad" in wireguard.stopped
    assert (("wg0",), "wg-mullvad") in wireguard.stopped
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is False


def test_connect_cancellation_preserves_fail_closed_pending_candidate(monkeypatch):
    registered_state()
    api = FakeApi(None, devices=[device()], relays=[relay()])

    class CancelledWireGuard(FakeWireGuard):
        async def probe(self, config, *, timeout):
            raise asyncio.CancelledError

    wireguard = CancelledWireGuard()
    monkeypatch.setattr(mullvad.killswitch, "configuration", lambda: (("wg0",), ()))
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(provider.connect("nl", timeout=1))

    state = provider_secrets.load("mullvad")
    assert state["pending"]["relay"]["hostname"] == relay().hostname
    assert "active" not in state
    assert "wg-mullvad" in wireguard.stopped
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is True


def test_failed_previous_generation_restore_stays_persistently_fail_closed(monkeypatch):
    previous = {"generation": "a" * 32, "relay": relay("nl-ams-wg-002").__dict__, "handshake": 1}
    registered_state(active=previous)
    api = FakeApi(None, devices=[device()], relays=[relay()])
    wireguard = FakeWireGuard(ready=False)
    monkeypatch.setattr(mullvad.killswitch, "configuration", lambda: (("wg0",), ()))
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)

    result = asyncio.run(provider.connect("nl", timeout=0.01))

    assert result["ok"] is False
    state = provider_secrets.load("mullvad")
    assert "active" not in state
    assert state["pending"]["recovery"] == "restore_previous"
    assert len(wireguard.started) == 2
    assert "wg-mullvad" in wireguard.stopped
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is True


def test_successful_retry_claims_and_releases_inherited_recovery_guard(monkeypatch):
    registered_state()
    api = FakeApi(None, devices=[device()], relays=[relay()])
    wireguard = FakeWireGuard(ready=False)
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)

    assert asyncio.run(provider.connect("nl", timeout=0.01))["ok"] is False
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is True
    assert "pending" in provider_secrets.load("mullvad")

    wireguard.ready = True
    assert asyncio.run(provider.connect("nl", timeout=1))["ok"] is True
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is False
    assert "pending" not in provider_secrets.load("mullvad")


def test_explicit_disconnect_clears_inherited_recovery_guard():
    state = registered_state()
    state["pending"] = {"recovery": "failed_connect"}
    provider_secrets.save("mullvad", state)
    core.set_setting(mullvad.killswitch.SETTING_TRANSITION, True)
    provider = mullvad.Mullvad(wireguard=FakeWireGuard())

    assert asyncio.run(provider.disconnect())["ok"] is True

    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is False
    assert "pending" not in provider_secrets.load("mullvad")


def test_external_provider_switch_retains_transition_ownership(monkeypatch):
    registered_state()
    api = FakeApi(None, devices=[device()], relays=[relay()])
    core.set_setting(mullvad.killswitch.SETTING_TRANSITION, True)
    monkeypatch.setattr(
        mullvad.vpn_operations,
        "active_snapshot",
        lambda: {"connection_id": "provider-switch", "state": "switching"},
    )
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=FakeWireGuard())

    assert asyncio.run(provider.connect("nl", timeout=1))["ok"] is True
    assert core.setting(mullvad.killswitch.SETTING_TRANSITION) is True


def test_prepare_activation_does_not_recreate_revoked_device(monkeypatch):
    registered_state()
    api = FakeApi(ACCOUNT, devices=[])
    wireguard = FakeWireGuard()
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)
    monkeypatch.setattr(provider, "_tools_available", lambda: True)

    result = asyncio.run(provider.prepare_activation())

    assert result == {"ok": False, "error_code": "device_revoked"}
    assert api.calls == ["devices"]
    assert provider_secrets.load("mullvad")["registration"] == "registered"


def test_sign_out_deletes_only_the_bound_device_then_local_secret():
    registered_state()
    api = FakeApi(ACCOUNT)
    wireguard = FakeWireGuard()
    provider = mullvad.Mullvad(api_factory=lambda account: api, wireguard=wireguard)

    result = asyncio.run(provider.sign_out())

    assert result == {"ok": True, "error": None, "already_signed_out": False}
    assert api.calls == [("delete", device().id)]
    assert provider_secrets.load("mullvad") is None
    assert ("remove", "wg-mullvad") in wireguard.stopped


def test_provider_secret_database_contains_no_plaintext_account_or_private_key():
    registered_state()
    with sqlite3.connect(core.DB) as connection:
        encrypted = bytes(
            connection.execute(
                "SELECT encrypted_payload FROM provider_secrets WHERE provider_id='mullvad'"
            ).fetchone()[0]
        )
    assert ACCOUNT.encode() not in encrypted
    assert PRIVATE_KEY.encode() not in encrypted
