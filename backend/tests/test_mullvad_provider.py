import asyncio
import json
import logging

import pytest

from exitlane.providers import mullvad
from exitlane.providers.base import InstallationState

ACCOUNT_SENTINEL = "1234123412341234"
CONNECTED_STATUS = json.dumps(
    {
        "state": "connected",
        "details": {
            "endpoint": {
                "address": "198.51.100.20:51820",
                "protocol": "udp",
                "tunnel_type": "wireguard",
                "tunnel_interface": "wg0-mullvad",
            },
            "location": {
                "ipv4": "203.0.113.9",
                "ipv6": None,
                "country": "Netherlands",
                "city": "Amsterdam",
                "hostname": "nl-ams-wg-001",
            },
            "feature_indicators": [],
        },
    }
)
RELAY_LIST = """Albania (al)
\tTirana (tia) @ 41.32795°N, 19.81870°W
\t\tal-tia-wg-001 (198.51.100.1, 2001:db8::1) - hosted by Example (rented)

Netherlands (nl)
\tAmsterdam (ams) @ 52.36760°N, 4.90410°W
\t\tnl-ams-wg-001 (198.51.100.20, 2001:db8::20) - hosted by Mullvad (Mullvad-owned)
\t\tnl-ams-wg-002 (198.51.100.21) - hosted by Example (rented)
"""


@pytest.fixture(autouse=True)
def reset_mullvad_state(tmp_path, monkeypatch):
    monkeypatch.setattr(mullvad, "INSTALL_PHASE_FILE", tmp_path / "mullvad.phase")
    monkeypatch.setattr(
        mullvad, "INSTALLATION_COMPLETE_MARKER", tmp_path / "mullvad-installation-complete"
    )
    monkeypatch.setattr(mullvad, "_gateway_defaults_task", None)
    monkeypatch.setattr(mullvad, "_installation_monitor_task", None)
    monkeypatch.setattr(mullvad, "_installation_status_lock", None)
    monkeypatch.setattr(mullvad, "_installation_started_at", None)
    monkeypatch.setattr(mullvad, "_installation_starting", False)
    monkeypatch.setattr(mullvad, "_relay_catalog_cache", ([], []))
    monkeypatch.setattr(mullvad, "_relay_catalog_updated_at", 0.0)


def test_metadata_and_capabilities_are_provider_specific_and_safe():
    provider = mullvad.Mullvad()
    assert provider.metadata.as_dict() == {
        "id": "mullvad",
        "display_name": "Mullvad VPN",
        "short_name": "Mullvad",
        "description": "Mullvad VPN Linux client",
        "icon": "shield-check",
        "logo": "/assets/providers/mullvad.svg",
        "provider_type": "commercial_vpn",
        "authentication_method": "account_number",
    }
    capabilities = provider.capabilities(
        installation_state="available",
        authentication_state="signed_in",
        connection_state="disconnected",
    )
    assert capabilities["can_connect"] is True
    assert capabilities["can_select_country"] is True
    assert capabilities["can_manage_provider_killswitch"] is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ACCOUNT_SENTINEL, ACCOUNT_SENTINEL),
        ("1234 1234 1234 1234", ACCOUNT_SENTINEL),
        ("1234\n1234\t1234 1234", ACCOUNT_SENTINEL),
        ("123412341234123", None),
        ("1234-1234-1234-1234", None),
        ("123412341234123x", None),
    ],
)
def test_account_number_normalization(value, expected):
    assert mullvad.normalize_account_number(value) == expected


@pytest.mark.parametrize(
    ("return_code", "output", "expected"),
    [
        (0, b'Mullvad account "sentinel" set', None),
        (1, b"The account does not exist", "invalid_account"),
        (1, b"There are too many devices on the account. One must be revoked", "too_many_devices"),
        (1, b"You are already logged in", "already_logged_in"),
        (1, b"Management RPC unavailable", "daemon_unavailable"),
        (124, b"", "timeout"),
        (127, b"", "command_unavailable"),
        (1, b"uncontrolled provider detail", "provider_error"),
    ],
)
def test_login_failure_classification(return_code, output, expected):
    assert mullvad.classify_login_failure(return_code, output) == expected


def test_authenticate_uses_stdin_boundary_and_never_returns_or_logs_account(monkeypatch, caplog):
    calls = []

    async def gateway(_self):
        return {"ok": True, "error_code": None}

    async def sensitive(*args, input_value, timeout):
        calls.append((args, input_value, timeout))
        return 0, bytearray(f'Mullvad account "{input_value}" set'.encode())

    monkeypatch.setattr(mullvad, "_run_sensitive_cli", sensitive)
    monkeypatch.setattr(mullvad.Mullvad, "prepare_authentication", gateway)
    monkeypatch.setattr(mullvad.Mullvad, "prepare_activation", gateway)
    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(mullvad.Mullvad().authenticate("1234 1234 1234 1234"))

    assert calls == [(("account", "login"), ACCOUNT_SENTINEL, mullvad.LOGIN_TIMEOUT_SECONDS)]
    assert result == {"ok": True, "error": None}
    assert ACCOUNT_SENTINEL not in repr(result)
    assert ACCOUNT_SENTINEL not in caplog.text


def test_invalid_account_is_rejected_before_subprocess(monkeypatch):
    async def unexpected(*_args, **_kwargs):
        pytest.fail("invalid credentials must not reach a subprocess")

    monkeypatch.setattr(mullvad, "_run_sensitive_cli", unexpected)
    assert asyncio.run(mullvad.Mullvad().authenticate("not-an-account")) == {
        "ok": False,
        "error": "invalid_account_format",
    }


def test_authentication_stops_before_secret_subprocess_when_gateway_defaults_fail(
    monkeypatch
):
    async def gateway(_self):
        return {"ok": False, "error_code": "gateway_settings_failed"}

    async def unexpected(*_args, **_kwargs):
        pytest.fail("credentials must not reach the CLI before safe gateway defaults")

    monkeypatch.setattr(mullvad.Mullvad, "prepare_authentication", gateway)
    monkeypatch.setattr(mullvad, "_run_sensitive_cli", unexpected)
    assert asyncio.run(mullvad.Mullvad().authenticate(ACCOUNT_SENTINEL)) == {
        "ok": False,
        "error": "provider_error",
    }


def test_authentication_logs_out_safely_when_authenticated_only_baseline_fails(
    monkeypatch, caplog
):
    calls = []

    async def ready(_self):
        return {"ok": True, "error_code": None}

    async def not_ready(_self):
        return {"ok": False, "error_code": "gateway_settings_failed"}

    async def sensitive(*args, input_value=None, timeout):
        calls.append((args, input_value, timeout))
        return 0, bytearray(ACCOUNT_SENTINEL.encode())

    monkeypatch.setattr(mullvad.Mullvad, "prepare_authentication", ready)
    monkeypatch.setattr(mullvad.Mullvad, "prepare_activation", not_ready)
    monkeypatch.setattr(mullvad, "_run_sensitive_cli", sensitive)

    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(mullvad.Mullvad().authenticate(ACCOUNT_SENTINEL))

    assert calls == [
        (("account", "login"), ACCOUNT_SENTINEL, mullvad.LOGIN_TIMEOUT_SECONDS),
        (("account", "logout"), None, mullvad.SIGN_OUT_TIMEOUT_SECONDS),
    ]
    assert result == {"ok": False, "error": "provider_error"}
    assert ACCOUNT_SENTINEL not in repr(result)
    assert ACCOUNT_SENTINEL not in caplog.text


def test_sensitive_runner_keeps_account_out_of_argv(monkeypatch):
    captured = []

    class Stdin:
        def __init__(self):
            self.value = bytearray()

        def write(self, value):
            self.value.extend(value)

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    class Process:
        def __init__(self):
            self.stdin = Stdin()
            self.stdout = self
            self.output = [f'Mullvad account "{ACCOUNT_SENTINEL}" set'.encode(), b""]
            self.returncode = None

        async def read(self, _size):
            return self.output.pop(0)

        async def wait(self):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    process = Process()

    async def create(*argv, **options):
        captured.append((argv, options))
        return process

    monkeypatch.setattr(mullvad.asyncio, "create_subprocess_exec", create)
    return_code, output = asyncio.run(
        mullvad._run_sensitive_cli("account", "login", input_value=ACCOUNT_SENTINEL, timeout=1)
    )

    assert return_code == 0
    assert captured[0][0] == ("mullvad", "account", "login")
    assert ACCOUNT_SENTINEL not in repr(captured)
    assert process.stdin.value == bytearray(f"{ACCOUNT_SENTINEL}\n".encode())
    assert ACCOUNT_SENTINEL.encode() in output
    output[:] = b"\0" * len(output)


def test_status_json_maps_connected_fields_inside_provider_boundary():
    status = mullvad.parse_status_json(CONNECTED_STATUS)
    assert status == {
        "state": "connected",
        "connected": True,
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "city_code": "ams",
        "server": "nl-ams-wg-001",
        "external_ip": "203.0.113.9",
        "technology": "WireGuard",
        "tunnel_interface": "wg0-mullvad",
        "latency_endpoint": "198.51.100.20",
        "error_code": None,
    }


@pytest.mark.parametrize(
    ("payload", "state", "error_code"),
    [
        (
            {"state": "disconnected", "details": {"location": None, "locked_down": False}},
            "disconnected",
            None,
        ),
        (
            {"state": "disconnected", "details": {"location": None, "locked_down": True}},
            "disconnected",
            "provider_lockdown_enabled",
        ),
        (
            {
                "state": "error",
                "details": {
                    "cause": {
                        "reason": "auth_failed",
                        "details": "[EXPIRED_ACCOUNT] This account has no time left",
                    }
                },
            },
            "error",
            "account_expired",
        ),
        (
            {
                "state": "error",
                "details": {
                    "cause": {"reason": "tunnel_parameter_error", "details": "no_matching_relay"}
                },
            },
            "error",
            "relay_unavailable",
        ),
        ({"state": "future_state"}, "error", "provider_status_unavailable"),
    ],
)
def test_status_json_maps_only_allowlisted_errors(payload, state, error_code):
    status = mullvad.parse_status_json(json.dumps(payload))
    assert status["state"] == state
    assert status["error_code"] == error_code
    assert "details" not in status


def test_status_json_rejects_untrusted_hostname_interface_and_addresses():
    payload = json.loads(CONNECTED_STATUS)
    payload["details"]["location"]["hostname"] = "../../relay"
    payload["details"]["location"]["ipv4"] = "2001:db8::1"
    payload["details"]["location"]["country"] = "<script>country</script>"
    payload["details"]["location"]["city"] = "city\nforged"
    payload["details"]["endpoint"]["tunnel_interface"] = "interface-too-long"
    payload["details"]["endpoint"]["address"] = "provider.invalid:443"
    status = mullvad.parse_status_json(json.dumps(payload))
    assert status["connected"] is True
    assert status["server"] is None
    assert status["country_code"] is None
    assert status["external_ip"] is None
    assert status["country"] is None
    assert status["city"] is None
    assert status["tunnel_interface"] is None
    assert status["latency_endpoint"] is None


def test_relay_list_parser_returns_validated_country_and_ipv4_servers():
    countries, relays = mullvad.parse_relay_list(RELAY_LIST)
    assert countries == [
        {"id": "AL", "country_code": "AL", "provider_name": "Albania"},
        {"id": "NL", "country_code": "NL", "provider_name": "Netherlands"},
    ]
    assert relays[-1] == {
        "id": "nl-ams-wg-002",
        "hostname": "nl-ams-wg-002",
        "station": "198.51.100.21",
        "country_code": "NL",
        "city": "Amsterdam",
        "city_code": "ams",
    }


def test_relay_list_parser_accepts_signed_coordinates_from_all_hemispheres():
    countries, relays = mullvad.parse_relay_list(
        "New Zealand (nz)\n"
        "\tAuckland (akl) @ -36.85090°N, 174.76450°W\n"
        "\t\tnz-akl-wg-001 (198.51.100.30) - hosted by Example (rented)\n"
    )
    assert countries == [
        {"id": "NZ", "country_code": "NZ", "provider_name": "New Zealand"}
    ]
    assert [relay["hostname"] for relay in relays] == ["nz-akl-wg-001"]


def test_connect_validates_targets_and_uses_fixed_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(mullvad.shutil, "which", lambda _name: "/usr/bin/mullvad")

    async def command(*args, **options):
        calls.append((args, options))
        return 0, "", ""

    monkeypatch.setattr(mullvad, "command", command)
    provider = mullvad.Mullvad()
    assert asyncio.run(provider.connect("; shutdown -h now"))["error_code"] == "invalid_target"
    result = asyncio.run(provider.connect_country("NL", server_hostname="nl-ams-wg-002"))
    assert result["ok"] is True
    assert [item[0] for item in calls] == [
        ("mullvad", "relay", "set", "location", "nl-ams-wg-002"),
        ("mullvad", "connect", "--wait"),
    ]
    assert all("shell" not in options for _args, options in calls)


def test_connect_reconnect_disconnect_timeout_codes(monkeypatch):
    monkeypatch.setattr(mullvad.shutil, "which", lambda _name: "/usr/bin/mullvad")

    async def command(*args, **_options):
        if args[1] == "connect":
            return 124, "", ""
        if args[1] == "reconnect":
            return 124, "", ""
        if args[1] == "disconnect":
            return 124, "", ""
        raise AssertionError(args)

    monkeypatch.setattr(mullvad, "command", command)
    provider = mullvad.Mullvad()
    assert asyncio.run(provider.connect())["error_code"] == "vpn_connect_timeout"
    assert asyncio.run(provider.reconnect())["error_code"] == "vpn_connect_timeout"
    assert asyncio.run(provider.disconnect())["error_code"] == "vpn_disconnect_timeout"


@pytest.mark.parametrize(
    ("return_code", "output", "expected"),
    [
        (0, b"Removed device from Mullvad account", None),
        (1, b"Not logged in on any account", "already_signed_out"),
        (1, b"Management RPC unavailable", "daemon_unavailable"),
        (124, b"", "timeout"),
        (127, b"", "command_unavailable"),
        (1, b"untrusted detail", "provider_error"),
    ],
)
def test_sign_out_classification_is_safe(return_code, output, expected):
    assert mullvad.classify_sign_out_failure(return_code, output) == expected


def test_sign_out_uses_fixed_command_and_returns_only_safe_fields(monkeypatch):
    calls = []
    captured = bytearray(f"Removed Mullvad account {ACCOUNT_SENTINEL}".encode())

    async def sensitive(*args, input_value=None, timeout):
        calls.append((args, input_value, timeout))
        return 0, captured

    monkeypatch.setattr(mullvad, "_run_sensitive_cli", sensitive)
    result = asyncio.run(mullvad.Mullvad().sign_out())
    assert calls == [(('account', 'logout'), None, mullvad.SIGN_OUT_TIMEOUT_SECONDS)]
    assert result == {"ok": True, "error": None, "already_signed_out": False}
    assert "Removed device" not in repr(result)
    assert captured == bytearray(len(captured))


def test_status_and_network_facts_use_observed_interface(monkeypatch):
    monkeypatch.setattr(mullvad.shutil, "which", lambda _name: "/usr/bin/mullvad")

    async def authentication():
        return "signed_in", None

    async def command(*args, **_options):
        if args[:2] == ("systemctl", "is-active"):
            return 0, "active", ""
        if args[:3] == ("mullvad", "status", "--json"):
            return 0, CONNECTED_STATUS, ""
        raise AssertionError(args)

    provider = mullvad.Mullvad()
    monkeypatch.setattr(provider, "_authentication_state", authentication)
    monkeypatch.setattr(mullvad, "command", command)
    status = asyncio.run(provider.status())
    facts = asyncio.run(provider.network_facts())
    assert status["authenticated"] is True
    assert status["management"]["provider"]["installation_state"] == "available"
    assert facts.available is True
    assert facts.interface == "wg0-mullvad"
    assert facts.protected_egress is True
    assert facts.supports_ipv4 is True
    assert facts.supports_ipv6 is False


def test_signed_out_status_keeps_available_provider(monkeypatch):
    monkeypatch.setattr(mullvad.shutil, "which", lambda _name: "/usr/bin/mullvad")

    async def authentication():
        return "signed_out", None

    async def command(*args, **_options):
        if args[:2] == ("systemctl", "is-active"):
            return 0, "active", ""
        if args[:3] == ("mullvad", "status", "--json"):
            return (
                0,
                json.dumps(
                    {"state": "disconnected", "details": {"location": None, "locked_down": False}}
                ),
                "",
            )
        raise AssertionError(args)

    provider = mullvad.Mullvad()
    monkeypatch.setattr(provider, "_authentication_state", authentication)
    monkeypatch.setattr(mullvad, "command", command)
    status = asyncio.run(provider.status())
    assert status["available"] is True
    assert status["authenticated"] is False
    assert status["management"]["authentication"]["state"] == "signed_out"
    assert status["management"]["capabilities"]["can_sign_in"] is True


def test_gateway_defaults_only_change_noncompliant_settings(monkeypatch):
    calls = []
    outputs = {
        ("auto-connect", "get"): "Autoconnect: on\n",
        ("lan", "get"): "Local network sharing setting: allow\n",
        ("lockdown-mode", "get"): "Block traffic when the VPN is disconnected: off\n",
        ("tunnel", "get"): "WireGuard options\nIPv6: off\n",
        ("split-tunnel", "list"): "Excluded PIDs:\n",
    }

    async def command(*args, **_options):
        calls.append(args)
        if args[1:] == ("auto-connect", "set", "off"):
            outputs[("auto-connect", "get")] = "Autoconnect: off\n"
        return 0, outputs.get(args[1:], "updated\n"), ""

    provider = mullvad.Mullvad()
    monkeypatch.setattr(mullvad, "command", command)
    results = asyncio.run(provider.defaults())
    assert ("mullvad", "auto-connect", "set", "off") in calls
    assert ("mullvad", "lan", "set", "allow") not in calls
    assert all(item["ok"] for item in results)


def test_pre_authentication_baseline_uses_only_unauthenticated_cli_settings(monkeypatch):
    observed = []

    async def apply(_settings):
        observed.extend(_settings)
        return [{"setting": item[0], "ok": True} for item in _settings]

    async def command(*args, **_options):
        assert args == ("mullvad", "status", "--json")
        return 0, json.dumps({"state": "disconnected", "details": {}}), ""

    provider = mullvad.Mullvad()
    monkeypatch.setattr(provider, "_apply_gateway_settings", apply)
    monkeypatch.setattr(mullvad, "command", command)

    result = asyncio.run(provider.prepare_authentication())

    assert result == {"ok": True, "error_code": None}
    assert observed == list(mullvad.GATEWAY_SETTINGS[:3])
    assert {item[0] for item in observed} == {"auto_connect", "lan", "lockdown_mode"}


def test_installation_response_has_complete_phase_contract():
    response = mullvad._installation_response(
        phase="failed",
        failed_phase="applying_gateway_settings",
        error_code="gateway_settings_failed",
        provider_available=True,
    )
    assert response["state"] == InstallationState.FAILED
    assert response["retry_action"] == "reapply_gateway_settings"
    assert [item["phase"] for item in response["steps"]] == list(mullvad.INSTALL_PHASES)
    failed = [item for item in response["steps"] if item["status"] == "failed"]
    assert failed == [
        {
            "phase": "applying_gateway_settings",
            "status": "failed",
            "error_code": "gateway_settings_failed",
        }
    ]


@pytest.mark.parametrize(
    "helper_code",
    (
        "provider_service_suppression_failed",
        "provider_firewall_unsafe",
        "management_connectivity_unavailable",
    ),
)
def test_installation_phase_preserves_safe_package_lifecycle_errors(
    helper_code, tmp_path, monkeypatch
):
    phase_file = tmp_path / "mullvad.phase"
    phase_file.write_text(f"failed|installing_client|{helper_code}\n", encoding="utf-8")
    monkeypatch.setattr(mullvad, "INSTALL_PHASE_FILE", phase_file)

    assert mullvad._read_installation_phase() == ("failed", "installing_client", helper_code)


def test_daemon_retry_uses_managed_helper_instead_of_direct_service_start(
    monkeypatch,
):
    monkeypatch.setattr(mullvad, "_supports_managed_installation", lambda: True)
    calls = []

    async def installation_status():
        return {
            "state": InstallationState.FAILED,
            "retry_action": "recheck_provider",
            "provider_available": False,
        }

    async def command(*args, **options):
        calls.append((args, options))
        return 0, "", ""

    provider = mullvad.Mullvad()
    monkeypatch.setattr(provider, "installation_status", installation_status)
    monkeypatch.setattr(provider, "_monitor_installation", lambda: asyncio.sleep(0))
    monkeypatch.setattr(mullvad, "command", command)

    result = asyncio.run(provider.start_installation())

    assert result["ok"] is True
    assert result["phase"] == "checking_system"
    assert any(
        args == ("systemctl", "start", "--no-block", mullvad.INSTALL_UNIT)
        for args, _options in calls
    )
    assert not any("mullvad-daemon" in args for args, _options in calls)


def test_validating_installation_fails_closed_when_gateway_defaults_are_not_proven(
    tmp_path, monkeypatch
):
    phase_file = tmp_path / "mullvad.phase"
    phase_file.write_text("validating_installation\n", encoding="utf-8")
    monkeypatch.setattr(mullvad, "INSTALL_PHASE_FILE", phase_file)
    monkeypatch.setattr(mullvad, "_supports_managed_installation", lambda: True)

    async def command(*args, **_options):
        assert args[:3] == ("systemctl", "show", mullvad.INSTALL_UNIT)
        return 0, "ActiveState=inactive\nResult=success\nExecMainStatus=0", ""

    async def health():
        return {"state": InstallationState.AVAILABLE, "error_code": None}

    async def gateway_settings():
        return [{"setting": "lan", "ok": False}]

    provider = mullvad.Mullvad()
    monkeypatch.setattr(mullvad, "command", command)
    monkeypatch.setattr(provider, "_installation_health", health)
    monkeypatch.setattr(provider, "gateway_settings_status", gateway_settings)
    result = asyncio.run(provider.installation_status())
    assert result["state"] == InstallationState.FAILED
    assert result["error_code"] == "gateway_settings_failed"
    assert result["retry_action"] == "reapply_gateway_settings"
    assert phase_file.read_text(encoding="utf-8") == (
        "failed|applying_gateway_settings|gateway_settings_failed\n"
    )


def test_installation_status_uses_durable_completion_marker_after_reboot(
    tmp_path, monkeypatch
):
    marker = tmp_path / "mullvad-installation-complete"
    marker.touch(mode=0o600)
    monkeypatch.setattr(mullvad, "INSTALLATION_COMPLETE_MARKER", marker)
    monkeypatch.setattr(mullvad, "_supports_managed_installation", lambda: True)

    async def command(*args, **_options):
        assert args[:3] == ("systemctl", "show", mullvad.INSTALL_UNIT)
        return 0, "ActiveState=inactive\nResult=success\nExecMainStatus=0", ""

    async def health():
        return {"state": InstallationState.AVAILABLE, "error_code": None}

    async def unexpected_defaults():
        pytest.fail("a validated durable installation must not reapply signed-in-only settings")

    provider = mullvad.Mullvad()
    monkeypatch.setattr(mullvad, "command", command)
    monkeypatch.setattr(provider, "_installation_health", health)
    monkeypatch.setattr(provider, "defaults", unexpected_defaults)

    result = asyncio.run(provider.installation_status())

    assert result["state"] == InstallationState.AVAILABLE
    assert result["phase"] == "completed"
    assert result["provider_available"] is True
