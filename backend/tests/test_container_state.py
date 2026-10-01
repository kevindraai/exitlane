"""Durable inventory with synthetic identities, never live appliance state."""

import base64
import hashlib
import json
import os
import sqlite3
from dataclasses import asdict

import pytest

from exitlane import core
from exitlane.container_state import ContainerLayout, ContainerState, ContainerStateError
from exitlane.providers.mullvad import Relay
from exitlane.providers.pia_api import PiaKeyResponse, PiaServer
from exitlane.providers.proton_profile import parse_profile
from exitlane.providers.wireguard_keys import _public_key_for_private
from exitlane.services import auth_security, provider_secrets

PRIVATE = base64.b64encode(bytes(range(32))).decode()
PUBLIC = _public_key_for_private(PRIVATE)
PEER = base64.b64encode(bytes(range(1, 33))).decode()


@pytest.fixture
def state(tmp_path, monkeypatch):
    from exitlane import container_state

    monkeypatch.setattr(container_state, "ROOT_UID", os.geteuid())
    controller = ContainerState(ContainerLayout(tmp_path / "published"))
    layout = controller.stage_empty(tmp_path / "staging")
    monkeypatch.setattr(core, "DB", layout.database)
    monkeypatch.setattr(auth_security, "master_key_path", lambda: layout.master_key)
    return ContainerState(layout)


def generation(provider, status="active"):
    token = "synthetic-generation"
    if provider == "mullvad":
        return {
            "version": 1,
            "account_number": "1234123412341234",
            "private_key": PRIVATE,
            "public_key": PUBLIC,
            "ipv4_address": "10.64.0.2/32",
            status: {
                "generation": token,
                "relay": asdict(
                    Relay(
                        "synthetic-relay", "NL", "Synthetic", "ams", "Synthetic", "192.0.0.9", PEER
                    )
                ),
            },
        }
    if provider == "pia":
        return {
            "version": 1,
            "username": "synthetic",
            "password": "fixture-only",
            status: {
                "generation": token,
                "private_key": PRIVATE,
                "public_key": PUBLIC,
                "address": "10.65.0.2/32",
                "server": asdict(
                    PiaServer("synthetic", "Synthetic", "NL", "peer", "192.0.0.9", "192.0.0.9")
                ),
                "response": asdict(PiaKeyResponse("10.65.0.2/32", PEER, 51820, "10.65.0.1")),
            },
        }
    profile = parse_profile(
        f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.66.0.2/32\nDNS = 10.66.0.1\n"
        f"[Peer]\nPublicKey = {PEER}\nEndpoint = 192.0.0.9:51820\nAllowedIPs = 0.0.0.0/0\n"
    )
    return {
        "version": 1,
        "profiles": {"synthetic": {"config": asdict(profile)}},
        status: {
            "generation": token,
            "profile_id": "synthetic",
            "endpoint_address": "192.0.0.9",
            "address": "10.66.0.2/32",
        },
    }


def test_staged_empty_complete_private_layout_and_native_paths_unchanged(state):
    layout = state.layout
    inventory = state.validate()
    assert inventory.schema == 1 and not inventory.intents
    assert layout.master_key.stat().st_mode & 0o777 == 0o600
    assert layout.database.stat().st_mode & 0o777 == 0o600
    assert all(
        path.stat().st_mode & 0o777 == 0o700
        for path in (
            layout.root,
            layout.config,
            layout.state,
            layout.wireguard,
            layout.provider_egress,
            layout.recovery,
            layout.backups,
        )
    )
    assert not (layout.root.parent / "published").exists()


@pytest.mark.parametrize("component", ["database", "master_key", "manifest"])
def test_missing_pair_or_manifest_fails_without_mfa(state, component):
    getattr(state.layout, component).unlink()
    with pytest.raises(ContainerStateError):
        state.validate()
    assert not getattr(state.layout, component).exists()


@pytest.mark.parametrize("component", ["database", "master_key", "manifest", "wireguard", "config"])
def test_insecure_permissions_rejected(state, component):
    getattr(state.layout, component).chmod(0o755)
    with pytest.raises(ContainerStateError, match="permissions_invalid"):
        state.validate()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "hardlink"])
def test_unsafe_key_never_opened_or_generated(state, kind):
    path = state.layout.master_key
    saved = state.layout.root / "old-key"
    path.rename(saved)
    if kind == "symlink":
        path.symlink_to(saved)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        os.link(saved, path)
    with pytest.raises(ContainerStateError, match="component_unsafe"):
        state.validate()


def test_wrong_owner_rejected(state, monkeypatch):
    from exitlane import container_state

    real = container_state._facts

    def wrong(path, **kwargs):
        if path == state.layout.master_key:
            raise ContainerStateError("container_state_owner_invalid")
        return real(path, **kwargs)

    monkeypatch.setattr(container_state, "_facts", wrong)
    with pytest.raises(ContainerStateError, match="owner_invalid"):
        state.validate()


@pytest.mark.parametrize("schema", [0, 2])
def test_schema_interval_refuses_old_or_future(state, schema):
    with sqlite3.connect(state.layout.database) as connection:
        if schema == 0:
            connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute("UPDATE schema_version SET version=?", (schema,))
    with pytest.raises(ContainerStateError):
        state.validate()


@pytest.mark.parametrize("provider", ["mullvad", "pia", "proton"])
@pytest.mark.parametrize("status", ["active", "pending"])
def test_all_direct_generations_reconstruct_without_network_or_api(state, provider, status):
    provider_secrets.save(provider, generation(provider, status))
    core.set_setting("vpn.provider_id", provider)
    inventory = state.validate()
    intent = inventory.intents[0]
    assert (intent.provider_id, intent.status, intent.generation) == (
        provider,
        status,
        "synthetic-generation",
    )
    assert PRIVATE not in repr(inventory)
    assert not list(state.layout.provider_egress.iterdir())
    state.rebuild_projections(inventory, guard_observed=lambda: True)
    projection = state.layout.provider_egress / f"wg-{provider}.conf"
    assert "Table = off" in projection.read_text()
    assert projection.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("provider", ["mullvad", "pia", "proton"])
def test_ambiguous_pending_is_recovery_required_not_promoted(state, provider):
    payload = generation(provider)
    payload.pop("active")
    payload["pending"] = {"recovery": "failed_connect"}
    provider_secrets.save(provider, payload)
    inventory = state.validate()
    assert inventory.recovery_required and inventory.intents[0].config is None
    with pytest.raises(ContainerStateError, match="recovery_required"):
        state.rebuild_projections(inventory, guard_observed=lambda: True)
    assert not list(state.layout.provider_egress.iterdir())


def test_reconstruction_requires_observed_guard(state):
    provider_secrets.save("mullvad", generation("mullvad"))
    with pytest.raises(ContainerStateError, match="guard_unproven"):
        state.rebuild_projections(state.validate(), guard_observed=lambda: False)
    assert not list(state.layout.provider_egress.iterdir())


def test_wrong_key_rejected_by_manifest_even_without_encrypted_rows(state):
    state.layout.master_key.write_bytes(b"x" * 32)
    with pytest.raises(ContainerStateError, match="manifest_invalid"):
        state.validate()


@pytest.mark.parametrize("provider", ["mullvad", "pia", "proton"])
def test_staged_wrong_key_rejects_each_provider_without_manifest(state, provider):
    provider_secrets.save(provider, generation(provider))
    state.layout.master_key.write_bytes(b"x" * 32)
    with pytest.raises(ContainerStateError, match="container_state_invalid") as error:
        state.validate_pair(state.layout.database, state.layout.master_key, state.layout.wireguard)
    assert PRIVATE not in str(error.value) and "fixture-only" not in str(error.value)


def test_staged_wrong_key_rejects_mfa_ciphertext(state):
    encrypted = auth_security.encrypt_secret("SYNTHETIC-MFA")
    with sqlite3.connect(state.layout.database) as connection:
        connection.execute(
            "INSERT INTO users(id,username,encrypted_totp_secret) VALUES(1,'synthetic',?)",
            (encrypted,),
        )
    state.layout.master_key.write_bytes(b"x" * 32)
    with pytest.raises(ContainerStateError):
        state.validate_pair(state.layout.database, state.layout.master_key, state.layout.wireguard)


def test_nordvpn_selected_or_encrypted_store_refused(state):
    core.set_setting("vpn.provider_id", "nordvpn")
    with pytest.raises(ContainerStateError, match="provider_unavailable"):
        state.validate()
    core.set_setting("vpn.provider_id", "mullvad")
    provider_secrets.save("nordvpn", {"version": 1})
    with pytest.raises(ContainerStateError, match="provider_unavailable"):
        state.validate()


def test_invalid_generation_cannot_write_shell_or_config_input(state):
    payload = generation("mullvad")
    payload["active"]["generation"] = "bad\nPrivateKey = injected"
    provider_secrets.save("mullvad", payload)
    with pytest.raises(ContainerStateError):
        state.validate()


def test_no_silent_dev_layout_adoption(state):
    state.layout.manifest.unlink()
    with pytest.raises(ContainerStateError):
        state.validate()
    with pytest.raises(ContainerStateError, match="staging_not_empty"):
        state.stage_empty(state.layout.root)


def test_manifest_digest_does_not_contain_key(state):
    content = state.layout.manifest.read_text()
    assert state.layout.master_key.read_bytes().hex() not in content
    assert (
        json.loads(content)["master_key_sha256"]
        == hashlib.sha256(state.layout.master_key.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("size", [0, 31, 33])
def test_invalid_master_key_length(state, size):
    state.layout.master_key.write_bytes(b"x" * size)
    with pytest.raises(ContainerStateError):
        state.validate()


def test_corrupt_proton_profile_rejected_even_without_generation(state):
    payload = generation("proton")
    payload.pop("active")
    payload["profiles"]["synthetic"]["config"]["private_key"] = "not-a-key"
    provider_secrets.save("proton", payload)
    with pytest.raises(ContainerStateError):
        state.validate()


@pytest.mark.parametrize("provider", ["pia", "proton"])
def test_generation_source_identity_must_match_validated_projection(state, provider):
    payload = generation(provider)
    payload["active"]["address"] = "10.42.0.2/32"
    provider_secrets.save(provider, payload)
    with pytest.raises(ContainerStateError):
        state.validate()


def test_manifest_rebinding_is_atomic_private_and_leaves_no_temporary_files(state):
    state.layout.master_key.write_bytes(b"x" * 32)
    state.write_manifest()
    assert state.validate().schema == 1
    assert state.layout.manifest.stat().st_mode & 0o777 == 0o600
    assert not list(state.layout.root.glob(".layout-*"))


def test_shared_schema_initializer_uses_explicit_path_without_mutating_core_db(state, tmp_path):
    original = core.DB
    target = tmp_path / "new-database"
    core.init_database(target)
    assert core.DB == original
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT version FROM schema_version").fetchone() == (1,)


def test_alias_in_ancestor_path_rejected(state):
    alias = state.layout.root.parent / "alias"
    alias.symlink_to(state.layout.root, target_is_directory=True)
    with pytest.raises(ContainerStateError, match="component_unsafe"):
        ContainerState(ContainerLayout(alias)).validate()
    with pytest.raises(ContainerStateError, match="component_unsafe"):
        state.validate_pair(
            alias / "state/exitlane.db", alias / "config/secret.key", alias / "state/wireguard"
        )


@pytest.mark.parametrize("provider", ["mullvad", "pia", "proton"])
def test_non_string_generation_rejected_before_provider_coercion(state, provider):
    payload = generation(provider)
    payload["active"]["generation"] = 123
    provider_secrets.save(provider, payload)
    with pytest.raises(ContainerStateError):
        state.validate()


def test_boolean_manifest_version_is_not_a_schema_number(state):
    metadata = json.loads(state.layout.manifest.read_text())
    metadata["layout_version"] = True
    state.layout.manifest.write_text(json.dumps(metadata))
    with pytest.raises(ContainerStateError, match="manifest_invalid"):
        state.validate()


def test_invalid_disconnected_mullvad_identity_rejected(state):
    payload = generation("mullvad")
    payload.pop("active")
    payload["account_number"] = "not-an-account"
    provider_secrets.save("mullvad", payload)
    with pytest.raises(ContainerStateError):
        state.validate()


@pytest.mark.parametrize("kind", ["fifo", "symlink", "oversized"])
def test_unsafe_wireguard_entry_rejected_before_parser_reads(state, monkeypatch, kind):
    from exitlane import container_state

    path = state.layout.wireguard / "wg-office.conf"
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "symlink":
        path.symlink_to(state.layout.master_key)
    else:
        path.write_bytes(b"x" * (container_state.lifecycle.WIREGUARD_CONFIG_MAX_BYTES + 1))
        path.chmod(0o600)
    calls = []
    monkeypatch.setattr(
        container_state.lifecycle, "_validate_restored_wireguard", lambda root: calls.append(root)
    )
    with pytest.raises(ContainerStateError, match="component_unsafe"):
        state.validate()
    assert calls == []


@pytest.mark.parametrize(
    "content",
    [None, "[Interface]\nPrivateKey = invalid\n", "[Interface]\nAddress = 10.77.0.1/24\n"],
)
def test_configured_ingress_must_validate_before_network_reconstruction(state, content):
    core.set_settings(
        {
            "wireguard_configured": True,
            "wireguard_interface": "wg-office",
            "wireguard_subnet": "10.77.0.0/24",
        }
    )
    if content is not None:
        path = state.layout.wireguard / "wg-office.conf"
        path.write_text(content)
        path.chmod(0o600)
    with pytest.raises(ContainerStateError):
        state.validate()


def test_configured_ingress_subnet_matches_validated_file(state):
    core.set_settings(
        {
            "wireguard_configured": True,
            "wireguard_interface": "wg-office",
            "wireguard_subnet": "10.78.0.0/24",
        }
    )
    path = state.layout.wireguard / "wg-office.conf"
    path.write_text(
        f"[Interface]\nAddress = 10.77.0.1/24\nPrivateKey = {PRIVATE}\n"
        f"ListenPort = 51820\n[Peer]\nPublicKey = {PEER}\nAllowedIPs = 10.77.0.2/32\n"
    )
    path.chmod(0o600)
    with pytest.raises(ContainerStateError, match="ingress_inconsistent"):
        state.validate()
    core.set_setting("wireguard_subnet", "10.77.0.0/24")
    state.validate()
