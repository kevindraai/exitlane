from __future__ import annotations

import io
import sqlite3
import tarfile
from pathlib import Path

import pytest

from exitlane import cli, core, lifecycle
from exitlane.services import auth_security, killswitch, provider_secrets
from exitlane.services.provider_wireguard import ProviderWireGuardError


@pytest.fixture
def appliance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    data = tmp_path / "data"
    config = tmp_path / "config"
    wireguard = data / "wireguard"
    for directory in (data, config, wireguard):
        directory.mkdir(mode=0o700)
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", wireguard)
    monkeypatch.setattr(lifecycle, "CONFIG_DIR", config)
    core.init()
    (config / "secret.key").write_bytes(b"k" * 32)
    (config / "secret.key").chmod(0o600)
    (wireguard / "wg0.conf").write_text("[Interface]\nPrivateKey = test\n", encoding="utf-8")
    (wireguard / "wg0.conf").chmod(0o600)
    core.set_setting("language", "nl")
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES('old',1,9999999999)"
        )
    return {"data": data, "config": config, "lock": tmp_path / "lifecycle.lock"}


def test_encrypted_backup_round_trip_and_session_revocation(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    info = lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )

    assert destination.read_bytes().startswith(lifecycle.MAGIC)
    assert b"PrivateKey" not in destination.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert info.database_schema_version == lifecycle.DATABASE_SCHEMA_VERSION
    verified = lifecycle.inspect_backup(
        destination, "correct horse battery staple", effective_user_id=0
    )
    assert verified.backup_id == info.backup_id

    core.set_setting("language", "en")
    lifecycle.restore_backup(
        destination,
        "correct horse battery staple",
        confirmation="RESTORE EXITLANE",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    assert core.setting("language") == "nl"
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT count(*) FROM sessions").fetchone() == (0,)


def test_wrong_passphrase_and_ciphertext_tampering_are_indistinguishable(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    with pytest.raises(lifecycle.LifecycleError, match="authentication_failed"):
        lifecycle.inspect_backup(destination, "incorrect passphrase", effective_user_id=0)
    content = bytearray(destination.read_bytes())
    content[-20] ^= 1
    destination.write_bytes(content)
    with pytest.raises(lifecycle.LifecycleError, match="authentication_failed"):
        lifecycle.inspect_backup(destination, "correct horse battery staple", effective_user_id=0)


def test_header_tampering_is_authenticated(appliance: dict[str, Path], tmp_path: Path) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    content = bytearray(destination.read_bytes())
    header_offset = len(lifecycle.MAGIC) + 4
    marker = content.find(b"AES-256-GCM", header_offset)
    content[marker] = ord("B")
    destination.write_bytes(content)
    with pytest.raises(lifecycle.LifecycleError, match="unsupported_backup_format"):
        lifecycle.inspect_backup(destination, "correct horse battery staple", effective_user_id=0)


def test_symlink_input_and_non_root_are_rejected(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    link = tmp_path / "linked.elb"
    link.symlink_to(destination)
    with pytest.raises(lifecycle.LifecycleError, match="unsafe_backup_file"):
        lifecycle.inspect_backup(link, "correct horse battery staple", effective_user_id=0)
    with pytest.raises(lifecycle.LifecycleError, match="root_required"):
        lifecycle.inspect_backup(
            destination, "correct horse battery staple", effective_user_id=1000
        )


def test_malicious_archive_entry_is_rejected_before_extraction(
    appliance: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(lifecycle.LifecycleError, match="unsafe_archive_entry"):
        lifecycle._validated_payload(output.getvalue(), staging)
    assert not (tmp_path / "escape").exists()


def test_lifecycle_lock_prevents_concurrent_actions(tmp_path: Path) -> None:
    lock = tmp_path / "lifecycle.lock"
    with (
        lifecycle.lifecycle_lock(lock),
        pytest.raises(lifecycle.LifecycleError, match="lifecycle_busy"),
        lifecycle.lifecycle_lock(lock),
    ):
        pass


def test_future_database_schema_stops_before_application_migrations(
    appliance: dict[str, Path],
) -> None:
    with sqlite3.connect(core.DB) as connection:
        connection.execute("UPDATE schema_version SET version=999 WHERE singleton=1")
    with pytest.raises(core.SettingsStorageError, match="Unsupported database schema"):
        core.init()


def test_failed_restore_health_check_rolls_database_back(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    core.set_setting("language", "state-before-failed-restore")
    actions: list[str] = []
    health_results = iter((False, True))
    guards: list[bool] = []

    with pytest.raises(lifecycle.LifecycleError, match="restored_service_unhealthy"):
        lifecycle.restore_backup(
            destination,
            "correct horse battery staple",
            confirmation="RESTORE EXITLANE",
            effective_user_id=0,
            lock_path=appliance["lock"],
            service_action=actions.append,
            health_check=lambda: next(health_results),
            forwarding_guard=lambda ingress, enabled: guards.append(enabled),
        )

    assert core.setting("language") == "state-before-failed-restore"
    assert actions == ["stop", "reset-egress", "start", "stop", "reset-egress", "start"]
    assert guards == [True, False]


@pytest.mark.parametrize("target_active", [False, True])
@pytest.mark.parametrize("guard_failure", ["none", "transient", "persistent"])
def test_active_mullvad_restore_guards_before_start_and_recovers_original_files(
    appliance: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guard_failure: str,
    target_active: bool,
) -> None:
    monkeypatch.setattr(
        auth_security, "master_key_path", lambda: appliance["config"] / "secret.key"
    )
    core.set_setting("wireguard_interface", "wg-restored")
    core.set_setting(killswitch.SETTING_INGRESS, ["br-restored"])
    core.set_setting(killswitch.SETTING_CONFIGURED, False)
    provider_secrets.save("mullvad", {"active": {"generation": "backup-generation"}})
    destination = tmp_path / "active.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    # Exercise both an intentional disconnect and a different live generation.
    (appliance["config"] / "secret.key").write_bytes(b"x" * 32)
    provider_secrets.save(
        "mullvad", {"active": {"generation": "current-generation"} if target_active else None}
    )
    core.set_setting("language", "current")
    core.set_setting("wireguard_interface", "wg-current")
    core.set_setting(killswitch.SETTING_INGRESS, ["br-current"])
    (core.WG_DIR / "wg0.conf").write_text("current ingress config\n")
    (core.WG_DIR / "current-client.conf").write_text("current client config\n")
    commands: list[tuple[str, ...]] = []
    guard = {"held": False, "provider": False}
    failed_once = False
    observed_starts: list[str] = []

    async def command(*arguments: str, **kwargs: object) -> tuple[int, str, str]:
        commands.append(arguments)
        if arguments[0] == "/usr/sbin/nft":
            rules = str(kwargs.get("input_text", ""))
            if arguments[1:3] == ("-f", "-"):
                guard["held"] = "counter drop" in rules
                if guard["held"]:
                    for interface in ("wg-current", "wg-restored", "br-current", "br-restored"):
                        assert f'"{interface}"' in rules
        elif arguments == ("/usr/bin/systemctl", "start", "exitlane.service"):
            assert guard["held"]
            observed_starts.append(core.setting("language"))
            if core.setting("language") == "nl":
                assert guard["provider"]
        return 0, "", ""

    class Egress:
        async def arm(self, ingress: tuple[str, ...], interface: str) -> None:
            assert guard["held"]
            nonlocal failed_once
            active = provider_secrets.load("mullvad").get("active")
            if (
                isinstance(active, dict)
                and active.get("generation") == "backup-generation"
                and (
                    guard_failure == "persistent"
                    or (guard_failure == "transient" and not failed_once)
                )
            ):
                failed_once = True
                raise ProviderWireGuardError("provider_egress_apply_failed")
            guard["provider"] = True

        async def stop_interface(self, interface: str) -> None:
            assert guard["held"]

        async def disarm(self, ingress: tuple[str, ...], interface: str) -> None:
            guard["provider"] = False

        def remove_config(self, interface: str) -> None:
            pass

    class Firewall:
        async def remove(self) -> None:
            assert guard["held"]

    async def fallback_fails() -> None:
        raise killswitch.KillswitchError("firewall_apply_failed")

    monkeypatch.setattr(core, "command", command)
    restore_provider_guard = cli.restore_provider_egress_guard
    restore_firewall_guard = cli.restore_killswitch
    monkeypatch.setattr(
        cli, "restore_provider_egress_guard", lambda: restore_provider_guard(effective_user_id=0)
    )
    monkeypatch.setattr(
        cli, "restore_killswitch", lambda: restore_firewall_guard(effective_user_id=0)
    )
    monkeypatch.setattr(cli, "ProviderWireGuard", Egress)
    monkeypatch.setattr(killswitch, "NftBackend", Firewall)
    monkeypatch.setattr(killswitch, "arm_provider_transition", fallback_fails)
    # A failing restored arm also prevents reset preflight. The caller must still
    # recover original files and keep forwarding closed without starting either DB.
    if guard_failure == "persistent":
        with pytest.raises(lifecycle.LifecycleError, match="recovery_network_cleanup_failed"):
            lifecycle.restore_backup(
                destination,
                "correct horse battery staple",
                confirmation="RESTORE EXITLANE",
                effective_user_id=0,
                lock_path=appliance["lock"],
                service_action=cli._systemd_service_action,
                health_check=lambda: True,
                forwarding_guard=cli._restore_forwarding_guard,
            )
        assert guard["held"]
        assert observed_starts == []
        assert core.setting("language") == "current"
        assert (core.WG_DIR / "wg0.conf").read_text() == "current ingress config\n"
        assert (core.WG_DIR / "current-client.conf").read_text() == "current client config\n"
        assert list(tmp_path.glob(".exitlane-prerestore-*"))
    elif guard_failure == "transient":
        with pytest.raises(lifecycle.LifecycleError, match="restore_network_guard_failed"):
            lifecycle.restore_backup(
                destination,
                "correct horse battery staple",
                confirmation="RESTORE EXITLANE",
                effective_user_id=0,
                lock_path=appliance["lock"],
                service_action=cli._systemd_service_action,
                health_check=lambda: True,
                forwarding_guard=cli._restore_forwarding_guard,
            )
        assert not guard["held"]
        assert observed_starts == ["current"]
        assert core.setting("language") == "current"
        assert (core.WG_DIR / "wg0.conf").read_text() == "current ingress config\n"
        assert (core.WG_DIR / "current-client.conf").read_text() == "current client config\n"
        for private_file in (core.DB, appliance["config"] / "secret.key", *core.WG_DIR.iterdir()):
            assert private_file.stat().st_mode & 0o777 == 0o600
        assert not list(tmp_path.glob(".exitlane-prerestore-*"))
    else:
        lifecycle.restore_backup(
            destination,
            "correct horse battery staple",
            confirmation="RESTORE EXITLANE",
            effective_user_id=0,
            lock_path=appliance["lock"],
            service_action=cli._systemd_service_action,
            health_check=lambda: True,
            forwarding_guard=cli._restore_forwarding_guard,
        )
        assert not guard["held"]
        assert guard["provider"]
        assert observed_starts == ["nl"]
        assert not (core.WG_DIR / "current-client.conf").exists()


def test_invalid_restored_ingress_fails_before_service_or_firewall_changes(
    appliance: dict[str, Path],
    tmp_path: Path,
) -> None:
    core.set_setting("wireguard_interface", 'wg0"; accept')
    destination = tmp_path / "invalid.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    core.set_setting("wireguard_interface", "wg0")
    with pytest.raises(lifecycle.LifecycleError, match="invalid_restore_ingress"):
        lifecycle.restore_backup(
            destination,
            "correct horse battery staple",
            confirmation="RESTORE EXITLANE",
            effective_user_id=0,
            lock_path=appliance["lock"],
            service_action=lambda action: pytest.fail("service changed before validation"),
            forwarding_guard=lambda ingress, enabled: pytest.fail(
                "firewall changed before validation"
            ),
        )


def test_reset_removes_owned_egress_policy_before_unregistering_ingress(
    appliance: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actions: list[str] = []

    class Egress:
        async def arm(self, ingress: tuple[str, ...], interface: str) -> None:
            actions.append("preflight-and-arm")

        async def stop_interface(self, interface: str) -> None:
            actions.append("stop-egress")

        async def disarm(self, ingress: tuple[str, ...], interface: str) -> None:
            actions.append("remove-owned-policy")

        def remove_config(self, interface: str) -> None:
            actions.append("remove-stale-secret")

    monkeypatch.setattr(cli, "ProviderWireGuard", Egress)
    monkeypatch.setattr(
        cli, "_restore_ingress_service", lambda **kwargs: actions.append("stop-ingress")
    )
    cli._systemd_service_action("reset-egress")
    assert actions == [
        "preflight-and-arm",
        "stop-egress",
        "remove-owned-policy",
        "remove-stale-secret",
        "stop-ingress",
    ]
