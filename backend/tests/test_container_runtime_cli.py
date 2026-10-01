"""Container CLI uses the real supervisor service contract, never a second lease."""

import argparse
import asyncio
import getpass
import os
import warnings
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from exitlane import cli
from exitlane.container_control import MutationAuthority, UnixControlClient, UnixControlServer
from exitlane.container_service import ContainerRecoveryService
from exitlane.lifecycle import LifecycleError
from exitlane.runtime import NativeSystemdRuntime, RuntimeCapabilities, RuntimePaths

SYNTHETIC = "synthetic-fixture-passphrase"


@pytest.mark.parametrize("warning_on_call", [1, 2])
def test_container_backup_reader_refuses_echo_fallback(monkeypatch, warning_on_call):
    monkeypatch.setattr(
        cli, "runtime", NativeSystemdRuntime(RuntimeCapabilities(runtime_name="container"))
    )
    calls = []

    def reader(_prompt):
        calls.append(True)
        if len(calls) == warning_on_call:
            warnings.warn("synthetic unavailable terminal", getpass.GetPassWarning)
            pytest.fail("reader could echo a secret")
        return SYNTHETIC

    with pytest.raises(LifecycleError, match="masked_input_unavailable") as error:
        cli._read_backup_passphrase(None, password_reader=reader, confirmation=True)
    assert SYNTHETIC not in str(error.value)
    assert len(calls) == warning_on_call


@asynccontextmanager
async def service(tmp_path):
    async def safe(_owner, _reason):
        return True

    authority = MutationAuthority(safe)
    paths = RuntimePaths.container(tmp_path / "data")
    backups = paths.application_data.parent / "backups"
    backups.mkdir(mode=0o700, parents=True)

    class Coordinator:
        layout = SimpleNamespace(backups=backups, recovery=tmp_path)
        journal = tmp_path / "journal"

        async def backup(self, destination, passphrase):
            assert authority.owner.label == "backup"
            assert passphrase == SYNTHETIC
            destination.write_text("synthetic encrypted envelope")

        async def restore(self, source, passphrase, *, confirmation):
            assert authority.owner.label == "restore"
            assert source.parent == backups and source.is_file()
            assert passphrase == SYNTHETIC
            assert confirmation == "RESTORE EXITLANE"

    recovery = ContainerRecoveryService(Coordinator(), authority)
    control = UnixControlServer(
        authority,
        callbacks=recovery.callbacks,
        path=tmp_path / "run" / "control.sock",
        allowed_uid=os.getuid(),
    )
    await control.start()
    runtime = NativeSystemdRuntime(RuntimeCapabilities(runtime_name="container"))
    runtime.paths = paths
    runtime.client = UnixControlClient(control.path, _test_uid=os.getuid())
    try:
        yield runtime, backups
    finally:
        await control.stop()


def test_backup_and_restore_use_actual_service_shapes(tmp_path, monkeypatch, capsys):
    async def scenario():
        async with service(tmp_path) as (runtime, backups):
            monkeypatch.setattr(cli, "runtime", runtime)
            monkeypatch.setattr(cli, "_read_backup_passphrase", lambda *_a, **_kw: SYNTHETIC)
            monkeypatch.setattr("builtins.input", lambda *_a: "RESTORE EXITLANE")
            create = argparse.Namespace(
                backup_command="create", passphrase_file=None, path=str(backups)
            )
            assert await asyncio.to_thread(cli.backup_command, create) == 0
            files = tuple(backups.iterdir())
            assert len(files) == 1
            restore = argparse.Namespace(
                backup_command="restore", passphrase_file=None, path=str(files[0])
            )
            assert await asyncio.to_thread(cli.backup_command, restore) == 0

    asyncio.run(scenario())
    captured = capsys.readouterr()
    assert "Encrypted backup created:" in captured.out
    assert "Backup restored." in captured.out
    assert SYNTHETIC not in captured.out + captured.err


@pytest.mark.parametrize(
    "command,path", [("create", "requested.elbackup"), ("restore", "../foreign.elbackup")]
)
def test_cli_refuses_noncanonical_container_paths_before_request(
    tmp_path, monkeypatch, command, path
):
    async def scenario():
        async with service(tmp_path) as (runtime, backups):
            monkeypatch.setattr(cli, "runtime", runtime)
            monkeypatch.setattr(cli, "_read_backup_passphrase", lambda *_a, **_kw: SYNTHETIC)
            args = argparse.Namespace(
                backup_command=command, passphrase_file=None, path=str(backups / path)
            )
            assert await asyncio.to_thread(cli.backup_command, args) == 2
            assert not tuple(backups.iterdir())

    asyncio.run(scenario())


def test_legacy_killswitch_status_cannot_invent_worker_dataplane_facts(monkeypatch, capsys):
    runtime = SimpleNamespace(
        coordinated_mutations=True, capabilities=RuntimeCapabilities(runtime_name="container")
    )
    monkeypatch.setattr(cli, "runtime", runtime)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    def forbidden(*_args, **_kwargs):
        pytest.fail("legacy status must not initialize state or native provider adapters")

    monkeypatch.setattr(cli.core, "init", forbidden)
    monkeypatch.setattr(cli.core, "setting", forbidden)
    assert cli.main(["killswitch-status"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "runtime_capability_unavailable" in captured.err
    assert "supervisor status" in captured.err and "WebUI diagnostics" in captured.err
