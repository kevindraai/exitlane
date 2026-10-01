from __future__ import annotations

import asyncio
import io
from types import SimpleNamespace

import pytest

from exitlane import container_cli
from exitlane.container_control import ControlError
from exitlane.container_service import ContainerRecoveryService


class Coordinator:
    def __init__(self, tmp_path):
        self.layout = SimpleNamespace(backups=tmp_path)
        self.journal = tmp_path / "journal.json"
        self.calls = []

    async def backup(self, destination, passphrase):
        self.calls.append(("backup", destination, passphrase))

    async def restore(self, source, passphrase, *, confirmation):
        self.calls.append(("restore", source, passphrase, confirmation))


@pytest.mark.parametrize(
    "name",
    [
        "../outside.elbackup",
        "/outside.elbackup",
        "a\n.elbackup",
        ".elbackup",
        "x" * 100 + ".elbackup",
        "plain",
    ],
)
def test_restore_cannot_select_arbitrary_files(tmp_path, name):
    coordinator = Coordinator(tmp_path)
    service = ContainerRecoveryService(coordinator, SimpleNamespace(owner=object()))
    with pytest.raises(ControlError):
        asyncio.run(
            service.restore(
                {
                    "name": name,
                    "passphrase": "synthetic-fixture-only",
                    "confirmation": "RESTORE EXITLANE",
                }
            )
        )
    assert not coordinator.calls


def test_service_requires_lease_and_drops_secret_payload(tmp_path):
    coordinator = Coordinator(tmp_path)
    authority = SimpleNamespace(owner=None)
    service = ContainerRecoveryService(coordinator, authority)
    with pytest.raises(ControlError):
        asyncio.run(service.backup({"passphrase": "synthetic-fixture-only"}))
    authority.owner = object()
    payload = {"passphrase": "synthetic-fixture-only"}
    result = asyncio.run(service.backup(payload))
    assert result.keys() == {"name"} and not payload
    assert coordinator.calls[0][1].parent == tmp_path
    assert "synthetic" not in repr(result)


def test_poisoned_readonly_status_has_no_credentials(tmp_path):
    coordinator = Coordinator(tmp_path)
    coordinator.journal.touch(mode=0o600)
    service = ContainerRecoveryService(coordinator, SimpleNamespace(available=False, owner=None))
    result = asyncio.run(service.status({}))
    assert result == {
        "state": "recovery_required",
        "available": False,
        "recovery_required": True,
        "worker_running": False,
    }


def test_cli_passphrase_only_stdin_not_argument(tmp_path, monkeypatch):
    monkeypatch.setattr(container_cli.sys, "stdin", io.StringIO("synthetic-fixture-only\n"))
    calls = []

    class Client:
        async def request(self, command, payload):
            calls.append((command, dict(payload)))
            return {"name": "result.elbackup"}

    args = container_cli.parse_arguments(["backup", "--passphrase-stdin"])
    assert "synthetic" not in repr(args)
    assert asyncio.run(container_cli.execute(args, client=Client())) == {"name": "result.elbackup"}
    assert calls[0][1] == {"passphrase": "synthetic-fixture-only"}


def test_cli_uses_masked_passphrase_prompt(monkeypatch):
    prompts = []
    monkeypatch.setattr(container_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        container_cli.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or "synthetic-fixture-only",
    )
    assert container_cli.read_passphrase(False) == "synthetic-fixture-only"
    assert prompts == ["Backup passphrase: "]


@pytest.mark.parametrize("value", ["short\n", "x" * 1026 + "\n", "synthetic-fixture-only"])
def test_cli_stdin_is_bounded_and_complete(monkeypatch, value):
    monkeypatch.setattr(container_cli.sys, "stdin", io.StringIO(value))
    with pytest.raises(ControlError):
        container_cli.read_passphrase(True)


def test_cli_error_never_prints_underlying_secret(monkeypatch, capsys):
    async def fail(*args):
        raise ControlError("synthetic-fixture-only")

    monkeypatch.setattr(container_cli, "execute", fail)
    assert container_cli.main(["status"]) == 1
    assert capsys.readouterr().err == "container_control_failed\n"


def test_cli_masking_failure_refuses_fallback_input(monkeypatch):
    import warnings

    monkeypatch.setattr(container_cli.sys.stdin, "isatty", lambda: True)

    def unavailable(prompt):
        warnings.warn("synthetic terminal unavailable", container_cli.getpass.GetPassWarning)
        pytest.fail("echoed fallback must never run")

    monkeypatch.setattr(container_cli.getpass, "getpass", unavailable)
    with pytest.raises(ControlError):
        container_cli.read_passphrase(False)


def test_cli_interrupt_has_no_traceback(monkeypatch, capsys):
    async def interrupted(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(container_cli, "execute", interrupted)
    assert container_cli.main(["status"]) == 1
    assert capsys.readouterr().err == "container_control_failed\n"


def test_actual_ipc_validation_refusal_does_not_quiesce_networking(tmp_path):
    import os

    from exitlane import lifecycle
    from exitlane.container_control import MutationAuthority, UnixControlClient, UnixControlServer

    async def scenario():
        mutations = []

        async def quiesce(owner, reason):
            mutations.append(reason)
            return True

        coordinator = Coordinator(tmp_path)

        async def invalid(*args, **kwargs):
            raise lifecycle.LifecycleError("synthetic-private-rejected")

        coordinator.restore = invalid
        authority = MutationAuthority(quiesce)
        service = ContainerRecoveryService(coordinator, authority)
        server = UnixControlServer(
            authority,
            callbacks=service.callbacks,
            path=tmp_path / "run/control.sock",
            allowed_uid=os.getuid(),
        )
        await server.start()
        try:
            client = UnixControlClient(server.path, _test_uid=os.getuid())
            result = await client.request(
                "restore",
                {
                    "name": "valid.elbackup",
                    "passphrase": "synthetic-fixture-only",
                    "confirmation": "RESTORE EXITLANE",
                },
            )
            assert result == {"restored": False, "error": "restore_rejected"}
            assert not mutations and authority.available
        finally:
            await server.stop()

    asyncio.run(scenario())


def test_failed_rollback_completed_callback_refuses_new_writers(tmp_path):
    from exitlane.container_control import MutationAuthority, MutationOwner
    from exitlane.container_recovery import ContainerRecoveryError

    async def scenario():
        async def quiesce(*args):
            return True

        coordinator = Coordinator(tmp_path)

        async def failed(*args, **kwargs):
            raise ContainerRecoveryError("recovery_required")

        coordinator.restore = failed
        authority = MutationAuthority(quiesce)
        service = ContainerRecoveryService(coordinator, authority)
        async with authority.exclusive(MutationOwner(123, "restore")):
            result = await service.restore(
                {
                    "name": "valid.elbackup",
                    "passphrase": "synthetic-fixture-only",
                    "confirmation": "RESTORE EXITLANE",
                }
            )
        assert result == {"restored": False, "error": "restore_failed"}
        assert not authority.available
        with pytest.raises(ControlError, match="recovery_required"):
            async with authority.exclusive(MutationOwner(123, "acquire")):
                pytest.fail("new writer admitted")

    asyncio.run(scenario())


def test_cli_completed_restore_refusal_exits_as_failure(monkeypatch):
    class Client:
        async def request(self, *args):
            return {"restored": False, "error": "restore_rejected"}

    monkeypatch.setattr(container_cli, "read_passphrase", lambda mode: "synthetic-fixture-only")
    args = container_cli.parse_arguments(
        ["restore", "--name", "valid.elbackup", "--confirm", "RESTORE EXITLANE"]
    )
    with pytest.raises(ControlError, match="control_operation_failed"):
        asyncio.run(container_cli.execute(args, client=Client()))
