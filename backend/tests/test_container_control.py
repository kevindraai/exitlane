"""Real local IPC and fail-closed writer ownership contracts; synthetic secrets only."""

import asyncio
import os
import socket
import stat
from contextlib import asynccontextmanager

import pytest

from exitlane.container_control import (
    MAX_FRAME,
    ControlError,
    MutationAuthority,
    MutationOwner,
    UnixControlClient,
    UnixControlServer,
    _read,
    _write,
)


@asynccontextmanager
async def server_at(tmp_path, *, quiesce=None, callbacks=None, allowed_uid=None):
    async def safe(_owner, _reason):
        return True

    path = tmp_path / "run" / "control.sock"
    authority = MutationAuthority(quiesce or safe)
    server = UnixControlServer(
        authority,
        callbacks=callbacks or {},
        path=path,
        allowed_uid=os.getuid() if allowed_uid is None else allowed_uid,
    )
    await server.start()
    try:
        yield server, UnixControlClient(path, _test_uid=os.getuid())
    finally:
        await server.stop()


def test_socket_permissions_and_cleanup(tmp_path):
    async def scenario():
        async with server_at(tmp_path) as (server, _client):
            assert stat.S_IMODE(server.path.stat().st_mode) == 0o600
            assert stat.S_IMODE(server.path.parent.stat().st_mode) == 0o700
            assert server.path.stat().st_uid == os.getuid()
        assert not server.path.exists()

    asyncio.run(scenario())


def test_api_cli_restore_share_one_authority(tmp_path):
    async def scenario():
        events = []
        entered = asyncio.Event()
        release = asyncio.Event()

        async def restore(_payload):
            events.append("restore-start")
            await asyncio.sleep(0)
            events.append("restore-end")
            return {"state": "complete"}

        async with server_at(tmp_path, callbacks={"restore": restore}) as (_server, client):

            async def app():
                async with client.mutation():
                    events.append("app-start")
                    entered.set()
                    await release.wait()
                    events.append("app-end")

            async def cli():
                async with client.mutation():
                    events.append("cli-start")
                    await asyncio.sleep(0)
                    events.append("cli-end")

            app_task = asyncio.create_task(app())
            await entered.wait()
            cli_task = asyncio.create_task(cli())
            restore_task = asyncio.create_task(client.request("restore"))
            await asyncio.sleep(0.03)
            assert events == ["app-start"]
            release.set()
            await asyncio.gather(app_task, cli_task, restore_task)
            assert events == [
                "app-start",
                "app-end",
                "cli-start",
                "cli-end",
                "restore-start",
                "restore-end",
            ]

    asyncio.run(scenario())


def test_disconnect_guards_and_joins_before_next_grant(tmp_path):
    async def scenario():
        events = []
        guarded = asyncio.Event()
        joined = asyncio.Event()

        async def quiesce(owner, reason):
            assert owner.pid == os.getpid()
            assert reason == "owner_lost"
            events.append("guard")
            guarded.set()
            await joined.wait()
            events.append("joined")
            return True

        async with server_at(tmp_path, quiesce=quiesce) as (server, client):
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "acquire"})
            assert (await _read(reader, 1))["ok"]
            writer.close()
            await writer.wait_closed()
            await guarded.wait()

            async def next_writer():
                async with client.mutation():
                    events.append("next")

            waiting = asyncio.create_task(next_writer())
            await asyncio.sleep(0.03)
            assert events == ["guard"]
            joined.set()
            await waiting
            assert events == ["guard", "joined", "next"]

    asyncio.run(scenario())


def test_unproven_owner_death_poison_authority(tmp_path):
    async def scenario():
        async def unsafe(_owner, _reason):
            return False

        async with server_at(tmp_path, quiesce=unsafe) as (server, client):
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "acquire"})
            await _read(reader, 1)
            writer.close()
            await writer.wait_closed()
            for _ in range(100):
                if not server.authority.available:
                    break
                await asyncio.sleep(0.001)
            assert not server.authority.available
            with pytest.raises(ControlError, match="control_recovery_required"):
                async with client.mutation():
                    pytest.fail("grant after uncertain writer loss")

    asyncio.run(scenario())


def test_lease_expiry_quiesces_and_does_not_renew(tmp_path):
    async def scenario():
        events = []

        async def quiesce(_owner, _reason):
            events.append("guarded")
            return True

        async with server_at(tmp_path, quiesce=quiesce) as (server, client):
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "acquire", "timeout": 0.05})
            await _read(reader, 1)
            failure = await _read(reader, 1)
            assert not failure["ok"]
            assert events == ["guarded"]
            async with client.mutation():
                events.append("next")
            assert events == ["guarded", "next"]
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())


def test_bounded_wait_fails_busy_without_mutation(tmp_path):
    async def scenario():
        async with server_at(tmp_path) as (_server, client), client.mutation():
            with pytest.raises(ControlError, match="control_busy"):
                async with client.mutation(wait_timeout=0.01):
                    pytest.fail("second mutation")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json\n",
        b"[]\n",
        b'{"command":"shell"}\n',
        b'{"command":"status","command":"restore"}\n',
        b'{"command":"acquire","timeout":NaN}\n',
        b'{"command":"acquire","timeout":true}\n',
        b'{"command":"acquire","timeout":181}\n',
        b'{"command":"acquire","argv":["anything"]}\n',
        b'{"command":"restore","payload":[]}\n',
        b"x" * (MAX_FRAME + 1) + b"\n",
    ],
)
def test_invalid_frames_never_invoke_callbacks(tmp_path, raw):
    async def scenario():
        calls = []

        async def restore(_payload):
            calls.append(True)
            return {}

        async with server_at(tmp_path, callbacks={"restore": restore}) as (server, _client):
            reader, writer = await asyncio.open_unix_connection(server.path)
            writer.write(raw)
            await writer.drain()
            result = await _read(reader, 1)
            assert result["ok"] is False
            assert not calls
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())


def test_replayed_token_on_other_connection_is_denied(tmp_path):
    async def scenario():
        async with server_at(tmp_path) as (server, _client):
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "acquire"})
            token = (await _read(reader, 1))["token"]
            await _write(writer, {"command": "release", "token": token})
            assert (await _read(reader, 1))["ok"]
            writer.close()
            await writer.wait_closed()
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "acquire"})
            new = await _read(reader, 1)
            assert new["token"] != token
            await _write(writer, {"command": "release", "token": token})
            assert (await _read(reader, 1))["error"] == "control_invalid_release"
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())


def test_foreign_uid_denied(tmp_path):
    async def scenario():
        path = tmp_path / "run" / "control.sock"
        path.parent.mkdir(mode=0o700)

        async def safe(_owner, _reason):
            return True

        server = UnixControlServer(
            MutationAuthority(safe), callbacks={}, path=path, allowed_uid=os.getuid()
        )
        await server.start()
        server.allowed_uid = os.getuid() + 1  # Deterministic peer-policy injection.
        try:
            reader, writer = await asyncio.open_unix_connection(path)
            await _write(writer, {"command": "acquire"})
            assert (await _read(reader, 1))["error"] == "control_unauthorized"
            writer.close()
            await writer.wait_closed()
        finally:
            await server.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["file", "symlink", "socket"])
def test_existing_nodes_are_never_adopted(tmp_path, kind):
    async def scenario():
        path = tmp_path / "run" / "control.sock"
        path.parent.mkdir(mode=0o700)
        sock = None
        if kind == "file":
            path.write_text("foreign")
        elif kind == "symlink":
            path.symlink_to(tmp_path / "elsewhere")
        else:
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(path))
        original = path.lstat().st_ino

        async def safe(_owner, _reason):
            return True

        server = UnixControlServer(
            MutationAuthority(safe), callbacks={}, path=path, allowed_uid=os.getuid()
        )
        try:
            with pytest.raises(ControlError, match="control_socket_collision"):
                await server.start()
            await server.stop()
            assert path.lstat().st_ino == original
        finally:
            if sock:
                sock.close()

    asyncio.run(scenario())


def test_stop_does_not_unlink_replaced_socket(tmp_path):
    async def scenario():
        async with server_at(tmp_path) as (server, _client):
            server.path.unlink()
            server.path.write_text("replacement")
        assert server.path.read_text() == "replacement"

    asyncio.run(scenario())


def test_callback_secret_exception_never_disclosed(tmp_path, capsys):
    secret = "synthetic-not-a-real-passphrase"

    async def scenario():
        async def restore(payload):
            assert payload == {"passphrase": secret}
            raise ControlError(secret)

        async with server_at(tmp_path, callbacks={"restore": restore}) as (_server, client):
            with pytest.raises(ControlError, match="^control_operation_failed$") as error:
                await client.request("restore", {"passphrase": secret})
            assert secret not in str(error.value)
        assert not tuple(tmp_path.rglob("*.log"))

    asyncio.run(scenario())
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err


def test_cancelled_restore_keeps_authority_until_transaction_returns(tmp_path):
    async def scenario():
        started = asyncio.Event()
        finish = asyncio.Event()
        quiesced = asyncio.Event()

        async def restore(_payload):
            started.set()
            await finish.wait()
            return {"state": "rolled_back"}

        async def safe(_owner, _reason):
            quiesced.set()
            return True

        async with server_at(tmp_path, callbacks={"restore": restore}, quiesce=safe) as (
            server,
            _client,
        ):
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "restore", "timeout": 0.05})
            await started.wait()
            await quiesced.wait()
            assert server.authority.owner is not None
            finish.set()
            assert (await _read(reader, 1))["ok"] is False
            assert server.authority.owner is None
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())


def test_local_authority_cancellation_waits_for_safe_cleanup():
    async def scenario():
        entered = asyncio.Event()
        guard = asyncio.Event()
        joined = asyncio.Event()

        async def safe(_owner, _reason):
            guard.set()
            await joined.wait()
            return True

        authority = MutationAuthority(safe)

        async def holder():
            async with authority.exclusive(MutationOwner(os.getpid(), "app")):
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(holder())
        await entered.wait()
        task.cancel()
        await guard.wait()
        assert authority.owner is not None
        task.cancel()  # Repeated cancellation must not skip guard/join.
        joined.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert authority.available and authority.owner is None

    asyncio.run(scenario())


def test_repeated_server_cancellation_cannot_release_live_callback(tmp_path):
    async def scenario():
        started = asyncio.Event()
        guarded = asyncio.Event()
        finish_guard = asyncio.Event()
        finish_transaction = asyncio.Event()

        async def restore(_payload):
            started.set()
            await finish_transaction.wait()
            return {}

        async def quiesce(_owner, _reason):
            guarded.set()
            await finish_guard.wait()
            return True

        async with server_at(tmp_path, callbacks={"restore": restore}, quiesce=quiesce) as (
            server,
            _client,
        ):
            _reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "restore"})
            await started.wait()
            handler = next(iter(server._handlers))
            handler.cancel()
            await guarded.wait()
            handler.cancel()
            finish_guard.set()
            await asyncio.sleep(0.01)
            assert server.authority.owner is not None
            assert not handler.done()
            finish_transaction.set()
            await handler
            assert server.authority.owner is None
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())


def test_quiesce_failure_keeps_poison_and_waits_for_callback(tmp_path):
    async def scenario():
        entered = asyncio.Event()
        failed_guard = asyncio.Event()
        finish = asyncio.Event()

        async def restore(_payload):
            entered.set()
            await finish.wait()
            return {}

        async def unsafe(_owner, _reason):
            failed_guard.set()
            return False

        async with server_at(tmp_path, callbacks={"restore": restore}, quiesce=unsafe) as (
            server,
            client,
        ):
            reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "restore", "timeout": 0.02})
            await entered.wait()
            await failed_guard.wait()
            assert not server.authority.available
            assert server.authority.owner is not None
            finish.set()
            assert (await _read(reader, 1))["error"] == "control_recovery_required"
            with pytest.raises(ControlError, match="control_recovery_required"):
                async with client.mutation():
                    pytest.fail("poisoned authority reused")
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())


def test_unsafe_directory_refused(tmp_path):
    async def scenario():
        async def safe(_owner, _reason):
            return True

        path = tmp_path / "public" / "control.sock"
        path.parent.mkdir(mode=0o755)
        server = UnixControlServer(
            MutationAuthority(safe), callbacks={}, path=path, allowed_uid=os.getuid()
        )
        with pytest.raises(ControlError, match="control_unsafe_directory"):
            await server.start()
        assert not path.exists()

    asyncio.run(scenario())


def test_client_refuses_symlink_without_connecting(tmp_path):
    async def scenario():
        path = tmp_path / "run" / "control.sock"
        path.parent.mkdir(mode=0o700)
        path.symlink_to(tmp_path / "foreign")
        client = UnixControlClient(path, _test_uid=os.getuid())
        with pytest.raises(ControlError, match="control_unsafe_socket"):
            async with client.mutation():
                pytest.fail("foreign socket accepted")

    asyncio.run(scenario())


def test_poisoned_authority_status_available_backup_denied(tmp_path):
    async def scenario():
        calls = []

        async def status(_payload):
            return {
                "state": "recovery_required",
                "available": False,
                "recovery_required": True,
                "worker_running": False,
                "dataplane_ready": False,
            }

        async def backup(_payload):
            calls.append("backup")
            return {}

        async with server_at(tmp_path, callbacks={"status": status, "backup": backup}) as (
            server,
            client,
        ):
            server.authority._poisoned = True
            assert (await client.request("status"))["recovery_required"] is True
            with pytest.raises(ControlError, match="control_recovery_required"):
                await client.request("backup")
            assert not calls

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "result",
    [
        {"state": "synthetic-secret"},
        {"error": "synthetic-secret"},
        {"available": "synthetic-secret"},
        {"state": {"nested": "synthetic-secret"}},
    ],
)
def test_status_rejects_arbitrary_strings_and_nested_results(tmp_path, result):
    async def scenario():
        async def status(_payload):
            return result

        async with server_at(tmp_path, callbacks={"status": status}) as (_server, client):
            with pytest.raises(ControlError, match="control_operation_failed"):
                await client.request("status")

    asyncio.run(scenario())


def test_restore_caller_disconnect_guards_before_callback_finishes(tmp_path):
    async def scenario():
        entered = asyncio.Event()
        guarded = asyncio.Event()
        finish = asyncio.Event()

        async def restore(_payload):
            entered.set()
            await finish.wait()
            return {}

        async def quiesce(_owner, _reason):
            guarded.set()
            return True

        async with server_at(tmp_path, callbacks={"restore": restore}, quiesce=quiesce) as (
            server,
            client,
        ):
            _reader, writer = await asyncio.open_unix_connection(server.path)
            await _write(writer, {"command": "restore"})
            await entered.wait()
            writer.close()
            await writer.wait_closed()
            await asyncio.wait_for(guarded.wait(), 1)
            assert server.authority.owner is not None
            with pytest.raises(ControlError, match="control_busy"):
                async with client.mutation(wait_timeout=0.01):
                    pytest.fail("callback still alive")
            finish.set()
            for _ in range(100):
                if server.authority.owner is None:
                    break
                await asyncio.sleep(0.001)
            assert server.authority.owner is None

    asyncio.run(scenario())


def test_ingress_borrows_only_owned_worker_lease_and_blocks_release(tmp_path):
    async def scenario():
        started = asyncio.Event()
        finish = asyncio.Event()
        calls = []

        async def safe(_owner, _reason):
            return True

        async def ingress(payload):
            calls.append(payload)
            started.set()
            await finish.wait()
            return {"active": True}

        path = tmp_path / "run" / "control.sock"
        authority = MutationAuthority(safe)
        server = UnixControlServer(
            authority,
            callbacks={},
            path=path,
            allowed_uid=os.getuid(),
            ingress_callback=ingress,
            worker_authorized=lambda pid: pid == os.getpid(),
        )
        await server.start()
        client = UnixControlClient(path, _test_uid=os.getuid())
        try:
            with pytest.raises(ControlError, match="control_unauthorized"):
                await client.request("ingress", {"action": "activate", "interface": "wg0"})

            async def writer():
                async with client.mutation():
                    request = asyncio.create_task(
                        client.request("ingress", {"action": "activate", "interface": "wg0"})
                    )
                    await started.wait()
                return await request

            task = asyncio.create_task(writer())
            await started.wait()
            await asyncio.sleep(0.01)
            assert authority.owner is not None and not task.done()
            finish.set()
            assert await task == {"active": True}
            assert authority.owner is None
            assert calls == [{"action": "activate", "interface": "wg0"}]
        finally:
            await server.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "shell", "interface": "wg0"},
        {"action": "activate", "interface": "../wg0"},
        {"action": "activate", "interface": "wg0", "config": "synthetic-private-fixture"},
    ],
)
def test_ingress_rejects_raw_configuration_and_invalid_action(tmp_path, payload):
    async def scenario():
        async def safe(_owner, _reason):
            return True

        async def forbidden(_payload):
            pytest.fail("invalid network command executed")

        path = tmp_path / "run" / "control.sock"
        server = UnixControlServer(
            MutationAuthority(safe),
            callbacks={},
            path=path,
            allowed_uid=os.getuid(),
            ingress_callback=forbidden,
            worker_authorized=lambda _pid: True,
        )
        await server.start()
        client = UnixControlClient(path, _test_uid=os.getuid())
        try:
            async with client.mutation():
                with pytest.raises(ControlError, match="control_unauthorized"):
                    await client.request("ingress", payload)
        finally:
            await server.stop()

    asyncio.run(scenario())


def test_startup_owner_cannot_borrow_ingress_deactivate_ipc(tmp_path):
    async def scenario():
        async def safe(_owner, _reason):
            return True

        async def forbidden(_payload):
            pytest.fail("startup borrower reached ingress mutation callback")

        path = tmp_path / "run" / "control.sock"
        authority = MutationAuthority(safe)
        server = UnixControlServer(
            authority,
            callbacks={},
            path=path,
            allowed_uid=os.getuid(),
            ingress_callback=forbidden,
            worker_authorized=lambda _pid: True,
        )
        await server.start()
        client = UnixControlClient(path, _test_uid=os.getuid())
        try:
            async with authority.exclusive(MutationOwner(os.getpid(), "startup")):
                with pytest.raises(ControlError, match="control_unauthorized"):
                    await client.request("ingress", {"action": "deactivate", "interface": "wg0"})
        finally:
            await server.stop()

    asyncio.run(scenario())


@pytest.mark.parametrize("loss", ["disconnect", "expire"])
def test_lost_lease_joins_paused_ingress_before_final_guard(tmp_path, loss):
    async def scenario():
        events = []
        entered = asyncio.Event()
        finish = asyncio.Event()

        async def safe(_owner, _reason):
            events.append("final-guard-blocked")
            return True

        async def ingress(_payload):
            entered.set()
            await finish.wait()
            events.append("subordinate-finished")
            return {"active": True}

        path = tmp_path / "run" / "control.sock"
        authority = MutationAuthority(safe)
        server = UnixControlServer(
            authority,
            callbacks={},
            path=path,
            allowed_uid=os.getuid(),
            ingress_callback=ingress,
            worker_authorized=lambda _pid: True,
        )
        await server.start()
        client = UnixControlClient(path, _test_uid=os.getuid())
        reader, writer = await asyncio.open_unix_connection(path)
        try:
            await _write(writer, {"command": "acquire", "timeout": 0.04 if loss == "expire" else 1})
            await _read(reader, 1)
            rpc = asyncio.create_task(
                client.request("ingress", {"action": "observe", "interface": "wg0"})
            )
            await entered.wait()
            if loss == "disconnect":
                writer.close()
                await writer.wait_closed()
            for _ in range(100):
                if authority.revoking:
                    break
                await asyncio.sleep(0.001)
            assert authority.revoking
            assert events == [] and authority.owner is not None
            with pytest.raises(ControlError, match="control_busy"):
                async with client.mutation(wait_timeout=0.01):
                    pytest.fail("new lease before subordinate join/final guard")
            finish.set()
            await rpc
            for _ in range(100):
                if authority.owner is None:
                    break
                await asyncio.sleep(0.001)
            assert events == ["subordinate-finished", "final-guard-blocked"]
            assert authority.owner is None
        finally:
            writer.close()
            await writer.wait_closed()
            await server.stop()

    asyncio.run(scenario())


def test_failing_rpc_invalidates_sibling_and_final_guard_follows_join(tmp_path):
    async def scenario():
        entered = asyncio.Event()
        finish = asyncio.Event()
        initial_guard = asyncio.Event()
        events = []

        async def safe(_owner, _reason):
            events.append("guard")
            initial_guard.set()
            return True

        authority = MutationAuthority(safe)

        async def ingress(payload):
            if payload["action"] == "activate":
                entered.set()
                await finish.wait()
                assert authority.revoking
                events.append("sibling-joined-without-reopen")
                return {"active": False}
            raise ControlError("control_operation_failed")

        server = UnixControlServer(
            authority,
            callbacks={},
            path=tmp_path / "run" / "control.sock",
            allowed_uid=os.getuid(),
            ingress_callback=ingress,
            worker_authorized=lambda _pid: True,
        )
        await server.start()
        client = UnixControlClient(server.path, _test_uid=os.getuid())
        try:

            async def writer():
                async with client.mutation():
                    sibling = asyncio.create_task(
                        client.request("ingress", {"action": "activate", "interface": "wg0"})
                    )
                    await entered.wait()
                    with pytest.raises(ControlError, match="control_operation_failed"):
                        await client.request("ingress", {"action": "observe", "interface": "wg0"})
                    # A buggy caller ignores failure and tries to release early.
                    return sibling

            owner = asyncio.create_task(writer())
            await initial_guard.wait()
            await asyncio.sleep(0.01)
            assert authority.revoking and authority.owner is not None
            assert not owner.done()
            finish.set()
            sibling = await owner
            assert await sibling == {"active": False}
            assert events == ["guard", "sibling-joined-without-reopen", "guard"]
            assert authority.owner is None
        finally:
            finish.set()
            await server.stop()

    asyncio.run(scenario())
