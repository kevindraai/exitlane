"""Supervisor-owned, fail-closed mutation authority and root-only local control.

No production runtime is enabled by importing this module. The supervisor's
quiesce callback MUST guard networking and prove the old writer has stopped;
returning false permanently closes the authority rather than handing state to
another writer. Root peers share the container's root trust boundary.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import stat
import struct
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

CONTROL_PATH = Path('/run/exitlane/control.sock')
MAX_FRAME = 16 * 1024
MAX_OPERATION_SECONDS = 180.0
MAX_WAIT_SECONDS = 30.0
ERROR_CODES = frozenset({
    'control_busy', 'control_expired', 'control_recovery_required',
    'control_invalid_request', 'control_invalid_release', 'control_unauthorized',
    'control_operation_failed', 'control_connection_failed',
})


class ControlError(RuntimeError):
    """Stable public code; never includes payloads or underlying exceptions."""


@dataclass(frozen=True)
class MutationOwner:
    pid: int
    label: str


Quiesce = Callable[[MutationOwner, str], Awaitable[bool]]
Callback = Callable[[dict], Awaitable[dict]]


def _seconds(value: object, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ControlError('control_invalid_request')
    if not 0 < value <= maximum:
        raise ControlError('control_invalid_request')
    return float(value)


class MutationAuthority:
    """Exclusive authority; loss of a writer is guarded before reuse.

    Local callbacks remain under the lock until completion even if cancellation
    arrives. The control server uses this same lock for app leases and restore,
    so restore callbacks must not acquire a second lease.
    """

    def __init__(self, quiesce: Quiesce):
        self._lock = asyncio.Lock()
        self._quiesce = quiesce
        self._poisoned = False
        self.owner: MutationOwner | None = None

    @property
    def available(self) -> bool:
        return not self._poisoned

    def require_recovery(self) -> None:
        """A completed guarded transaction can permanently refuse new writers."""
        self._poisoned = True

    async def _abandon(self, owner: MutationOwner, reason: str) -> None:
        try:
            async with asyncio.timeout(MAX_WAIT_SECONDS):
                safe = await self._quiesce(owner, reason)
        except BaseException:  # noqa: BLE001 -- cancellation must also poison authority
            safe = False
        if safe is not True:
            self._poisoned = True
            raise ControlError('control_recovery_required') from None

    @asynccontextmanager
    async def exclusive(
        self, owner: MutationOwner, *, timeout: float = 180, wait_timeout: float = 30
    ) -> AsyncIterator[None]:
        timeout = _seconds(timeout, MAX_OPERATION_SECONDS)
        wait_timeout = _seconds(wait_timeout, MAX_WAIT_SECONDS)
        try:
            await asyncio.wait_for(self._lock.acquire(), wait_timeout)
        except TimeoutError:
            raise ControlError('control_busy') from None
        try:
            if self._poisoned:
                raise ControlError('control_recovery_required')
            self.owner = owner
            try:
                async with asyncio.timeout(timeout):
                    yield
            except BaseException as exc:
                # Shield cleanup through cancellation. The lock is kept until
                # the guard/quiesce callback has actually returned.
                task = asyncio.create_task(self._abandon(owner, 'owner_lost'))
                while not task.done():
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        continue
                task.result()
                if isinstance(exc, TimeoutError):
                    raise ControlError('control_expired') from None
                raise
        finally:
            self.owner = None
            self._lock.release()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError


async def _read(reader: asyncio.StreamReader, deadline: float) -> dict:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b'\n'), deadline)
        if len(raw) > MAX_FRAME:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant)
        if not isinstance(value, dict):
            raise TypeError
        return value
    except (ValueError, TypeError, UnicodeError, asyncio.LimitOverrunError,
            asyncio.IncompleteReadError, TimeoutError):
        raise ControlError('control_invalid_request') from None


async def _write(writer: asyncio.StreamWriter, value: dict) -> None:
    try:
        raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(raw) > MAX_FRAME:
            raise ValueError
        writer.write(raw)
        await asyncio.wait_for(writer.drain(), 5)
    except (ValueError, TypeError, ConnectionError, TimeoutError):
        raise ControlError('control_connection_failed') from None


def _status_projection(result: object) -> dict:
    # Deliberately tiny recovery projection: no arbitrary strings, nested state,
    # database reads that mutate sessions, paths, or exception representations.
    fields = {'state', 'available', 'recovery_required', 'worker_running', 'dataplane_ready'}
    states = {'ready', 'blocked', 'recovery_required', 'restoring', 'stopped', 'running', 'idle'}
    if not isinstance(result, dict) or set(result) - fields:
        raise ControlError('control_operation_failed')
    for key, value in result.items():
        if key == 'state':
            if not isinstance(value, str) or value not in states:
                raise ControlError('control_operation_failed')
        elif not isinstance(value, bool):
            raise ControlError('control_operation_failed')
    return result


class UnixControlServer:
    """Fixed commands; readonly status is available outside the mutation lease."""

    def __init__(
        self, authority: MutationAuthority, *, callbacks: dict[str, Callback],
        path: Path = CONTROL_PATH, allowed_uid: int = 0,
    ):
        if set(callbacks) - {'backup', 'restore', 'status'}:
            raise ControlError('control_invalid_configuration')
        self.authority = authority
        self.callbacks = dict(callbacks)
        self.path = path
        self.allowed_uid = allowed_uid
        self._server: asyncio.AbstractServer | None = None
        self._inode: tuple[int, int] | None = None
        self._handlers: set[asyncio.Task] = set()
        self._stopping = False

    async def start(self) -> None:
        if self._server is not None:
            raise ControlError('control_already_started')
        self._stopping = False
        # Do not adopt existing nodes, including a stale socket or symlink.
        try:
            self.path.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
            directory = self.path.parent.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != self.allowed_uid
                    or stat.S_IMODE(directory.st_mode) != 0o700):
                raise ControlError('control_unsafe_directory')
            if os.path.lexists(self.path):
                raise ControlError('control_socket_collision')
            self._server = await asyncio.start_unix_server(
                self._handle, path=str(self.path), limit=MAX_FRAME,
            )
            os.chmod(self.path, 0o600)
            node = self.path.lstat()
            self._inode = (node.st_dev, node.st_ino)
        except OSError:
            raise ControlError('control_start_failed') from None

    async def stop(self) -> None:
        self._stopping = True
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Handlers cancel under the same authority, which must first quiesce.
        tasks = tuple(self._handlers)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            node = self.path.lstat()
            if (node.st_dev, node.st_ino) == self._inode and stat.S_ISSOCK(node.st_mode):
                self.path.unlink()
        except FileNotFoundError:
            pass
        self._inode = None

    async def _finish_interrupted(self, owner: MutationOwner, operation: asyncio.Task) -> None:
        # Even failed quiescence cannot release the lease around a live callback.
        # Poisoning prevents reuse; waiting still lets a rollback finish safely.
        error = None
        try:
            await self.authority._abandon(owner, 'operation_interrupted')
        except ControlError as exc:
            error = exc
        try:
            await operation
        except BaseException:  # noqa: BLE001, S110 -- secret-safe consume finished callback
            pass
        if error is not None:
            raise error

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._handlers.add(task)
        try:
            if self._stopping or len(self._handlers) > 32:
                raise ControlError('control_busy')
            peer = writer.get_extra_info('socket')
            pid, uid, _gid = struct.unpack('3i', peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != self.allowed_uid:
                raise ControlError('control_unauthorized')
            request = await _read(reader, 5)
            command = request.get('command')
            if command not in {'acquire', 'backup', 'restore', 'status'}:
                raise ControlError('control_invalid_request')
            timeout = _seconds(request.get('timeout', 180), MAX_OPERATION_SECONDS)
            wait = _seconds(request.get('wait_timeout', 30), MAX_WAIT_SECONDS)
            allowed = {'command', 'timeout', 'wait_timeout'}
            if command != 'acquire':
                allowed.add('payload')
            if set(request) - allowed:
                raise ControlError('control_invalid_request')
            if command == 'status':
                callback = self.callbacks.get('status')
                if callback is None or request.get('payload', {}) != {}:
                    raise ControlError('control_invalid_request')
                async with asyncio.timeout(min(timeout, MAX_WAIT_SECONDS)):
                    result = await callback({})
                await _write(writer, {'ok': True, 'result': _status_projection(result)})
                return
            owner = MutationOwner(pid, command)
            async with self.authority.exclusive(owner, timeout=timeout, wait_timeout=wait):
                if command == 'acquire':
                    token = secrets.token_hex(32)
                    await _write(writer, {'ok': True, 'token': token})
                    release = await _read(reader, timeout)
                    if (set(release) != {'command', 'token'} or release['command'] != 'release'
                            or not isinstance(release['token'], str)
                            or not secrets.compare_digest(release['token'], token)):
                        raise ControlError('control_invalid_release')
                    await _write(writer, {'ok': True})
                else:
                    callback = self.callbacks.get(command)
                    payload = request.get('payload', {})
                    if callback is None or not isinstance(payload, dict):
                        raise ControlError('control_invalid_request')
                    # Keep callback shielded until its commit/rollback completes;
                    # losing the caller never releases an active writer.
                    operation = asyncio.create_task(callback(payload))
                    disconnected = asyncio.create_task(reader.read(1))
                    try:
                        done, _pending = await asyncio.wait(
                            (operation, disconnected), return_when=asyncio.FIRST_COMPLETED)
                        if disconnected in done:
                            raise ControlError('control_connection_failed')
                        result = operation.result()
                    except BaseException:
                        cleanup = asyncio.create_task(self._finish_interrupted(owner, operation))
                        while not cleanup.done():
                            try:
                                await asyncio.shield(cleanup)
                            except asyncio.CancelledError:
                                continue
                        cleanup.result()
                        raise
                    finally:
                        disconnected.cancel()
                        await asyncio.gather(disconnected, return_exceptions=True)
                    if not isinstance(result, dict):
                        raise ControlError('control_operation_failed')
                    await _write(writer, {'ok': True, 'result': result})
        except asyncio.CancelledError:
            pass
        except ControlError as exc:
            try:
                code = str(exc) if str(exc) in ERROR_CODES else 'control_operation_failed'
                await _write(writer, {'ok': False, 'error': code})
            except ControlError:
                pass
        except Exception:  # noqa: BLE001 -- fixed error, never leak callback exceptions
            try:
                await _write(writer, {'ok': False, 'error': 'control_operation_failed'})
            except ControlError:
                pass
        finally:
            self._handlers.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


class UnixControlClient:
    def __init__(self, path: Path = CONTROL_PATH, *, _test_uid: int = 0):
        self.path = path
        self._uid = _test_uid

    async def _connect(self):
        try:
            node = self.path.lstat()
            directory = self.path.parent.lstat()
            if (not stat.S_ISSOCK(node.st_mode) or node.st_uid != self._uid
                    or stat.S_IMODE(node.st_mode) != 0o600
                    or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != self._uid
                    or stat.S_IMODE(directory.st_mode) != 0o700):
                raise ControlError('control_unsafe_socket')
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(
                str(self.path), limit=MAX_FRAME), 5)
            peer = writer.get_extra_info('socket')
            _pid, uid, _gid = struct.unpack('3i', peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != self._uid:
                writer.close()
                await writer.wait_closed()
                raise ControlError('control_unauthorized')
            return reader, writer
        except (OSError, TimeoutError):
            raise ControlError('control_unavailable') from None

    @asynccontextmanager
    async def mutation(self, *, timeout: float = 180, wait_timeout: float = 30):
        timeout = _seconds(timeout, MAX_OPERATION_SECONDS)
        wait_timeout = _seconds(wait_timeout, MAX_WAIT_SECONDS)
        reader, writer = await self._connect()
        try:
            await _write(writer, {'command': 'acquire', 'timeout': timeout,
                                 'wait_timeout': wait_timeout})
            response = await _read(reader, wait_timeout + 5)
            self._check(response)
            token = response.get('token')
            if not isinstance(token, str) or len(token) != 64:
                raise ControlError('control_invalid_response')
            # Client also bounds its task. On timeout/disconnect the server
            # guards and quiesces the peer before granting another lease.
            async with asyncio.timeout(timeout):
                yield
            await _write(writer, {'command': 'release', 'token': token})
            self._check(await _read(reader, 5))
        finally:
            writer.close()
            await writer.wait_closed()

    async def request(self, command: str, payload: dict | None = None, *, timeout: float = 180):
        if command not in {'backup', 'restore', 'status'}:
            raise ControlError('control_invalid_request')
        timeout = _seconds(timeout, MAX_OPERATION_SECONDS)
        reader, writer = await self._connect()
        try:
            await _write(writer, {'command': command, 'payload': payload or {}, 'timeout': timeout})
            response = await _read(reader, timeout + MAX_WAIT_SECONDS + 5)
            self._check(response)
            return response.get('result')
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    def _check(response: dict):
        if response.get('ok') is not True:
            code = response.get('error')
            # Never relay arbitrary peer content or exception strings.
            raise ControlError(code if isinstance(code, str) and code in ERROR_CODES
                               else 'control_invalid_response')
