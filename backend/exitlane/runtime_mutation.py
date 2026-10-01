"""One outer runtime lease covers request writers, including authenticated reads.

Health and immutable assets are read-only. Session checks and Activity updates
can write during GET requests, so HTTP method alone is not a safe distinction.
Native mutation contexts remain no-ops. Container activation belongs to D5.
"""

from __future__ import annotations

import asyncio
import os
import socket
import stat
from contextlib import asynccontextmanager, suppress

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from exitlane.container_control import ControlError, _read, _write


class ContainerMutationBoundary:
    """Explicit IPC boundary for a worker; no capability/runtime activation."""

    coordinated_mutations = True

    def __init__(self, client):
        self.client = client

    def mutation(self):
        return self.client.mutation()

    def startup_mutation(self):
        return StartupBorrower.from_environment().context()


class StartupBorrower:
    """One inherited supervisor channel authorizes initialization only once."""

    def __init__(self, fd: int):
        self.fd = fd
        self.used = False

    @classmethod
    def from_environment(cls):
        value = os.environ.pop("EXITLANE_STARTUP_FD", None)
        if value is None or not value.isascii() or not value.isdecimal():
            raise ControlError("control_startup_handoff_required")
        fd = int(value)
        if not 3 <= fd <= 65535:
            raise ControlError("control_startup_handoff_required")
        return cls(fd)

    @asynccontextmanager
    async def context(self):
        if self.used:
            raise ControlError("control_startup_handoff_required")
        self.used = True
        writer = None
        try:
            facts = os.fstat(self.fd)
            if not stat.S_ISSOCK(facts.st_mode):
                raise ControlError("control_startup_handoff_required")
            sock = socket.socket(fileno=self.fd)
            self.fd = -1
            if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
                sock.close()
                raise ControlError("control_startup_handoff_required")
            sock.setblocking(False)
            reader, writer = await asyncio.open_connection(sock=sock, limit=16384)
            grant = await _read(reader, 30)
            if (
                grant != {"command": "startup-grant", "version": 1}
                or type(grant["version"]) is not int
            ):
                raise ControlError("control_startup_handoff_required")
            try:
                async with asyncio.timeout(30):
                    yield
            except BaseException:
                await _write(writer, {"command": "startup-failed", "version": 1})
                raise
            else:
                await _write(writer, {"command": "initialized", "version": 1})
        except OSError:
            raise ControlError("control_startup_handoff_required") from None
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            elif self.fd >= 0:
                with suppress(OSError):
                    os.close(self.fd)
                self.fd = -1


class RuntimeMutationMiddleware:
    def __init__(self, app: ASGIApp, *, runtime):
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        path = scope.get("path", "")
        method = scope.get("method", "")
        protected_documents = {"/docs", "/redoc", "/openapi.json"}
        readonly = (
            method == "GET"
            and path == "/api/health"
            or method in {"GET", "HEAD"}
            and not path.startswith("/api/")
            and path not in protected_documents
        )
        if scope["type"] != "http" or readonly:
            return await self.app(scope, receive, send)
        started = False

        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            async with self.runtime.mutation():
                if self.runtime.coordinated_mutations:
                    await finish_writer(self.app(scope, receive, tracked_send))
                else:
                    await self.app(scope, receive, tracked_send)
        except ControlError:
            if started:
                raise
            await JSONResponse(status_code=503, content={"detail": "runtime_recovery_busy"})(
                scope, receive, send
            )


async def finish_writer(operation):
    """Cancellation cannot release a lease while a child writer is still alive."""
    task = asyncio.create_task(operation)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:  # noqa: BLE001 -- preserve the caller's cancellation
                break
        # Retrieve failure without exposing it through a cancelled caller.
        if not task.cancelled():
            task.exception()
        raise
