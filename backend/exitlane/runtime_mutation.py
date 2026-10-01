"""One outer runtime lease covers request writers, including authenticated reads.

Health and immutable assets are read-only. Session checks and Activity updates
can write during GET requests, so HTTP method alone is not a safe distinction.
Native mutation contexts remain no-ops. Container activation belongs to D5.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from exitlane.container_control import ControlError


class ContainerMutationBoundary:
    """Explicit IPC boundary for a worker; no capability/runtime activation."""

    coordinated_mutations = True

    def __init__(self, client):
        self.client = client

    def mutation(self):
        return self.client.mutation()

    @asynccontextmanager
    async def startup_mutation(self):
        # D5 must implement an explicit supervisor-to-worker bootstrap handoff.
        # Requesting another lease while restore owns it would deadlock; silently
        # skipping it would permit startup writes during restore.
        raise ControlError("control_startup_handoff_required")
        yield  # pragma: no cover -- keep this a contextmanager, never authorize startup


class RuntimeMutationMiddleware:
    def __init__(self, app: ASGIApp, *, runtime):
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        path = scope.get("path", "")
        method = scope.get("method", "")
        protected_documents = {"/docs", "/redoc", "/openapi.json"}
        readonly = (
            method == "GET" and path == "/api/health"
            or method in {"GET", "HEAD"} and not path.startswith("/api/")
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
