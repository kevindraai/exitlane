from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from exitlane.container_control import ControlError
from exitlane.runtime import NativeSystemdRuntime, RuntimePaths
from exitlane.runtime_mutation import RuntimeMutationMiddleware, finish_writer


class Runtime:
    coordinated_mutations = True

    def __init__(self):
        self.events = []
        self.busy = False

    @asynccontextmanager
    async def mutation(self):
        if self.busy:
            raise ControlError('control_busy')
        self.events.append('acquire')
        try:
            yield
        finally:
            self.events.append('release')


def test_authenticated_get_is_writer_but_health_assets_are_read_only():
    async def scenario():
        runtime = Runtime()

        async def app(scope, receive, send):
            runtime.events.append(scope['path'])

        middleware = RuntimeMutationMiddleware(app, runtime=runtime)
        for path in ('/api/settings', '/api/auth/session', '/api/health', '/assets/app.js', '/'):
            await middleware({'type': 'http', 'path': path, 'method': 'GET'}, None, None)
        assert runtime.events == ['acquire', '/api/settings', 'release', 'acquire',
                                  '/api/auth/session', 'release', '/api/health',
                                  '/assets/app.js', '/']
    asyncio.run(scenario())


def test_busy_recovery_does_not_call_application():
    async def scenario():
        runtime = Runtime()
        runtime.busy = True
        output = []

        async def app(*args):
            raise AssertionError('application writer ran')

        async def send(message):
            output.append(message)

        await RuntimeMutationMiddleware(app, runtime=runtime)(
            {'type': 'http', 'path': '/api/auth/session', 'method': 'GET'}, None, send)
        assert output[0]['status'] == 503
        assert b'runtime_recovery_busy' in output[1]['body']
    asyncio.run(scenario())


def test_cancelled_request_keeps_lease_until_writer_finishes():
    async def scenario():
        runtime = Runtime()
        started = asyncio.Event()
        finish = asyncio.Event()

        async def app(*args):
            started.set()
            await finish.wait()
            runtime.events.append('committed')

        task = asyncio.create_task(RuntimeMutationMiddleware(app, runtime=runtime)(
            {'type': 'http', 'path': '/api/settings'}, None, None))
        await started.wait()
        task.cancel()
        await asyncio.sleep(0)
        assert runtime.events == ['acquire']
        finish.set()
        result = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(result[0], asyncio.CancelledError)
        assert runtime.events == ['acquire', 'committed', 'release']
    asyncio.run(scenario())


def test_native_context_preserves_cancellation():
    async def scenario():
        runtime = NativeSystemdRuntime()
        assert not runtime.coordinated_mutations
        async with runtime.mutation():
            pass
    asyncio.run(scenario())


def test_container_paths_are_fixed_and_do_not_enable_composition(tmp_path):
    paths = RuntimePaths.container(tmp_path)
    assert paths.config == tmp_path / 'config'
    assert paths.application_data == paths.service_data == tmp_path / 'state'
    assert paths.system_wireguard == tmp_path / 'state/wireguard'
    assert list(tmp_path.iterdir()) == []


def test_cancelled_child_failure_does_not_replace_cancellation():
    async def scenario():
        started = asyncio.Event()
        finish = asyncio.Event()

        async def operation():
            started.set()
            await finish.wait()
            raise ValueError('synthetic secret omitted')

        task = asyncio.create_task(finish_writer(operation()))
        await started.wait()
        task.cancel()
        finish.set()
        result = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(result[0], asyncio.CancelledError)
    asyncio.run(scenario())


def test_document_authentication_and_nonget_health_are_writers():
    async def scenario():
        runtime = Runtime()
        async def app(scope, receive, send):
            runtime.events.append(scope['path'])
        middleware = RuntimeMutationMiddleware(app, runtime=runtime)
        for path, method in (
            ('/docs', 'GET'), ('/redoc', 'GET'), ('/openapi.json', 'GET'),
            ('/api/health', 'POST'), ('/api/health', 'HEAD'), ('/assets/app.js', 'POST'),
        ):
            await middleware({'type': 'http', 'path': path, 'method': method}, None, None)
        assert len(runtime.events) == 18
        assert runtime.events[::3] == ['acquire'] * 6
        assert runtime.events[2::3] == ['release'] * 6
    asyncio.run(scenario())


def test_container_startup_refuses_before_any_initialization(monkeypatch):
    import pytest

    from exitlane import main
    from exitlane.runtime_mutation import ContainerMutationBoundary

    class Client:
        def mutation(self):
            pytest.fail('startup must not request another restore-owned lease')

    monkeypatch.setattr(main, 'runtime', ContainerMutationBoundary(Client()))
    monkeypatch.setattr(main, 'init', lambda: pytest.fail('state initialized before handoff'))
    monkeypatch.setattr(main, 'validate_config', lambda: pytest.fail('startup side effect'))

    async def scenario():
        with pytest.raises(ControlError, match='control_startup_handoff_required'):
            async with main.lifespan(main.app):
                pytest.fail('container startup enabled before D5')
    asyncio.run(scenario())


def test_native_lifespan_initializes_then_starts_and_joins_monitors(monkeypatch):
    from exitlane import main

    events = []
    async def initialize():
        events.append('initialized')
    async def monitor():
        events.append('monitor-started')
        try:
            await asyncio.Event().wait()
        finally:
            events.append('monitor-stopped')
    monkeypatch.setattr(main, 'runtime', NativeSystemdRuntime())
    monkeypatch.setattr(main, '_initialize_runtime_state', initialize)
    monkeypatch.setattr(main, '_monitor_killswitch', monitor)
    monkeypatch.setattr(main, '_monitor_management_routing', monitor)

    async def scenario():
        async with main.lifespan(main.app):
            await asyncio.sleep(0)
            assert events == ['initialized', 'monitor-started', 'monitor-started']
        assert events[-2:] == ['monitor-stopped', 'monitor-stopped']
    asyncio.run(scenario())


def test_actual_auth_read_waits_for_cancelled_network_monitor(monkeypatch, tmp_path):
    import httpx

    from exitlane import core, main

    monkeypatch.setattr(core, 'DATA', tmp_path)
    monkeypatch.setattr(core, 'DB', tmp_path / 'exitlane.db')
    monkeypatch.setattr(core, 'WG_DIR', tmp_path / 'wireguard')
    core.init()

    async def scenario():
        held = asyncio.Lock()
        entered = asyncio.Event()
        finish = asyncio.Event()
        tick = asyncio.Queue()
        events = []
        original_sleep = asyncio.sleep

        class Coordinated(NativeSystemdRuntime):
            coordinated_mutations = True

            @asynccontextmanager
            async def mutation(self):
                async with held:
                    events.append('acquire')
                    try:
                        yield
                    finally:
                        events.append('release')

        coordinated = Coordinated()
        async def sleep(seconds):
            if seconds == 5:
                await tick.get()
            else:
                await original_sleep(seconds)
        async def reconcile():
            assert held.locked()
            events.append('network-start')
            entered.set()
            await finish.wait()
            events.append('network-committed')
        def session_user(_cookie):
            assert held.locked()
            events.append('session-write')

        monkeypatch.setattr(main, 'runtime', coordinated)
        monkeypatch.setattr(main.asyncio, 'sleep', sleep)
        monkeypatch.setattr(main.management_routing, 'reconcile', reconcile)
        monkeypatch.setattr(main, 'session_user', session_user)
        # Actual app/auth middleware and actual periodic monitor share the
        # outer runtime boundary; the default inner native boundary is a no-op.
        wrapped = RuntimeMutationMiddleware(main.app, runtime=coordinated)
        monitor = asyncio.create_task(main._monitor_management_routing())
        await tick.put(None)
        await entered.wait()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped),
                                     base_url='http://testserver') as client:
            request = asyncio.create_task(client.get('/docs'))
            monitor.cancel()
            await original_sleep(0.01)
            assert events == ['acquire', 'network-start']
            assert not monitor.done() and not request.done()
            finish.set()
            result = await asyncio.gather(monitor, return_exceptions=True)
            assert isinstance(result[0], asyncio.CancelledError)
            assert (await request).status_code == 401
        assert events == ['acquire', 'network-start', 'network-committed', 'release',
                          'acquire', 'session-write', 'release']
    asyncio.run(scenario())


def test_actual_killswitch_monitor_busy_retry_never_writes_unleased(monkeypatch):
    import pytest

    from exitlane import main

    async def scenario():
        tick = asyncio.Queue()
        denied = asyncio.Event()
        entered = asyncio.Event()
        original_sleep = asyncio.sleep
        attempts = []

        class Coordinated(NativeSystemdRuntime):
            coordinated_mutations = True

            @asynccontextmanager
            async def mutation(self):
                attempts.append('claim')
                if len(attempts) == 1:
                    denied.set()
                    raise ControlError('control_busy')
                try:
                    yield
                finally:
                    attempts.append('release')
        async def sleep(seconds):
            if seconds == 5:
                await tick.get()
            else:
                await original_sleep(seconds)
        async def iteration(previous, facts):
            entered.set()
            return previous, facts
        monkeypatch.setattr(main, 'runtime', Coordinated())
        monkeypatch.setattr(main.asyncio, 'sleep', sleep)
        monkeypatch.setattr(main, '_killswitch_monitor_iteration', iteration)
        monkeypatch.setattr(main, 'record_event', lambda *a, **k: pytest.fail('unleased Activity'))
        monitor = asyncio.create_task(main._monitor_killswitch())
        await tick.put(None)
        await denied.wait()
        await tick.put(None)
        await entered.wait()
        await original_sleep(0)
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        assert attempts == ['claim', 'claim', 'release']
    asyncio.run(scenario())
