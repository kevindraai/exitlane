import asyncio
from types import SimpleNamespace

import pytest

from exitlane import container_runtime, core
from exitlane.runtime import ContainerRuntime


@pytest.mark.parametrize("interface", ["wg-office", "wg-retry"])
def test_worker_retries_changed_initial_identity_only_after_owned_rollback(
    tmp_path, monkeypatch, interface
):
    original = SimpleNamespace(interface="wg-office", address="10.77.0.1/24")
    replacement = SimpleNamespace(interface=interface, address="10.88.0.1/24")
    calls = []

    class Network:
        def __init__(self):
            self.config = original

        async def rebind_initial_ingress(self, config):
            calls.append(("rebind", config.interface))
            self.config = config

        async def observe_guard(self):
            calls.append(("observe", self.config.interface))

    class Client:
        async def request(self, command, payload):
            calls.append((command, payload["action"], payload["interface"]))
            return {"active": False}

    worker = ContainerRuntime.__new__(ContainerRuntime)
    worker.client = Client()
    worker.network = Network()
    worker._initial_ingress_rolled_back = False
    binding = worker.network
    monkeypatch.setattr(core, "WG_DIR", tmp_path)
    monkeypatch.setattr(core, "setting", lambda _key, default=False: default)
    monkeypatch.setattr(
        container_runtime.IngressConfig, "from_file", classmethod(lambda cls, _path: replacement)
    )

    with pytest.raises(RuntimeError, match="identity_change_unsupported"):
        asyncio.run(worker.configure_providers(interface))
    asyncio.run(worker.deactivate_initial_ingress("wg-office"))
    asyncio.run(worker.configure_providers(interface))
    assert worker.network is binding
    assert worker.network.config is replacement
    assert worker._initial_ingress_rolled_back is False
    assert ("rebind", interface) in calls
