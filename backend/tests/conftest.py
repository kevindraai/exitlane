import pytest

from exitlane.services import management_routing


@pytest.fixture(autouse=True)
def isolate_host_management_routing(monkeypatch):
    """Unit/API tests must never mutate the host policy-routing database."""

    async def reconcile():
        return management_routing.ReconcileResult((), 0, 0)

    async def prepare_provider_transition():
        return management_routing.ReconcileResult((), 0, 0)

    monkeypatch.setattr(management_routing, "reconcile", reconcile)
    monkeypatch.setattr(
        management_routing,
        "prepare_provider_transition",
        prepare_provider_transition,
        raising=False,
    )
