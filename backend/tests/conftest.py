import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from exitlane.services import management_routing, wireguard


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


@pytest.fixture
def synthetic_wireguard_keys(monkeypatch):
    """Exercise real X25519 identities without requiring wg-tools on CI runners."""

    async def keypair():
        private = X25519PrivateKey.generate()
        raw_private = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        raw_public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw_private).decode(), base64.b64encode(raw_public).decode()

    async def public_key(private):
        raw = base64.b64decode(private, validate=True)
        public = (
            X25519PrivateKey.from_private_bytes(raw)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        return base64.b64encode(public).decode()

    monkeypatch.setattr(wireguard, "keypair", keypair)
    monkeypatch.setattr(wireguard, "_public_key", public_key)
