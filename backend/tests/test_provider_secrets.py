import sqlite3

import pytest

from exitlane import core
from exitlane.services import auth_security, provider_secrets


@pytest.fixture
def secret_store(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DB", tmp_path / "exitlane.db")
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(auth_security, "master_key_path", lambda: tmp_path / "secret.key")
    core.init()
    auth_security.ensure_master_key()
    return tmp_path


def test_round_trip_update_and_delete(secret_store):
    provider_secrets.save("mullvad", {"private_key": "secret", "count": 1})
    assert provider_secrets.load("mullvad") == {"private_key": "secret", "count": 1}

    provider_secrets.save("mullvad", {"private_key": "replacement"})
    assert provider_secrets.load("mullvad") == {"private_key": "replacement"}

    provider_secrets.delete("mullvad")
    assert provider_secrets.load("mullvad") is None


def test_ciphertext_is_bound_to_provider_identity(secret_store):
    provider_secrets.save("mullvad", {"private_key": "secret"})
    with sqlite3.connect(core.DB) as connection:
        encrypted = connection.execute(
            "SELECT encrypted_payload FROM provider_secrets WHERE provider_id='mullvad'"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO provider_secrets(provider_id, encrypted_payload, updated_at) VALUES(?,?,1)",
            ("other", encrypted),
        )

    with pytest.raises(provider_secrets.ProviderSecretError, match="provider_secret_invalid"):
        provider_secrets.load("other")


def test_invalid_provider_id_is_rejected_before_database_access(secret_store):
    with pytest.raises(provider_secrets.ProviderSecretError, match="provider_secret_invalid"):
        provider_secrets.save("../../bad", {"secret": True})
