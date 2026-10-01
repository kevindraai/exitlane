"""Validate the evidence contract, including failures that must not be called PASS."""

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "scripts/qualification"
spec = importlib.util.spec_from_file_location(
    "recovery_harness", DIRECTORY / "container_recovery.py"
)
harness = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(DIRECTORY))
try:
    spec.loader.exec_module(harness)
finally:
    sys.path.remove(str(DIRECTORY))


def receipt():
    return {
        "schema": 1,
        "journal_present": False,
        "marker": "old",
        "key_digest": "synthetic-digest",
        "provider_digests": [
            (name, "synthetic-cipher-digest") for name in ("mullvad", "pia", "proton")
        ],
        "intents": [
            (name, "active", "synthetic-generation") for name in ("mullvad", "pia", "proton")
        ],
        "server_public": "synthetic-public",
        "sessions": 0,
    }


def test_coherent_restored_receipt_passes():
    harness.validate_receipt(receipt(), receipt(), marker="old", revoked=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 2),
        ("journal_present", True),
        ("key_digest", "wrong-pair"),
        ("provider_digests", [("mullvad", "missing-other-provider")]),
        ("intents", []),
        ("server_public", "wrong-ingress"),
        ("marker", "new"),
        ("sessions", 1),
    ],
)
def test_incoherent_or_unrevoked_receipts_fail(field, value):
    changed = deepcopy(receipt())
    changed[field] = value
    with pytest.raises(AssertionError):
        harness.validate_receipt(receipt(), changed, marker="old", revoked=True)


def test_checkpoint_matrix_includes_mixed_file_publications():
    assert set(harness.CHECKPOINTS) >= {
        "prepared",
        "snapshot_ready",
        "publishing",
        "published_database",
        "published_master_key",
        "published_manifest",
        "published_wireguard",
        "published_provider_egress",
        "installed",
        "validated",
        "committed",
    }


def test_embedded_owned_writer_and_worker_programs_compile():
    spec = importlib.util.spec_from_file_location(
        "recovery_fixture", DIRECTORY / "container_recovery_fixture.py"
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    compile(fixture.WRITER, "synthetic-writer", "exec")
    compile(fixture.WORKER, "synthetic-worker", "exec")
