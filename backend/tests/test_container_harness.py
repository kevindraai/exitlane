"""Cross-engine capability spellings retain the same minimal privilege contract."""

import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[2] / "scripts/qualification/container_lifecycle.py"
spec = importlib.util.spec_from_file_location("container_lifecycle_harness", path)
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


@pytest.mark.parametrize("capabilities", [["NET_ADMIN"], ["CAP_NET_ADMIN"]])
def test_capability_aliases_mean_exactly_net_admin(capabilities):
    harness.validate_capabilities(capabilities)


@pytest.mark.parametrize(
    "capabilities",
    [[], ["ALL"], ["SYS_ADMIN"], ["NET_ADMIN", "NET_RAW"], ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"]],
)
def test_additional_or_missing_capabilities_are_rejected(capabilities):
    with pytest.raises(AssertionError):
        harness.validate_capabilities(capabilities)
