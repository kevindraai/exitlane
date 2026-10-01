"""The IPv6 host coordinator must handle L3 WireGuard links without MACs."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "scripts/qualification"))

from container_host import QualificationError
from container_host_ipv6_qualify import LINK_FACTS_PROGRAM, _mac_for_link


def test_wireguard_link_without_address_has_no_mac():
    """`ip -j link` omits address for ARPHRD_NONE; the coordinator must allow it."""
    assert _mac_for_link("none", None) is None
    assert "links[0].get('address')" in LINK_FACTS_PROGRAM
    assert "links[0]['address']" not in LINK_FACTS_PROGRAM


def test_ethernet_link_requires_a_valid_mac():
    assert _mac_for_link("ether", "02:00:00:00:00:01") == "02:00:00:00:00:01"
    for value in (None, "", "synthetic-invalid"):
        with pytest.raises(QualificationError, match="ipv6_calibration_hardware_invalid"):
            _mac_for_link("ether", value)


def test_unknown_link_type_fails_closed():
    with pytest.raises(QualificationError, match="ipv6_calibration_hardware_invalid"):
        _mac_for_link("loopback", None)
