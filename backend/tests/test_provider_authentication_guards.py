import asyncio

import pytest
from fastapi import HTTPException

from exitlane import main


def provider_status(authentication_state: str) -> dict:
    return {
        "installed": True,
        "authenticated": authentication_state == "signed_in",
        "connected": False,
        "management": {"authentication": {"state": authentication_state}},
    }


def test_signed_out_provider_is_rejected_with_safe_machine_code(monkeypatch):
    async def signed_out():
        return provider_status("signed_out")

    monkeypatch.setattr(main, "_fresh_vpn_status", signed_out)
    with pytest.raises(HTTPException) as error:
        asyncio.run(main._require_provider_authentication())
    assert error.value.status_code == 409
    assert error.value.detail == "provider_authentication_required"


def test_signed_in_provider_passes_authentication_guard(monkeypatch):
    expected = provider_status("signed_in")

    async def signed_in():
        return expected

    monkeypatch.setattr(main, "_fresh_vpn_status", signed_in)
    assert asyncio.run(main._require_provider_authentication()) == expected


@pytest.mark.parametrize(
    ("action", "arguments"),
    [
        (main.vpn_country_servers, ("NL",)),
        (main.measure_vpn_country, ("NL",)),
        (main.connect_vpn_country, (main.CountryConnect(country_code="NL"), None)),
        (main.connect_nordvpn, (main.Connect(target="NL"), None)),
    ],
)
def test_provider_dependent_endpoints_stop_before_work_when_signed_out(
    monkeypatch, action, arguments
):
    async def reject():
        raise HTTPException(409, "provider_authentication_required")

    monkeypatch.setattr(main, "_require_provider_authentication", reject)
    with pytest.raises(HTTPException) as error:
        asyncio.run(action(*arguments))
    assert error.value.detail == "provider_authentication_required"
