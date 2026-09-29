"""Shared provider registration for the API and early-boot recovery CLI."""

from exitlane.providers.mullvad import provider as mullvad_provider
from exitlane.providers.nordvpn import provider as nordvpn_provider
from exitlane.providers.pia import provider as pia_provider
from exitlane.providers.proton import provider as proton_provider
from exitlane.providers.registry import ProviderRegistry

provider_registry = ProviderRegistry(
    [nordvpn_provider, mullvad_provider, pia_provider, proton_provider],
    default_id=nordvpn_provider.id,
)
