"""Shared provider registration for the API and early-boot recovery CLI."""

from exitlane.providers.mullvad import provider as mullvad_provider
from exitlane.providers.nordvpn import provider as nordvpn_provider
from exitlane.providers.pia import provider as pia_provider
from exitlane.providers.proton import provider as proton_provider
from exitlane.providers.registry import ProviderRegistry
from exitlane.runtime import runtime

provider_registry = ProviderRegistry(
    [nordvpn_provider, mullvad_provider, pia_provider, proton_provider],
    default_id=nordvpn_provider.id if runtime.capabilities.runtime_name == "native" else "mullvad",
    capabilities=lambda: runtime.capabilities,
)

if runtime.capabilities.runtime_name == "container":
    mullvad_provider._legacy_conflict = runtime.legacy_provider_conflict

if runtime.capabilities.runtime_name == "container":
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    for direct in provider_registry.direct_egress_providers():
        direct.wireguard = UnconfiguredContainerEgress()
