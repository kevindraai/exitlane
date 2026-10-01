"""No native network fallback before first-run ingress is configured."""

from exitlane.services.provider_wireguard import ProviderWireGuardError


class UnconfiguredContainerEgress:
    """Explicit unavailable adapter; no inherited native commands or file writes."""

    async def _unavailable(self, *_args, **_kwargs):
        raise ProviderWireGuardError("container_ingress_required")

    start = stop = stop_interface = probe = observe = status = _unavailable
    arm = arm_source = arm_for_restore = reapply_guards = disarm = _unavailable
    transition_facts = committed = verify_route = interface_exists = _unavailable

    def remove_config(self, *_args, **_kwargs):
        raise ProviderWireGuardError("container_ingress_required")
