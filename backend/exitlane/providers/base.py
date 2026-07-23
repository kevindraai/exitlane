from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass


class ProviderActionUnsupported(RuntimeError):
    """Raised when a provider does not implement an optional explicit action."""


@dataclass(frozen=True)
class ProviderMetadata:
    id: str
    display_name: str
    short_name: str
    description: str
    icon: str
    provider_type: str = "commercial_vpn"
    authentication_method: str = "token"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


class Provider(ABC):
    id: str
    display_name: str
    metadata: ProviderMetadata

    @abstractmethod
    async def status(self): ...
    @abstractmethod
    async def connect(self, target=None): ...
    @abstractmethod
    async def disconnect(self): ...

    def capabilities(
        self,
        *,
        installation_state: str,
        authentication_state: str,
        connection_state: str,
    ) -> dict[str, bool]:
        """Return conservative management capabilities for forward-compatible clients."""
        return {
            "can_sign_in": False,
            "can_sign_out": False,
            "can_connect": False,
            "can_disconnect": False,
            "can_reconnect": False,
            "can_select_country": False,
            "can_select_server": False,
            "can_measure_latency": False,
            "can_select_location": False,
            "can_manage_provider_killswitch": False,
            "can_manage_killswitch": False,
        }

    async def authenticate(self, credential: str) -> dict:
        raise ProviderActionUnsupported("provider_action_unsupported")

    async def sign_out(self) -> dict:
        raise ProviderActionUnsupported("provider_action_unsupported")

    async def reconnect(self, target: str | None = None) -> dict:
        return await self.connect(target)

    async def countries(self) -> list[dict]:
        raise ProviderActionUnsupported("provider_action_unsupported")

    async def servers(self, location_id: int) -> list[dict]:
        raise ProviderActionUnsupported("provider_action_unsupported")

    def management_status(
        self,
        *,
        installation_state: str,
        authentication_state: str,
        connection_state: str,
        error_code: str | None = None,
        reconnect_required: bool = False,
    ) -> dict:
        return {
            "provider": {
                "id": self.id,
                "display_name": self.display_name,
                "installation_state": installation_state,
            },
            "authentication": {"state": authentication_state},
            "connection": {"state": connection_state},
            "capabilities": self.capabilities(
                installation_state=installation_state,
                authentication_state=authentication_state,
                connection_state=connection_state,
            ),
            "error_code": error_code,
            "reconnect_required": reconnect_required,
        }
