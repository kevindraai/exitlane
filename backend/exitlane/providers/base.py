from abc import ABC, abstractmethod


class Provider(ABC):
    id: str
    display_name: str

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
            "can_select_location": False,
            "can_manage_killswitch": False,
        }

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
