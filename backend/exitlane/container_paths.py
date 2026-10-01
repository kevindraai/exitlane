"""Pure container paths; safe to import before application composition."""
from dataclasses import dataclass
from pathlib import Path


class ContainerStateError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(condition: bool, code: str = "container_state_invalid") -> None:
    if not condition:
        raise ContainerStateError(code)


@dataclass(frozen=True)
class ContainerLayout:
    root: Path

    def __post_init__(self):
        object.__setattr__(self, "root", Path(self.root))
        require(self.root.is_absolute() and ".." not in self.root.parts)

    @property
    def config(self):
        return self.root / "config"

    @property
    def state(self):
        return self.root / "state"

    @property
    def database(self):
        return self.state / "exitlane.db"

    @property
    def master_key(self):
        return self.config / "secret.key"

    @property
    def wireguard(self):
        return self.state / "wireguard"

    @property
    def provider_egress(self):
        return self.state / "provider-egress"

    @property
    def recovery(self):
        return self.root / "recovery"

    @property
    def backups(self):
        return self.root / "backups"

    @property
    def manifest(self):
        return self.root / "layout.json"
