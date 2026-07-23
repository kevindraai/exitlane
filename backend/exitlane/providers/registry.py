from __future__ import annotations

from collections.abc import Iterable

from .base import Provider


class ProviderNotFound(LookupError):
    """Raised when an API or stored setting references an unknown provider."""


class ProviderRegistry:
    """Deterministic registry of shared provider instances."""

    def __init__(self, providers: Iterable[Provider] = (), *, default_id: str):
        self._providers: dict[str, Provider] = {}
        self.default_id = default_id
        for provider in providers:
            self.register(provider)
        if default_id not in self._providers:
            raise ValueError("Default provider must be registered")

    def register(self, provider: Provider) -> None:
        if provider.id in self._providers:
            raise ValueError(f"Provider already registered: {provider.id}")
        self._providers[provider.id] = provider

    def get(self, provider_id: str) -> Provider:
        try:
            return self._providers[provider_id]
        except KeyError as error:
            raise ProviderNotFound(provider_id) from error

    def all(self) -> tuple[Provider, ...]:
        return tuple(self._providers[key] for key in sorted(self._providers))
