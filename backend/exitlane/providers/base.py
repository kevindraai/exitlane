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
