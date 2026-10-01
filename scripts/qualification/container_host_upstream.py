"""D6-only upstream API responses; never installed in the production image.

The real worker, provider keys, transactions, proof, routing and supervisor stay
unchanged. Only Mullvad/PIA HTTP response factories use a disposable external
fixture. Its registration service receives public WireGuard keys, never private
keys or commercial account credentials.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import os
import re
import stat
from pathlib import Path

CONFIG = Path('/data/.d6-upstream.json')
MAX_RESPONSE = 16384


def configuration(path=CONFIG):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        facts = os.fstat(descriptor)
        if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0
                or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_size > 4096):
            raise ValueError('qualification_configuration_invalid')
        with os.fdopen(descriptor, 'r') as source:
            descriptor = None
            value = json.load(source)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(value, dict) or set(value) != {'address', 'port', 'token'}:
        raise ValueError('qualification_configuration_invalid')
    address = ipaddress.IPv4Address(value['address'])
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError('qualification_configuration_invalid')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535:
        raise ValueError('qualification_configuration_invalid')
    if not isinstance(value['token'], str) or re.fullmatch('[a-f0-9]{64}', value['token']) is None:
        raise ValueError('qualification_configuration_invalid')
    return value


class Upstream:
    def __init__(self, config):
        self.config = config

    def request(self, action, **fields):
        client = http.client.HTTPConnection(self.config['address'], self.config['port'], timeout=3)
        try:
            payload = json.dumps({'action': action, **fields}).encode()
            if len(payload) > 4096:
                raise ValueError('qualification_request_invalid')
            client.request('POST', '/upstream', payload, {
                'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.config['token'],
            })
            response = client.getresponse()
            body = response.read(MAX_RESPONSE + 1)
            if response.status != 200 or len(body) > MAX_RESPONSE:
                raise ValueError('qualification_upstream_unavailable')
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {'result'}:
                raise ValueError('qualification_response_invalid')
            return value['result']
        finally:
            client.close()

    async def call(self, action, **fields):
        return await asyncio.to_thread(self.request, action, **fields)


class MullvadResponses:
    def __init__(self, upstream):
        self.upstream = upstream

    async def call(self, action, **fields):
        from exitlane.providers.mullvad import MullvadApiError
        try:
            return await self.upstream.call(action, **fields)
        except (OSError, http.client.HTTPException, ValueError):
            raise MullvadApiError('provider_api_unavailable') from None

    async def devices(self):
        from exitlane.providers.mullvad import Device
        return [Device.parse(value) for value in await self.call('mullvad_devices')]

    async def create_device(self, public_key):
        from exitlane.providers.mullvad import Device
        return Device.parse(await self.call('mullvad_register', public_key=public_key))

    async def delete_device(self, device_id):
        await self.call('mullvad_delete', device_id=device_id)

    async def relays(self):
        from exitlane.providers.mullvad import Relay
        relays = [Relay.parse(value) for value in await self.call('mullvad_relays')]
        if not relays or any(value is None for value in relays):
            raise ValueError('qualification_response_invalid')
        return relays


class PiaResponses:
    def __init__(self, upstream):
        self.upstream = upstream

    async def call(self, action, **fields):
        from exitlane.providers.pia_api import PiaApiError
        try:
            return await self.upstream.call(action, **fields)
        except (OSError, http.client.HTTPException, ValueError):
            raise PiaApiError('provider_api_unavailable') from None

    async def token(self):
        await self.call('pia_token')
        return 'qualification-synthetic-token-only'

    async def catalog(self):
        from exitlane.providers.pia_api import PiaServer
        return [PiaServer.parse(value['region'], value['server'], value['address'])
                for value in await self.call('pia_catalog')]

    async def add_key(self, server, public_key):
        from exitlane.providers.pia_api import PiaKeyResponse
        return PiaKeyResponse.parse(await self.call(
            'pia_register', peer=server.region_id, public_key=public_key),
            expected_public_key=public_key, expected_server_address=server.address)


def install(config=None):
    """Replace exactly two upstream factories on existing provider singletons."""
    from exitlane.providers import mullvad, pia
    upstream = Upstream(config if config is not None else configuration())
    mullvad.provider.api_factory = lambda _account: MullvadResponses(upstream)
    pia.provider.api_factory = lambda _username, _password: PiaResponses(upstream)
