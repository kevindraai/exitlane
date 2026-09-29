"""Strict boundary for PIA's published manual WireGuard protocol."""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"  # nosec B105
CATALOG_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
CA_PATH = Path(__file__).with_name("pia_ca.pem")
MAX_RESPONSE = 8 * 1024 * 1024
MAX_ACCOUNT_RESPONSE = 32 * 1024
TOKEN_LIFETIME = 23 * 60 * 60  # Upstream documents 24 hours; refresh early.
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,79}$")
HOSTNAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
TOKEN = re.compile(r"^[A-Za-z0-9._~-]{16,4096}$")
KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class PiaApiError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ipv4(value: object, *, public: bool) -> str:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError) as error:
        raise PiaApiError("provider_api_invalid_response") from error
    if (
        address.version != 4
        or (public and not address.is_global)
        or address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
    ):
        raise PiaApiError("provider_api_invalid_response")
    return str(address)


def _host_address(value: object) -> str:
    try:
        address = ipaddress.ip_interface(value)
    except (TypeError, ValueError) as error:
        raise PiaApiError("provider_api_invalid_response") from error
    if (
        address.version != 4
        or address.network.prefixlen != 32
        or address.ip.is_unspecified
        or address.ip.is_multicast
        or address.ip.is_loopback
        or address.ip.is_link_local
    ):
        raise PiaApiError("provider_api_invalid_response")
    return str(address)


def _key(value: object) -> str:
    import base64

    if not isinstance(value, str) or KEY.fullmatch(value) is None:
        raise PiaApiError("provider_api_invalid_response")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise PiaApiError("provider_api_invalid_response") from error
    if len(raw) != 32:
        raise PiaApiError("provider_api_invalid_response")
    return value


@dataclass(frozen=True)
class PiaServer:
    region_id: str
    region_name: str
    country_code: str
    hostname: str
    address: str
    latency_address: str

    @property
    def selection_id(self) -> str:
        return f"{self.region_id}.{self.hostname}"

    @classmethod
    def parse(cls, region: dict, server: dict, latency_address: str) -> PiaServer:
        identifier = region.get("id")
        name = region.get("name")
        country = region.get("country")
        raw_hostname = server.get("cn")
        hostname = raw_hostname.casefold() if isinstance(raw_hostname, str) else raw_hostname
        if (
            not isinstance(identifier, str)
            or IDENTIFIER.fullmatch(identifier) is None
            or not isinstance(name, str)
            or not 1 <= len(name) <= 80
            or not name.isprintable()
            or not isinstance(country, str)
            or re.fullmatch(r"[A-Z]{2}", country) is None
            or not isinstance(hostname, str)
            or HOSTNAME.fullmatch(hostname) is None
        ):
            raise PiaApiError("provider_api_invalid_response")
        parsed = cls(
            identifier,
            name,
            country,
            hostname,
            _ipv4(server.get("ip"), public=True),
            latency_address,
        )
        if len(parsed.selection_id) > 80:
            raise PiaApiError("provider_api_invalid_response")
        return parsed


@dataclass(frozen=True)
class PiaKeyResponse:
    peer_ip: str
    server_key: str
    server_port: int
    dns_address: str

    @classmethod
    def parse(
        cls,
        payload: object,
        *,
        expected_public_key: str | None = None,
        expected_server_address: str | None = None,
    ) -> PiaKeyResponse:
        if not isinstance(payload, dict) or payload.get("status") != "OK":
            raise PiaApiError("provider_api_invalid_response")
        port = payload.get("server_port")
        dns = payload.get("dns_servers")
        if (
            type(port) is not int
            or not 1 <= port <= 65535
            or not isinstance(dns, list)
            or not 1 <= len(dns) <= 4
        ):
            raise PiaApiError("provider_api_invalid_response")
        addresses = [_ipv4(item, public=False) for item in dns]
        if (
            expected_public_key is not None
            and payload.get("peer_pubkey") is not None
            and _key(payload["peer_pubkey"]) != expected_public_key
        ):
            raise PiaApiError("provider_api_invalid_response")
        if (
            expected_server_address is not None
            and payload.get("server_ip") is not None
            and _ipv4(payload["server_ip"], public=True) != expected_server_address
        ):
            raise PiaApiError("provider_api_invalid_response")
        return cls(
            _host_address(payload.get("peer_ip")),
            _key(payload.get("server_key")),
            port,
            addresses[0],
        )


def parse_catalog(payload: object) -> list[PiaServer]:
    if not isinstance(payload, dict) or not isinstance(payload.get("regions"), list):
        raise PiaApiError("provider_api_invalid_response")
    regions = payload["regions"]
    if not 1 <= len(regions) <= 512:
        raise PiaApiError("provider_api_invalid_response")
    result: list[PiaServer] = []
    seen: set[tuple[str, str]] = set()
    for region in regions:
        if not isinstance(region, dict):
            raise PiaApiError("provider_api_invalid_response")
        if type(region.get("offline")) is not bool:
            raise PiaApiError("provider_api_invalid_response")
        if region["offline"] is True:
            continue
        servers = region.get("servers")
        if (
            not isinstance(servers, dict)
            or not isinstance(servers.get("wg"), list)
            or not isinstance(servers.get("meta"), list)
        ):
            raise PiaApiError("provider_api_invalid_response")
        if not servers["wg"] or not servers["meta"] or len(servers["wg"]) > 32:
            raise PiaApiError("provider_api_invalid_response")
        if not isinstance(servers["meta"][0], dict):
            raise PiaApiError("provider_api_invalid_response")
        latency_address = _ipv4(servers["meta"][0].get("ip"), public=True)
        for item in servers["wg"]:
            if not isinstance(item, dict):
                raise PiaApiError("provider_api_invalid_response")
            parsed = PiaServer.parse(region, item, latency_address)
            identity = (parsed.region_id, parsed.hostname)
            if identity in seen:
                raise PiaApiError("provider_api_invalid_response")
            seen.add(identity)
            result.append(parsed)
    if not result:
        raise PiaApiError("provider_api_invalid_response")
    return result


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str):
        context = ssl.create_default_context(cafile=str(CA_PATH))
        super().__init__(hostname, port=1337, timeout=15, context=context)
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class PiaApi:
    def __init__(self, username: str | None = None, password: str | None = None):
        self.username = username
        self.password = password
        self._token: str | None = None
        self._token_deadline = 0.0
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _public_request(
        self,
        url: str,
        *,
        form: bytes | None = None,
        boundary: str | None = None,
        maximum: int,
    ) -> bytes:
        if form is not None and (
            not isinstance(boundary, str) or re.fullmatch(r"[A-Za-z0-9-]{1,70}", boundary) is None
        ):
            raise PiaApiError("provider_api_invalid_response")
        request = urllib.request.Request(
            url, data=form, method="POST" if form is not None else "GET"
        )
        request.add_header("Accept", "application/json")
        if form is not None:
            request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        try:
            with self._opener.open(request, timeout=15) as response:
                if response.status != 200:
                    raise PiaApiError("provider_api_unavailable")
                data = response.read(maximum + 1)
        except urllib.error.HTTPError as error:
            raise PiaApiError(
                "invalid_credentials"
                if form is not None and error.code in {401, 403}
                else "provider_api_unavailable"
            ) from None
        except (TimeoutError, urllib.error.URLError) as error:
            raise PiaApiError(
                "provider_api_timeout"
                if isinstance(error, TimeoutError)
                else "provider_api_unavailable"
            ) from None
        except OSError:
            raise PiaApiError("provider_api_unavailable") from None
        if len(data) > maximum:
            raise PiaApiError("provider_api_invalid_response")
        return data

    async def token(self) -> str:
        if self._token and time.monotonic() < self._token_deadline:
            return self._token
        if not self.username or not self.password:
            raise PiaApiError("invalid_credentials")
        if (
            len(self.username) > 80
            or len(self.password) > 400
            or not self.username.isascii()
            or not self.username.isalnum()
            or not self.password.isprintable()
        ):
            raise PiaApiError("invalid_credentials")
        boundary = f"exitlane-{secrets.token_hex(16)}"
        form = (
            b"".join(
                b"--"
                + boundary.encode("ascii")
                + b"\r\n"
                + f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("ascii")
                + value.encode("utf-8")
                + b"\r\n"
                for name, value in (("username", self.username), ("password", self.password))
            )
            + b"--"
            + boundary.encode("ascii")
            + b"--\r\n"
        )
        raw = await asyncio.to_thread(
            self._public_request,
            TOKEN_URL,
            form=form,
            boundary=boundary,
            maximum=MAX_ACCOUNT_RESPONSE,
        )
        try:
            payload = json.loads(raw)
        except (UnicodeError, ValueError) as error:
            raise PiaApiError("provider_api_invalid_response") from error
        value = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(value, str) or TOKEN.fullmatch(value) is None:
            raise PiaApiError(
                "invalid_credentials"
                if isinstance(payload, dict) and payload.get("token") is None
                else "provider_api_invalid_response"
            )
        self._token = value
        self._token_deadline = time.monotonic() + TOKEN_LIFETIME
        return value

    async def catalog(self) -> list[PiaServer]:
        raw = await asyncio.to_thread(self._public_request, CATALOG_URL, maximum=MAX_RESPONSE)
        try:
            payload = json.loads(raw.split(b"\n", 1)[0])
        except (UnicodeError, ValueError) as error:
            raise PiaApiError("provider_api_invalid_response") from error
        return parse_catalog(payload)

    def _add_key_sync(self, server: PiaServer, token: str, public_key: str) -> PiaKeyResponse:
        if (
            not isinstance(server, PiaServer)
            or not isinstance(token, str)
            or TOKEN.fullmatch(token) is None
        ):
            raise PiaApiError("provider_api_invalid_response")
        _key(public_key)
        # The published CA authenticates the selected CN while the socket uses its catalog IP.
        connection = None
        query = urllib.parse.urlencode({"pt": token, "pubkey": public_key})
        try:
            connection = _PinnedConnection(server.hostname, server.address)
            connection.request("GET", f"/addKey?{query}", headers={"Accept": "application/json"})
            response = connection.getresponse()
            raw = response.read(MAX_ACCOUNT_RESPONSE + 1)
            if response.status != 200 or len(raw) > MAX_ACCOUNT_RESPONSE:
                raise PiaApiError(
                    "provider_api_unavailable"
                    if response.status != 200
                    else "provider_api_invalid_response"
                )
            try:
                payload = json.loads(raw)
            except (UnicodeError, ValueError) as error:
                raise PiaApiError("provider_api_invalid_response") from error
            return PiaKeyResponse.parse(
                payload,
                expected_public_key=public_key,
                expected_server_address=server.address,
            )
        except TimeoutError:
            raise PiaApiError("provider_api_timeout") from None
        except (OSError, ssl.SSLError, http.client.HTTPException):
            raise PiaApiError("provider_api_unavailable") from None
        finally:
            if connection is not None:
                connection.close()

    async def add_key(self, server: PiaServer, public_key: str) -> PiaKeyResponse:
        return await asyncio.to_thread(self._add_key_sync, server, await self.token(), public_key)
