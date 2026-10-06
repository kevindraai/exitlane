"""Named WireGuard ingress peers. Private material stays in root-only config files."""

from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import sqlite3
import stat
import unicodedata
import uuid
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from exitlane import core
from exitlane.services import wireguard

Sync = Callable[[str], Awaitable[None]]
PEER_COLUMNS = (
    "peer_id", "name", "description", "public_key", "tunnel_ip", "config_name",
    "status", "is_default", "created_at", "updated_at", "revoked_at",
)
PEER_SECTION = re.compile(r"(?m)^\[Peer\]\s*$")
IDENTIFIER = re.compile(r"[0-9a-f]{32}\Z")


class PeerError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@contextmanager
def state_lock():
    """Serialize cross-process peer writes and a backup's DB+file snapshot."""
    path = core.DATA / ".wireguard-peers.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_mode & 0o077:
            raise PeerError("wireguard_configuration_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PeerError("wireguard_generation_in_progress") from error
        yield
    finally:
        os.close(descriptor)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def validate_name(value: str, *, description: bool = False) -> str:
    limit = 240 if description else 80
    if not isinstance(value, str) or len(value) > limit:
        raise PeerError("wireguard_peer_invalid_description" if description else "wireguard_peer_invalid_name")
    value = value.strip()
    if (not description and not value) or any(
        unicodedata.category(char).startswith("C") or char in "\\/" for char in value
    ):
        raise PeerError("wireguard_peer_invalid_description" if description else "wireguard_peer_invalid_name")
    if not description and value in {".", ".."}:
        raise PeerError("wireguard_peer_invalid_name")
    return value


def _path(name: str) -> Path:
    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) is None:
        raise PeerError("wireguard_configuration_invalid")
    return wireguard._configuration_path(name)


def _read(path: Path) -> str:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        facts = os.fstat(descriptor)
        if (not stat.S_ISREG(facts.st_mode) or facts.st_nlink != 1
            or facts.st_uid != os.geteuid() or facts.st_mode & 0o077
            or facts.st_size > 65536):
            raise PeerError("wireguard_configuration_invalid")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as source:
            return source.read(65537)
    except (OSError, UnicodeError) as error:
        raise PeerError("wireguard_configuration_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sections(content: str) -> tuple[str, list[dict[str, str]]]:
    matches = list(PEER_SECTION.finditer(content))
    if not matches:
        if "[Interface]" not in content:
            raise PeerError("wireguard_configuration_invalid")
        return content, []
    prefix = content[:matches[0].start()]
    peers = []
    for index, match in enumerate(matches):
        block = content[match.end(): matches[index + 1].start() if index + 1 < len(matches) else None]
        values: dict[str, str] = {}
        for raw in block.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise PeerError("wireguard_configuration_invalid")
            key, value = (part.strip() for part in line.split("=", 1))
            if key in values or key not in {"PublicKey", "AllowedIPs", "PersistentKeepalive"}:
                raise PeerError("wireguard_configuration_invalid")
            values[key] = value
        if not all(key in values for key in ("PublicKey", "AllowedIPs")):
            raise PeerError("wireguard_configuration_invalid")
        peers.append(values)
    return prefix, peers


def _server(content: str) -> tuple[str, list[dict[str, str]], ipaddress.IPv4Interface, str]:
    prefix, peers = _sections(content)
    address = wireguard._value(prefix, "Address", section="Interface")
    private = wireguard._value(prefix, "PrivateKey", section="Interface")
    if not address or not private:
        raise PeerError("wireguard_configuration_invalid")
    try:
        interface = ipaddress.IPv4Interface(address)
        if interface.network.prefixlen > 31:
            raise ValueError
        addresses = [ipaddress.IPv4Network(p["AllowedIPs"], strict=True) for p in peers]
        if any(item.prefixlen != 32 or item.network_address not in interface.network
               or not _assignable(interface, item.network_address) for item in addresses):
            raise ValueError
        if len(set(addresses)) != len(addresses) or len({p["PublicKey"] for p in peers}) != len(peers):
            raise ValueError
    except ValueError as error:
        raise PeerError("wireguard_configuration_invalid") from error
    return prefix, peers, interface, private


def _assignable(server: ipaddress.IPv4Interface, candidate: ipaddress.IPv4Address) -> bool:
    network = server.network
    return (candidate in network and candidate != server.ip and
            (network.prefixlen >= 31 or candidate not in {
                network.network_address, network.broadcast_address,
            }))


def _render(prefix: str, peers: list[dict[str, str]]) -> str:
    result = prefix.rstrip() + "\n"
    for peer in peers:
        result += (
            "\n[Peer]\n"
            f"PublicKey = {peer['PublicKey']}\n"
            f"AllowedIPs = {peer['AllowedIPs']}\n"
            f"PersistentKeepalive = {peer.get('PersistentKeepalive', '25')}\n"
        )
    return result


def _rows(connection: sqlite3.Connection) -> list[dict]:
    connection.row_factory = sqlite3.Row
    return [dict(row) for row in connection.execute(
        f"SELECT {', '.join(PEER_COLUMNS)} FROM wireguard_peers ORDER BY created_at, peer_id"
    )]


def _profile(connection: sqlite3.Connection) -> dict | None:
    connection.row_factory = sqlite3.Row
    row = connection.execute("SELECT * FROM wireguard_ingress_profile WHERE singleton=1").fetchone()
    return dict(row) if row else None


def _validate_profile(profile: dict | None) -> dict:
    if profile is None:
        raise PeerError("wireguard_configuration_invalid")
    try:
        endpoint = profile["endpoint"]
        host, separator, port = endpoint.rpartition(":")
        if not separator or not 1 <= int(port) <= 65535:
            raise ValueError
        wireguard._validated_endpoint(host)
        wireguard._validated_dns_address(profile["dns"])
        parts = [part.strip() for part in profile["allowed_ips"].split(",")]
        if not parts or any(not part for part in parts):
            raise ValueError
        for part in parts:
            ipaddress.ip_network(part, strict=True)
        for key in ("client_keepalive", "server_keepalive"):
            if type(profile[key]) is not int or not 0 <= profile[key] <= 65535:
                raise ValueError
    except (KeyError, TypeError, ValueError) as error:
        raise PeerError("wireguard_configuration_invalid") from error
    return profile


def list_peers() -> list[dict]:
    with sqlite3.connect(core.DB) as connection:
        return _rows(connection)


def get_peer(peer_id: str) -> dict:
    if IDENTIFIER.fullmatch(peer_id) is None:
        raise PeerError("wireguard_peer_not_found")
    with sqlite3.connect(core.DB) as connection:
        return _get(connection, peer_id)


def _get(connection: sqlite3.Connection, peer_id: str) -> dict:
    row = next((row for row in _rows(connection) if row["peer_id"] == peer_id), None)
    if row is None:
        raise PeerError("wireguard_peer_not_found")
    return row


def public_peer(row: dict) -> dict:
    return {key: row[key] for key in (
        "peer_id", "name", "description", "public_key", "tunnel_ip", "status",
        "created_at", "updated_at", "revoked_at",
    )}


async def _validate_state(connection: sqlite3.Connection, interface: str) -> tuple[str, list[dict[str, str]], ipaddress.IPv4Interface, list[dict]]:
    server_content = _read(_path(interface))
    prefix, server_peers, address, server_private = _server(server_content)
    rows = _rows(connection)
    profile = _validate_profile(_profile(connection))
    active = [row for row in rows if row["status"] == "active"]
    if {p["PublicKey"]: p["AllowedIPs"] for p in server_peers} != {
        row["public_key"]: f"{row['tunnel_ip']}/32" for row in active
    }:
        raise PeerError("wireguard_configuration_invalid")
    server_public = await wireguard._public_key(server_private)
    if profile["server_public_key"] != server_public:
        raise PeerError("wireguard_configuration_invalid")
    for row in rows:
        if row["status"] not in {"active", "revoked"} or row["is_default"] not in {0, 1}:
            raise PeerError("wireguard_configuration_invalid")
        client = _read(_path(row["config_name"]))
        private = wireguard._value(client, "PrivateKey", section="Interface")
        remote_public = wireguard._value(client, "PublicKey", section="Peer")
        tunnel = wireguard._value(client, "Address", section="Interface")
        try:
            client_ip = ipaddress.IPv4Interface(tunnel or "")
            if client_ip.ip != ipaddress.IPv4Address(row["tunnel_ip"]) or client_ip.network.prefixlen != 32:
                raise ValueError
        except ValueError as error:
            raise PeerError("wireguard_configuration_invalid") from error
        if not private or await wireguard._public_key(private) != row["public_key"] or remote_public != server_public:
            raise PeerError("wireguard_configuration_invalid")
    return prefix, server_peers, address, rows


async def migrate_legacy(interface: str, client: str) -> bool:
    """Adopt exact v1 key material and bytes; reject partial/inconsistent state."""
    with state_lock(), sqlite3.connect(core.DB, timeout=5) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if _profile(connection) is not None:
            await _validate_state(connection, interface)
            return False
        server_path, client_path = _path(interface), _path(client)
        if not server_path.exists() and not client_path.exists():
            return False
        if not server_path.exists() or not client_path.exists():
            raise PeerError("wireguard_configuration_invalid")
        server_content, client_content = _read(server_path), _read(client_path)
        _, server_peers, server_address, server_private = _server(server_content)
        if len(server_peers) != 1:
            raise PeerError("wireguard_configuration_invalid")
        peer = server_peers[0]
        client_private = wireguard._value(client_content, "PrivateKey", section="Interface")
        remote_public = wireguard._value(client_content, "PublicKey", section="Peer")
        client_address = wireguard._value(client_content, "Address", section="Interface")
        try:
            tunnel = ipaddress.IPv4Interface(client_address or "")
            if (tunnel.network.prefixlen != 32 or tunnel.ip not in server_address.network
                or not _assignable(server_address, tunnel.ip)):
                raise ValueError
            if ipaddress.IPv4Network(peer["AllowedIPs"], strict=True) != ipaddress.IPv4Network(f"{tunnel.ip}/32"):
                raise ValueError
        except ValueError as error:
            raise PeerError("wireguard_configuration_invalid") from error
        if not client_private or await wireguard._public_key(client_private) != peer["PublicKey"] or remote_public != await wireguard._public_key(server_private):
            raise PeerError("wireguard_configuration_invalid")
        endpoint = wireguard._value(client_content, "Endpoint", section="Peer")
        dns = wireguard._value(client_content, "DNS", section="Interface")
        allowed = wireguard._value(client_content, "AllowedIPs", section="Peer")
        client_keepalive = wireguard._value(client_content, "PersistentKeepalive", section="Peer")
        try:
            if not all((endpoint, dns, allowed)):
                raise ValueError
            keepalive = int(client_keepalive or "25")
            server_keepalive = int(peer.get("PersistentKeepalive", "25"))
            if not 0 <= keepalive <= 65535 or not 0 <= server_keepalive <= 65535:
                raise ValueError
        except ValueError as error:
            raise PeerError("wireguard_configuration_invalid") from error
        timestamp = _now()
        profile = _validate_profile({
            "endpoint": endpoint, "dns": dns, "allowed_ips": allowed,
            "client_keepalive": keepalive, "server_keepalive": server_keepalive,
            "server_public_key": await wireguard._public_key(server_private),
        })
        connection.execute(
            """INSERT INTO wireguard_ingress_profile(singleton,endpoint,dns,allowed_ips,
               client_keepalive,server_keepalive,server_public_key) VALUES(1,?,?,?,?,?,?)""",
            (profile["endpoint"], profile["dns"], profile["allowed_ips"],
             profile["client_keepalive"], profile["server_keepalive"],
             profile["server_public_key"]),
        )
        connection.execute(
            """INSERT INTO wireguard_peers(peer_id,name,description,public_key,tunnel_ip,
               config_name,status,is_default,created_at,updated_at,revoked_at)
               VALUES(?,?,?,?,?,?,'active',1,?,?,NULL)""",
            (uuid.uuid4().hex, validate_name(client), "", peer["PublicKey"], str(tunnel.ip), client, timestamp, timestamp),
        )
        return True


def _allocate(address: ipaddress.IPv4Interface, rows: list[dict]) -> str:
    used = {ipaddress.IPv4Address(row["tunnel_ip"]) for row in rows}
    used.add(address.ip)
    for candidate in address.network.hosts():
        if candidate not in used:
            return str(candidate)
    raise PeerError("wireguard_address_pool_exhausted")


def _new_client(profile: dict, private_key: str, tunnel_ip: str) -> str:
    dns, remote = profile["dns"], profile["server_public_key"]
    endpoint, allowed, keepalive = (profile["endpoint"], profile["allowed_ips"],
                                    profile["client_keepalive"])
    if not all((dns, remote, endpoint, allowed)):
        raise PeerError("wireguard_configuration_invalid")
    return (
        f"[Interface]\nPrivateKey = {private_key}\nAddress = {tunnel_ip}/32\nDNS = {dns}\n"
        f"\n[Peer]\nPublicKey = {remote}\nEndpoint = {endpoint}\n"
        f"AllowedIPs = {allowed}\nPersistentKeepalive = {keepalive}\n"
    )


def filename(name: str) -> str:
    slug = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-")[:48] or "device"
    return f"exitlane-{slug}.conf"


async def _change(interface: str, sync: Sync, operation) -> dict:
    with state_lock(), sqlite3.connect(core.DB, timeout=5) as connection:
        connection.execute("BEGIN IMMEDIATE")
        prefix, server_peers, address, rows = await _validate_state(connection, interface)
        changes = await operation(connection, prefix, server_peers, address, rows)
        old_files: dict[Path, str | None] = changes.pop("_old_files")
        new_files: dict[Path, str | None] = changes.pop("_new_files")
        written = False
        try:
            for path, content in new_files.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    wireguard._atomic_write(path, content)
            written = True
            if _path(interface) in new_files:
                await sync(interface)
            connection.commit()
        except Exception as error:
            connection.rollback()
            if written or new_files:
                try:
                    for path, content in old_files.items():
                        wireguard._restore(path, content)
                    if _path(interface) in new_files:
                        await sync(interface)
                except Exception as rollback_error:
                    raise PeerError("wireguard_rollback_failed") from rollback_error
            if isinstance(error, PeerError):
                raise
            raise PeerError("wireguard_peer_mutation_failed") from error
        return changes


async def create(interface: str, name: str, description: str, sync: Sync) -> dict:
    name, description = validate_name(name), validate_name(description, description=True)

    async def operation(connection, prefix, server_peers, address, rows):
        from exitlane.lifecycle import MAX_FILES

        # DB, master key and server config also occupy backup inventory slots.
        if len(rows) >= MAX_FILES - 3:
            raise PeerError("wireguard_peer_limit_reached")
        tunnel_ip = _allocate(address, rows)
        private, public = await wireguard.keypair()
        if any(row["public_key"] == public for row in rows):
            raise PeerError("wireguard_peer_duplicate_key")
        peer_id = uuid.uuid4().hex
        config_name = f"peer-{peer_id}"
        profile = _profile(connection)
        config = _new_client(profile, private, tunnel_ip)
        now = _now()
        connection.execute(
            """INSERT INTO wireguard_peers(peer_id,name,description,public_key,tunnel_ip,
               config_name,status,is_default,created_at,updated_at,revoked_at)
               VALUES(?,?,?,?,?,?,'active',0,?,?,NULL)""",
            (peer_id, name, description, public, tunnel_ip, config_name, now, now),
        )
        server_path, client_path = _path(interface), _path(config_name)
        keepalive = str(profile["server_keepalive"])
        next_peers = [*server_peers, {"PublicKey": public, "AllowedIPs": f"{tunnel_ip}/32", "PersistentKeepalive": keepalive}]
        return {
            "peer": public_peer(_get(connection, peer_id)), "configuration": config,
            "filename": filename(name), "available": True,
            "_old_files": {server_path: _read(server_path), client_path: None},
            "_new_files": {server_path: _render(prefix, next_peers), client_path: config},
        }

    return await _change(interface, sync, operation)


async def update(interface: str, peer_id: str, name: str, description: str) -> dict:
    name, description = validate_name(name), validate_name(description, description=True)
    with state_lock(), sqlite3.connect(core.DB, timeout=5) as connection:
        connection.execute("BEGIN IMMEDIATE")
        await _validate_state(connection, interface)
        _get(connection, peer_id)
        connection.execute(
            "UPDATE wireguard_peers SET name=?,description=?,updated_at=? WHERE peer_id=?",
            (name, description, _now(), peer_id),
        )
        return public_peer(_get(connection, peer_id))


async def regenerate(interface: str, peer_id: str, sync: Sync) -> dict:
    async def operation(connection, prefix, server_peers, address, rows):
        row = _get(connection, peer_id)
        private, public = await wireguard.keypair()
        if any(item["public_key"] == public for item in rows):
            raise PeerError("wireguard_peer_duplicate_key")
        client_path, server_path = _path(row["config_name"]), _path(interface)
        profile = _profile(connection)
        config = _new_client(profile, private, row["tunnel_ip"])
        old_peer = next((peer for peer in server_peers if peer["PublicKey"] == row["public_key"]), None)
        keepalive = (old_peer or {}).get("PersistentKeepalive", str(profile["server_keepalive"]))
        replacement = {"PublicKey": public, "AllowedIPs": f"{row['tunnel_ip']}/32", "PersistentKeepalive": keepalive}
        next_peers = [replacement if peer["PublicKey"] == row["public_key"] else peer for peer in server_peers]
        if row["status"] == "revoked":
            next_peers.append(replacement)
        connection.execute(
            "UPDATE wireguard_peers SET public_key=?,status='active',updated_at=?,revoked_at=NULL WHERE peer_id=?",
            (public, _now(), peer_id),
        )
        return {
            "peer": public_peer(_get(connection, peer_id)), "configuration": config,
            "filename": filename(row["name"]), "available": True,
            "_old_files": {server_path: _read(server_path), client_path: _read(client_path)},
            "_new_files": {server_path: _render(prefix, next_peers), client_path: config},
        }

    return await _change(interface, sync, operation)


async def revoke(interface: str, peer_id: str, sync: Sync) -> dict:
    async def operation(connection, prefix, server_peers, address, rows):
        row = _get(connection, peer_id)
        if row["status"] == "revoked":
            raise PeerError("wireguard_peer_already_revoked")
        next_peers = [peer for peer in server_peers if peer["PublicKey"] != row["public_key"]]
        connection.execute(
            "UPDATE wireguard_peers SET status='revoked',updated_at=?,revoked_at=? WHERE peer_id=?",
            (timestamp := _now(), timestamp, peer_id),
        )
        server_path = _path(interface)
        return {
            "peer": public_peer(_get(connection, peer_id)),
            "_old_files": {server_path: _read(server_path)},
            "_new_files": {server_path: _render(prefix, next_peers)},
        }

    return await _change(interface, sync, operation)


async def delete(interface: str, peer_id: str) -> dict:
    with state_lock(), sqlite3.connect(core.DB, timeout=5) as connection:
        connection.execute("BEGIN IMMEDIATE")
        await _validate_state(connection, interface)
        row = _get(connection, peer_id)
        if row["status"] != "revoked":
            raise PeerError("wireguard_peer_must_revoke_first")
        path = _path(row["config_name"])
        original = _read(path)
        try:
            path.unlink()
            connection.execute("DELETE FROM wireguard_peers WHERE peer_id=?", (peer_id,))
            connection.commit()
        except Exception as error:
            connection.rollback()
            try:
                wireguard._restore(path, original)
            except Exception as rollback_error:
                raise PeerError("wireguard_rollback_failed") from rollback_error
            raise PeerError("wireguard_peer_mutation_failed") from error
        return public_peer(row)


async def configuration(interface: str, peer_id: str) -> dict:
    with sqlite3.connect(core.DB) as connection:
        await _validate_state(connection, interface)
        row = _get(connection, peer_id)
        if row["status"] != "active":
            raise PeerError("wireguard_peer_revoked")
        return {
            "available": True, "configuration": _read(_path(row["config_name"])),
            "filename": filename(row["name"]), "peer": public_peer(row),
        }
