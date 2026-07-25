from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import stat
import struct
import tarfile
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from exitlane import __version__, core
from exitlane.config import CONFIG_DIR

MAGIC = b"EXITLANE-BACKUP\x00"
FORMAT_VERSION = 1
DATABASE_SCHEMA_VERSION = 1
MAX_BACKUP_BYTES = 512 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_FILES = 256
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 384 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
LOCK_PATH = Path(os.getenv("EXITLANE_LIFECYCLE_LOCK", "/run/lock/exitlane-lifecycle.lock"))


class LifecycleError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class BackupInfo:
    backup_id: str
    created_at: str
    exitlane_version: str
    database_schema_version: int
    format_version: int
    files: tuple[dict[str, object], ...]


def _root_only(effective_user_id: int | None) -> None:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        raise LifecycleError("root_required")


def _safe_regular_file(path: Path, *, required: bool = True) -> bool:
    try:
        details = path.lstat()
    except FileNotFoundError:
        if required:
            raise LifecycleError("required_component_missing") from None
        return False
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise LifecycleError("unsafe_component")
    return True


@contextmanager
def lifecycle_lock(path: Path = LOCK_PATH) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LifecycleError("lifecycle_busy") from None
        yield
    finally:
        os.close(descriptor)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise LifecycleError("passphrase_required")
    return Scrypt(salt=salt, length=KEY_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        passphrase.encode("utf-8")
    )


def _database_snapshot(source: Path, destination: Path) -> None:
    _safe_regular_file(source)
    with (
        sqlite3.connect(f"file:{source}?mode=ro", uri=True) as source_connection,
        sqlite3.connect(destination) as destination_connection,
    ):
        source_connection.backup(destination_connection)
    os.chmod(destination, 0o600)


def _inventory_entry(
    logical_type: str, archive_name: str, path: Path, mode: int
) -> dict[str, object]:
    content = path.read_bytes()
    return {
        "type": logical_type,
        "name": archive_name,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "mode": mode,
    }


def _collect_components(staging: Path) -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    database = staging / "database.sqlite3"
    _database_snapshot(core.DB, database)
    components.append(_inventory_entry("database", database.name, database, 0o600))

    master_key = CONFIG_DIR / "secret.key"
    _safe_regular_file(master_key)
    key_copy = staging / "master-key"
    shutil.copyfile(master_key, key_copy, follow_symlinks=False)
    os.chmod(key_copy, 0o600)
    components.append(_inventory_entry("master_key", key_copy.name, key_copy, 0o600))

    if core.WG_DIR.exists():
        if core.WG_DIR.is_symlink() or not core.WG_DIR.is_dir():
            raise LifecycleError("unsafe_component")
        for index, source in enumerate(sorted(core.WG_DIR.iterdir())):
            if not _safe_regular_file(source, required=False):
                continue
            if index >= MAX_FILES - 2:
                raise LifecycleError("too_many_files")
            destination = staging / f"wireguard-{index:03d}.conf"
            shutil.copyfile(source, destination, follow_symlinks=False)
            os.chmod(destination, 0o600)
            entry = _inventory_entry("wireguard_config", destination.name, destination, 0o600)
            entry["original_name"] = source.name
            components.append(entry)
    return components


def _make_payload(staging: Path, manifest: dict[str, object]) -> bytes:
    manifest_path = staging / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    os.chmod(manifest_path, 0o600)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(staging.iterdir()):
            archive.add(path, arcname=path.name, recursive=False, filter=_tar_filter)
    return output.getvalue()


def _tar_filter(member: tarfile.TarInfo) -> tarfile.TarInfo:
    member.uid = member.gid = 0
    member.uname = member.gname = "root"
    member.mode = 0o600
    member.mtime = 0
    member.pax_headers = {}
    return member


def create_backup(
    destination: Path,
    passphrase: str,
    *,
    effective_user_id: int | None = None,
    lock_path: Path = LOCK_PATH,
) -> BackupInfo:
    _root_only(effective_user_id)
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists() and destination.is_symlink():
        raise LifecycleError("unsafe_destination")
    with (
        lifecycle_lock(lock_path),
        tempfile.TemporaryDirectory(
            prefix=".exitlane-backup-", dir=destination.parent
        ) as temporary,
    ):
        staging = Path(temporary)
        os.chmod(staging, 0o700)
        files = _collect_components(staging)
        created_at = datetime.now(UTC).isoformat()
        backup_id = str(uuid.uuid4())
        manifest: dict[str, object] = {
            "format": "exitlane-appliance-backup",
            "format_version": FORMAT_VERSION,
            "backup_id": backup_id,
            "created_at": created_at,
            "exitlane_version": __version__,
            "database_schema_version": core.database_schema_version(),
            "files": files,
        }
        payload = _make_payload(staging, manifest)
        salt, nonce = secrets.token_bytes(SALT_LENGTH), secrets.token_bytes(NONCE_LENGTH)
        header = {
            "format": "exitlane-appliance-backup",
            "format_version": FORMAT_VERSION,
            "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
            "cipher": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        associated_data = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
        ciphertext = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, payload, associated_data)
        temporary_output = staging.parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
        try:
            descriptor = os.open(
                temporary_output,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(associated_data)
                handle.write(ciphertext)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_output, destination)
            os.chmod(destination, 0o600)
        finally:
            temporary_output.unlink(missing_ok=True)
    return _backup_info(manifest)


def _read_envelope(source: Path) -> tuple[dict[str, object], bytes, bytes]:
    details = source.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise LifecycleError("unsafe_backup_file")
    if details.st_size > MAX_BACKUP_BYTES:
        raise LifecycleError("backup_too_large")
    with source.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            raise LifecycleError("invalid_magic")
        length_bytes = handle.read(4)
        if len(length_bytes) != 4:
            raise LifecycleError("invalid_header")
        header_length = struct.unpack(">I", length_bytes)[0]
        if header_length < 2 or header_length > MAX_HEADER_BYTES:
            raise LifecycleError("invalid_header")
        header_bytes = handle.read(header_length)
        if len(header_bytes) != header_length:
            raise LifecycleError("invalid_header")
        ciphertext = handle.read(MAX_BACKUP_BYTES + 1)
    try:
        header = json.loads(header_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LifecycleError("invalid_header") from None
    if (
        not isinstance(header, dict)
        or header.get("format") != "exitlane-appliance-backup"
        or header.get("format_version") != FORMAT_VERSION
        or header.get("cipher") != "AES-256-GCM"
        or header.get("kdf") != {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    ):
        raise LifecycleError("unsupported_backup_format")
    associated_data = MAGIC + length_bytes + header_bytes
    return header, associated_data, ciphertext


def _decrypt(source: Path, passphrase: str) -> bytes:
    header, associated_data, ciphertext = _read_envelope(source)
    try:
        salt = base64.b64decode(str(header["salt"]), validate=True)
        nonce = base64.b64decode(str(header["nonce"]), validate=True)
        if len(salt) != SALT_LENGTH or len(nonce) != NONCE_LENGTH:
            raise ValueError
        return AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, ciphertext, associated_data)
    except (InvalidTag, KeyError, TypeError, ValueError):
        raise LifecycleError("authentication_failed") from None


def _validated_payload(payload: bytes, staging: Path) -> dict[str, object]:
    if len(payload) > MAX_TOTAL_BYTES:
        raise LifecycleError("payload_too_large")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")  # noqa: SIM115
    except tarfile.TarError:
        raise LifecycleError("invalid_archive") from None
    seen: set[str] = set()
    total = 0
    members = archive.getmembers()
    if not members or len(members) > MAX_FILES + 1:
        raise LifecycleError("invalid_file_count")
    for member in members:
        normalized = PurePosixPath(member.name)
        if (
            member.name in seen
            or normalized.is_absolute()
            or ".." in normalized.parts
            or len(normalized.parts) != 1
            or not member.isfile()
        ):
            raise LifecycleError("unsafe_archive_entry")
        seen.add(member.name)
        if member.size < 0 or member.size > MAX_FILE_BYTES:
            raise LifecycleError("file_too_large")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            raise LifecycleError("payload_too_large")
    compressed_size = max(len(payload), 1)
    if total > compressed_size * MAX_COMPRESSION_RATIO:
        raise LifecycleError("compression_ratio_exceeded")
    if "manifest.json" not in seen:
        raise LifecycleError("manifest_missing")
    for member in members:
        source = archive.extractfile(member)
        if source is None:
            raise LifecycleError("invalid_archive")
        destination = staging / member.name
        with destination.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        os.chmod(destination, 0o600)
    try:
        manifest = json.loads((staging / "manifest.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LifecycleError("invalid_manifest") from None
    _validate_manifest(manifest, staging, seen)
    return manifest


def _validate_manifest(manifest: object, staging: Path, seen: set[str]) -> None:
    if not isinstance(manifest, dict):
        raise LifecycleError("invalid_manifest")
    if (
        manifest.get("format") != "exitlane-appliance-backup"
        or manifest.get("format_version") != FORMAT_VERSION
        or not isinstance(manifest.get("backup_id"), str)
        or not isinstance(manifest.get("created_at"), str)
        or not isinstance(manifest.get("exitlane_version"), str)
        or not isinstance(manifest.get("database_schema_version"), int)
        or not isinstance(manifest.get("files"), list)
    ):
        raise LifecycleError("invalid_manifest")
    entries = manifest["files"]
    allowed_types = {"database", "master_key", "wireguard_config"}
    names: set[str] = set()
    types: list[str] = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or entry.get("type") not in allowed_types
            or not isinstance(entry.get("name"), str)
            or entry["name"] in names
            or entry["name"] not in seen
            or not isinstance(entry.get("size"), int)
            or not isinstance(entry.get("sha256"), str)
            or entry.get("mode") != 0o600
        ):
            raise LifecycleError("invalid_manifest")
        names.add(entry["name"])
        types.append(entry["type"])
        content = (staging / entry["name"]).read_bytes()
        if len(content) != entry["size"] or not secrets.compare_digest(
            hashlib.sha256(content).hexdigest(), entry["sha256"]
        ):
            raise LifecycleError("checksum_mismatch")
    if set(seen) != names | {"manifest.json"}:
        raise LifecycleError("unexpected_file")
    if types.count("database") != 1 or types.count("master_key") != 1:
        raise LifecycleError("required_component_missing")
    if manifest["database_schema_version"] > DATABASE_SCHEMA_VERSION:
        raise LifecycleError("future_database_schema")


def _inspect_database(path: Path) -> None:
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            schema = connection.execute(
                "SELECT version FROM schema_version WHERE singleton=1"
            ).fetchone()
    except sqlite3.DatabaseError:
        raise LifecycleError("invalid_database") from None
    if result != ("ok",) or schema is None or schema[0] > DATABASE_SCHEMA_VERSION:
        raise LifecycleError("invalid_database")


def inspect_backup(
    source: Path,
    passphrase: str,
    *,
    effective_user_id: int | None = None,
) -> BackupInfo:
    _root_only(effective_user_id)
    payload = _decrypt(source, passphrase)
    with tempfile.TemporaryDirectory(prefix="exitlane-inspect-") as temporary:
        os.chmod(temporary, 0o700)
        staging = Path(temporary)
        manifest = _validated_payload(payload, staging)
        database_name = next(
            entry["name"] for entry in manifest["files"] if entry["type"] == "database"
        )
        _inspect_database(staging / database_name)
    return _backup_info(manifest)


def _backup_info(manifest: dict[str, object]) -> BackupInfo:
    return BackupInfo(
        backup_id=str(manifest["backup_id"]),
        created_at=str(manifest["created_at"]),
        exitlane_version=str(manifest["exitlane_version"]),
        database_schema_version=int(manifest["database_schema_version"]),
        format_version=int(manifest["format_version"]),
        files=tuple(manifest["files"]),
    )


def restore_backup(
    source: Path,
    passphrase: str,
    *,
    confirmation: str,
    effective_user_id: int | None = None,
    lock_path: Path = LOCK_PATH,
    service_action: Callable[[str], None] | None = None,
) -> BackupInfo:
    _root_only(effective_user_id)
    if confirmation != "RESTORE EXITLANE":
        raise LifecycleError("confirmation_required")
    payload = _decrypt(source, passphrase)
    with (
        lifecycle_lock(lock_path),
        tempfile.TemporaryDirectory(prefix=".exitlane-restore-", dir=core.DATA.parent) as temporary,
    ):
        os.chmod(temporary, 0o700)
        staging = Path(temporary)
        manifest = _validated_payload(payload, staging)
        entries = manifest["files"]
        database = next(staging / entry["name"] for entry in entries if entry["type"] == "database")
        master_key = next(
            staging / entry["name"] for entry in entries if entry["type"] == "master_key"
        )
        _inspect_database(database)
        recovery_dir = Path(tempfile.mkdtemp(prefix=".exitlane-prerestore-", dir=core.DATA.parent))
        os.chmod(recovery_dir, 0o700)
        try:
            _database_snapshot(core.DB, recovery_dir / "database.sqlite3")
            shutil.copyfile(CONFIG_DIR / "secret.key", recovery_dir / "master-key")
            if service_action:
                service_action("stop")
            os.replace(database, core.DB)
            os.chmod(core.DB, 0o600)
            os.replace(master_key, CONFIG_DIR / "secret.key")
            os.chmod(CONFIG_DIR / "secret.key", 0o600)
            core.WG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            for existing in core.WG_DIR.iterdir():
                if existing.is_file() and not existing.is_symlink():
                    existing.unlink()
            for entry in entries:
                if entry["type"] == "wireguard_config":
                    original_name = entry.get("original_name")
                    if (
                        not isinstance(original_name, str)
                        or PurePosixPath(original_name).name != original_name
                    ):
                        raise LifecycleError("invalid_manifest")
                    os.replace(staging / entry["name"], core.WG_DIR / original_name)
                    os.chmod(core.WG_DIR / original_name, 0o600)
            with sqlite3.connect(core.DB) as connection:
                connection.execute("DELETE FROM sessions")
                connection.execute("DELETE FROM mfa_challenges")
                connection.execute("DELETE FROM mfa_enrollments")
            if service_action:
                service_action("start")
            _inspect_database(core.DB)
        except Exception:
            os.replace(recovery_dir / "database.sqlite3", core.DB)
            os.replace(recovery_dir / "master-key", CONFIG_DIR / "secret.key")
            if service_action:
                service_action("start")
            raise
        finally:
            shutil.rmtree(recovery_dir, ignore_errors=True)
    return _backup_info(manifest)
