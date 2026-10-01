"""Private durable container state; never enables full container composition.

A staged empty layout is published by the recovery coordinator, not by this module.
Network reconstruction requires an independently observed protection boundary.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from exitlane import core, lifecycle
from exitlane.providers.mullvad import Mullvad, Relay, normalize_account_number
from exitlane.providers.pia import Pia, validate_credentials
from exitlane.providers.proton import Proton
from exitlane.providers.proton_profile import parse_profile
from exitlane.providers.wireguard_keys import _public_key_for_private
from exitlane.services import auth_security, provider_secrets
from exitlane.services.provider_wireguard import EgressConfig, ProviderWireGuard

PROVIDERS = ("mullvad", "pia", "proton")
LAYOUT_VERSION = 1
SCHEMA_MIN = SCHEMA_MAX = 1
MAX_STATE_BYTES = 128 * 1024 * 1024
ROOT_UID = 0


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


@dataclass(frozen=True)
class ProviderIntent:
    provider_id: str
    status: str
    generation: str | None
    config: EgressConfig | None = field(default=None, repr=False)

    @property
    def recovery_required(self):
        return self.status == "recovery_required"


@dataclass(frozen=True)
class StateInventory:
    schema: int
    selected_provider: str | None
    intents: tuple[ProviderIntent, ...]

    @property
    def recovery_required(self):
        return any(item.recovery_required for item in self.intents)


def _facts(path: Path, *, directory: bool = False) -> os.stat_result:
    require(path.is_absolute() and ".." not in path.parts, "container_state_component_unsafe")
    for parent in path.parents:
        require(not parent.is_symlink(), "container_state_component_unsafe")
    try:
        value = path.lstat()
    except OSError:
        raise ContainerStateError("container_state_component_missing") from None
    require(value.st_uid == ROOT_UID, "container_state_owner_invalid")
    require(
        stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode),
        "container_state_component_unsafe",
    )
    require(value.st_mode & 0o077 == 0, "container_state_permissions_invalid")
    if not directory:
        require(
            value.st_nlink == 1 and value.st_size <= MAX_STATE_BYTES,
            "container_state_component_unsafe",
        )
    return value


def _read(path: Path, maximum: int) -> bytes:
    _facts(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            facts = os.fstat(source.fileno())
            require(
                stat.S_ISREG(facts.st_mode)
                and facts.st_nlink == 1
                and facts.st_uid == ROOT_UID
                and facts.st_mode & 0o077 == 0
                and facts.st_size <= maximum
            )
            content = source.read(maximum + 1)
        require(len(content) <= maximum)
        return content
    except OSError:
        raise ContainerStateError("container_state_component_unsafe") from None


def _validate_profile(profile: dict) -> None:
    item = profile["config"]
    # Reuse the import parser's complete grammar, never feed imported hooks to wg-quick.
    extra = f"PresharedKey = {item['preshared_key']}\n" if item.get("preshared_key") else ""
    parse_profile(
        f"[Interface]\nPrivateKey = {item['private_key']}\nAddress = {item['address']}\n"
        f"DNS = {item['dns_address']}\nMTU = {item['mtu']}\n[Peer]\n"
        f"PublicKey = {item['peer_public_key']}\n{extra}"
        f"Endpoint = {item['endpoint_host']}:{item['endpoint_port']}\nAllowedIPs = 0.0.0.0/0\n"
    )


def build_manifest(key: bytes) -> dict:
    require(type(key) is bytes and len(key) == 32, "container_state_key_invalid")
    return {
        "layout_version": LAYOUT_VERSION,
        "schema_min": SCHEMA_MIN,
        "schema_max": SCHEMA_MAX,
        "master_key_sha256": hashlib.sha256(key).hexdigest(),
    }


class ContainerState:
    def __init__(self, layout: ContainerLayout):
        self.layout = layout

    def stage_empty(self, staging: Path) -> ContainerLayout:
        layout = ContainerLayout(staging)
        require(os.geteuid() == ROOT_UID, "root_required")
        for parent in layout.root.parents:
            require(not parent.is_symlink(), "container_state_component_unsafe")
        require(
            not layout.root.exists() and not layout.root.is_symlink(),
            "container_state_staging_not_empty",
        )
        layout.root.mkdir(mode=0o700)
        for directory in (
            layout.config,
            layout.state,
            layout.wireguard,
            layout.provider_egress,
            layout.recovery,
            layout.backups,
        ):
            directory.mkdir(mode=0o700)
        descriptor = os.open(layout.master_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(secrets.token_bytes(32))
            destination.flush()
            os.fsync(destination.fileno())
        core.init_database(layout.database)
        layout.database.chmod(0o600)
        self.write_manifest(layout)
        ContainerState(layout).validate()
        return layout

    def write_manifest(self, layout: ContainerLayout | None = None) -> None:
        layout = layout or self.layout
        _facts(layout.root, directory=True)
        metadata = build_manifest(_read(layout.master_key, 32))
        if layout.manifest.exists() or layout.manifest.is_symlink():
            _facts(layout.manifest)
        descriptor, temporary = tempfile.mkstemp(prefix=".layout-", dir=layout.root)
        temporary = Path(temporary)
        try:
            with os.fdopen(descriptor, "w") as destination:
                os.fchmod(destination.fileno(), 0o600)
                json.dump(metadata, destination, sort_keys=True)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, layout.manifest)
            directory = os.open(layout.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def validate(self) -> StateInventory:
        layout = self.layout
        for directory in (
            layout.root,
            layout.config,
            layout.state,
            layout.wireguard,
            layout.provider_egress,
            layout.recovery,
            layout.backups,
        ):
            _facts(directory, directory=True)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(layout.database) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                _facts(sidecar)
        for path in layout.provider_egress.iterdir():
            require(path.name in {f"wg-{provider}.conf" for provider in PROVIDERS})
            _facts(path)
        return self.validate_pair(
            layout.database, layout.master_key, layout.wireguard, layout.manifest
        )

    def validate_pair(
        self, database: Path, master_key: Path, wireguard: Path, manifest: Path | None = None
    ) -> StateInventory:
        try:
            _facts(database)
            key = _read(master_key, 32)
            require(len(key) == 32, "container_state_key_invalid")
            _facts(wireguard, directory=True)
            if manifest is not None:
                metadata = json.loads(_read(manifest, 4096))
                require(
                    isinstance(metadata, dict)
                    and all(
                        type(metadata.get(name)) is int
                        for name in ("layout_version", "schema_min", "schema_max")
                    )
                    and metadata == build_manifest(key),
                    "container_state_manifest_invalid",
                )
            try:
                lifecycle._inspect_database(database)
            except lifecycle.LifecycleError as error:
                if (
                    getattr(error.__context__, "sqlite_errorcode", None)
                    == sqlite3.SQLITE_READONLY_ROLLBACK
                ):
                    raise ContainerStateError("container_state_sqlite_recovery_required") from None
                raise
            entries = tuple(wireguard.iterdir())
            require(len(entries) <= lifecycle.MAX_FILES, "container_state_inventory_too_large")
            for path in entries:
                facts = _facts(path)
                require(
                    facts.st_size <= lifecycle.WIREGUARD_CONFIG_MAX_BYTES,
                    "container_state_component_unsafe",
                )
            lifecycle._validate_restored_wireguard(wireguard)
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                schema = connection.execute(
                    "SELECT version FROM schema_version WHERE singleton=1"
                ).fetchone()[0]
                require(
                    type(schema) is int and SCHEMA_MIN <= schema <= SCHEMA_MAX,
                    "container_state_schema_incompatible",
                )
                for query in (
                    "SELECT encrypted_totp_secret FROM users WHERE encrypted_totp_secret IS NOT NULL",
                    "SELECT encrypted_secret FROM mfa_enrollments",
                ):
                    for row in connection.execute(query):
                        auth_security.decrypt_secret_with_key(bytes(row[0]), key)
                states = {}
                for provider_id, encrypted in connection.execute(
                    "SELECT provider_id,encrypted_payload FROM provider_secrets"
                ):
                    require(provider_id in PROVIDERS, "container_state_provider_unavailable")
                    states[provider_id] = provider_secrets.decode(
                        provider_id, bytes(encrypted), key
                    )
                selected = connection.execute(
                    "SELECT value FROM settings WHERE key='vpn.provider_id'"
                ).fetchone()
                selected = json.loads(selected[0]) if selected else None
                require(
                    selected is None or selected in PROVIDERS,
                    "container_state_provider_unavailable",
                )

                def setting(name, default=None):
                    row = connection.execute(
                        "SELECT value FROM settings WHERE key=?", (name,)
                    ).fetchone()
                    return json.loads(row[0]) if row else default

                configured = setting("wireguard_configured", False)
                require(type(configured) is bool)
                if configured:
                    from exitlane.container_runtime import IngressConfig

                    interface = setting(
                        "wireguard_interface", setting("wireguard.interface", "wg0")
                    )
                    require(
                        isinstance(interface, str)
                        and re.fullmatch(r"[A-Za-z0-9-]{1,15}", interface) is not None
                    )
                    ingress_path = wireguard / f"{interface}.conf"
                    _facts(ingress_path)
                    ingress = IngressConfig.from_file(ingress_path)
                    subnet = setting("wireguard_subnet")
                    require(
                        isinstance(subnet, str)
                        and str(ipaddress.IPv4Interface(ingress.address).network) == subnet,
                        "container_state_ingress_inconsistent",
                    )
            intents = []
            for provider_id, state in states.items():
                require(type(state.get("version")) is int and state["version"] == 1)
                if provider_id == "mullvad":
                    require(
                        isinstance(state.get("account_number"), str)
                        and normalize_account_number(state["account_number"])
                        == state["account_number"]
                    )
                    require(
                        _public_key_for_private(state.get("private_key")) == state.get("public_key")
                        and state.get("public_key") is not None
                    )
                if provider_id == "pia":
                    require(validate_credentials(state.get("username"), state.get("password")))
                if provider_id == "proton":
                    profiles = Proton._profiles(state)
                    require(len(profiles) <= 32)
                    for profile in profiles.values():
                        _validate_profile(profile)
                for status in ("active", "pending"):
                    generation = state.get(status)
                    if generation is None:
                        continue
                    require(isinstance(generation, dict))
                    if "recovery" in generation:
                        require(
                            status == "pending"
                            and set(generation) == {"recovery"}
                            and generation["recovery"] == "failed_connect"
                        )
                        intents.append(ProviderIntent(provider_id, "recovery_required", None))
                        continue
                    require(
                        isinstance(generation.get("generation"), str)
                        and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", generation["generation"])
                        is not None
                    )
                    if provider_id == "mullvad":
                        config = Mullvad._config(
                            state, Relay(**generation["relay"]), generation["generation"]
                        )
                    elif provider_id == "pia":
                        config = Pia._config(generation)
                    else:
                        config = Proton._config(profiles[generation["profile_id"]], generation)
                    require(
                        isinstance(config.generation, str)
                        and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", config.generation) is not None
                    )
                    config.validated()
                    if provider_id in {"pia", "proton"}:
                        require(generation.get("address") == config.address)
                    intents.append(ProviderIntent(provider_id, status, config.generation, config))
            return StateInventory(schema, selected, tuple(intents))
        except ContainerStateError:
            raise
        except Exception:  # noqa: BLE001 - sanitize every untrusted state/parser failure
            # Ciphertexts, provider credentials and config repr never enter an error.
            raise ContainerStateError("container_state_invalid") from None

    def recover_database(self, *, guard_observed: Callable[[], bool]) -> StateInventory:
        """SQLite owns rollback of a private validated pair, never manual deletion.

        The supervisor must hold its exclusive lease and quiesce writers first.
        A successful guard readback is mandatory before permitting SQLite's own
        writable hot-journal recovery. mode=rw cannot create a missing database.
        """
        try:
            return self.validate()
        except ContainerStateError as error:
            if error.code != "container_state_sqlite_recovery_required":
                raise
        require(guard_observed() is True, "container_state_guard_unproven")
        try:
            with sqlite3.connect(f"file:{self.layout.database}?mode=rw", uri=True) as connection:
                require(connection.execute("PRAGMA integrity_check").fetchone() == ("ok",))
        except sqlite3.DatabaseError:
            raise ContainerStateError("container_state_invalid") from None
        require(guard_observed() is True, "container_state_guard_unproven")
        return self.validate()

    def rebuild_projections(
        self,
        inventory: StateInventory,
        root: Path | None = None,
        *,
        guard_observed: Callable[[], bool],
    ) -> None:
        require(guard_observed() is True, "container_state_guard_unproven")
        root = root or self.layout.provider_egress
        _facts(root, directory=True)
        require(not inventory.recovery_required, "container_state_recovery_required")
        writer = ProviderWireGuard(root=root)
        # Pending wins only as a blocked projection. This never commits or starts it.
        configs = {item.provider_id: item.config for item in inventory.intents if item.config}
        for provider_id, config in configs.items():
            require(guard_observed() is True, "container_state_guard_unproven")
            writer._atomic_write(root / f"wg-{provider_id}.conf", writer.render(config))
