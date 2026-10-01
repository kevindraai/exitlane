"""Container durable recovery. Every public method requires the caller's exclusive lease.

Hooks must prove guards before stopping writers and must stop/reap all writers before
returning from quiesce. No method grants a second lease or runs background file writers.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import sqlite3
import stat
import uuid
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from exitlane import __version__, lifecycle
from exitlane.container_state import (
    ContainerLayout,
    ContainerState,
    ContainerStateError,
    StateInventory,
)


class ContainerRecoveryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class IngressIdentity:
    interface: str
    subnet: str

    def __post_init__(self):
        try:
            if (
                not isinstance(self.interface, str)
                or lifecycle.killswitch.INTERFACE_RE.fullmatch(self.interface) is None
                or not isinstance(self.subnet, str)
            ):
                raise ValueError
            network = ipaddress.ip_network(self.subnet, strict=True)
            if network.version != 4 or network.prefixlen > 30 or str(network) != self.subnet:
                raise ValueError
        except (TypeError, ValueError):
            raise ContainerRecoveryError("recovery_ingress_invalid") from None


@dataclass(frozen=True)
class RecoveryHooks:
    guard: Callable[[tuple[IngressIdentity, ...]], Awaitable[None]]
    quiesce: Callable[[], Awaitable[None]]
    reset_egress: Callable[[], Awaitable[None]]
    reconcile: Callable[[StateInventory], Awaitable[None]]
    health: Callable[[], Awaitable[bool]]
    reopen: Callable[[], Awaitable[None]]


PHASES = {
    "init_preparing",
    "init_ready",
    "prepared",
    "snapshot_ready",
    "publishing",
    "installed",
    "validated",
    "committed",
    "rollback_required",
}


def _private(path: Path, *, directory: bool = False) -> None:
    try:
        value = path.lstat()
    except OSError:
        raise ContainerRecoveryError("recovery_component_missing") from None
    if (
        value.st_uid != os.geteuid()
        or value.st_mode & 0o077
        or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        or (not directory and (value.st_nlink != 1 or value.st_size > lifecycle.MAX_FILE_BYTES))
    ):
        raise ContainerRecoveryError("recovery_component_unsafe")


def _sync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_tree(root: Path) -> None:
    _private(root, directory=True)
    for path in root.iterdir():
        if path.is_dir() and not path.is_symlink():
            _sync_tree(path)
        else:
            _private(path)
            _sync(path)
    _sync(root)


def _copy_file(source: Path, destination: Path) -> None:
    _private(source)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source_handle:
        if not stat.S_ISREG(os.fstat(source_handle.fileno()).st_mode):
            raise ContainerRecoveryError("recovery_component_unsafe")
        descriptor = os.open(
            destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            shutil.copyfileobj(source_handle, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())


def _copy_directory(source: Path, destination: Path) -> None:
    _private(source, directory=True)
    destination.mkdir(mode=0o700)
    entries = sorted(source.iterdir())
    if len(entries) > lifecycle.MAX_FILES:
        raise ContainerRecoveryError("recovery_inventory_too_large")
    for entry in entries:
        _copy_file(entry, destination / entry.name)
    _sync(destination)


def ingress_identities(database: Path) -> tuple[IngressIdentity, ...]:
    """Read bounded canonical ingress facts; no fabricated interface on a new volume."""
    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            settings = {
                key: json.loads(value)
                for key, value in connection.execute(
                    "SELECT key,value FROM settings WHERE key IN (?,?,?,?)",
                    (
                        "wireguard_configured",
                        "wireguard_interface",
                        "wireguard_subnet",
                        lifecycle.killswitch.SETTING_INGRESS,
                    ),
                )
            }
        if not settings.get("wireguard_configured", False):
            return ()
        subnet = ipaddress.ip_network(settings["wireguard_subnet"], strict=True)
        if subnet.version != 4 or subnet.prefixlen > 30:
            raise ValueError
        interfaces = (
            settings["wireguard_interface"],
            *settings.get(lifecycle.killswitch.SETTING_INGRESS, []),
        )
        if len(interfaces) > 32 or any(
            not isinstance(item, str) or lifecycle.killswitch.INTERFACE_RE.fullmatch(item) is None
            for item in interfaces
        ):
            raise ValueError
        return tuple(IngressIdentity(item, str(subnet)) for item in dict.fromkeys(interfaces))
    except (sqlite3.DatabaseError, ValueError, TypeError, KeyError):
        raise ContainerRecoveryError("recovery_ingress_invalid") from None


class ContainerRecoveryCoordinator:
    def __init__(
        self,
        state: ContainerState,
        hooks: RecoveryHooks,
        *,
        require_exclusive: Callable[[], bool],
        phase_observer: Callable[[str], None] | None = None,
    ):
        self.state, self.layout, self.hooks = state, state.layout, hooks
        self.phase_observer = phase_observer
        self.require_exclusive = require_exclusive
        self.journal = self.layout.recovery / "transaction.json"

    def _leased(self) -> None:
        if self.require_exclusive() is not True:
            raise ContainerRecoveryError("recovery_exclusive_lease_required")

    def _paths(self, transaction: str) -> tuple[Path, Path]:
        try:
            if str(uuid.UUID(transaction)) != transaction:
                raise ValueError
        except (TypeError, ValueError, AttributeError):
            raise ContainerRecoveryError("recovery_journal_invalid") from None
        base = self.layout.recovery / transaction
        return base / "candidate", base / "previous"

    def _record(self, transaction: str, phase: str, ingress: tuple[IngressIdentity, ...]) -> None:
        self._leased()
        if phase not in PHASES:
            raise ContainerRecoveryError("recovery_journal_invalid")
        _private(self.layout.recovery, directory=True)
        record = {
            "version": 1,
            "transaction": transaction,
            "phase": phase,
            "ingress": [{"interface": item.interface, "subnet": item.subnet} for item in ingress],
        }
        temporary = self.journal.with_suffix(".new")
        if temporary.exists() or temporary.is_symlink():
            _private(temporary)
            temporary.unlink()
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(record, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.journal)
        _sync(self.layout.recovery)
        if self.phase_observer:
            self.phase_observer(phase)

    def _read_journal(self) -> dict:
        _private(self.journal)
        if self.journal.stat().st_size > 4096:
            raise ContainerRecoveryError("recovery_journal_invalid")
        try:
            descriptor = os.open(self.journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "r") as source:
                value = json.loads(source.read(4097))
            if (
                not isinstance(value, dict)
                or set(value) != {"version", "transaction", "phase", "ingress"}
                or type(value["version"]) is not int
                or value["version"] != 1
                or value["phase"] not in PHASES
                or not isinstance(value["ingress"], list)
                or len(value["ingress"]) > 32
                or any(
                    not isinstance(item, dict)
                    or set(item) != {"interface", "subnet"}
                    or not isinstance(item["interface"], str)
                    or lifecycle.killswitch.INTERFACE_RE.fullmatch(item["interface"]) is None
                    or not isinstance(item["subnet"], str)
                    or ipaddress.ip_network(item["subnet"], strict=True).version != 4
                    or ipaddress.ip_network(item["subnet"], strict=True).prefixlen > 30
                    for item in value["ingress"]
                )
            ):
                raise ValueError
            self._paths(value["transaction"])
            return value
        except (ValueError, TypeError, KeyError):
            raise ContainerRecoveryError("recovery_journal_invalid") from None

    def _snapshot(self, destination: Path) -> ContainerLayout:
        self._leased()
        destination.mkdir(mode=0o700)
        target = ContainerLayout(destination)
        for directory in (target.config, target.state, target.recovery, target.backups):
            directory.mkdir(mode=0o700)
        lifecycle._database_snapshot(self.layout.database, target.database)
        _copy_file(self.layout.master_key, target.master_key)
        _copy_file(self.layout.manifest, target.manifest)
        _copy_directory(self.layout.wireguard, target.wireguard)
        _copy_directory(self.layout.provider_egress, target.provider_egress)
        ContainerState(target).validate()
        _sync_tree(destination)
        return target

    def _publish(self, source: ContainerLayout) -> None:
        self._leased()
        ContainerState(source).validate()
        # Only called after every writer has been reaped. Remove known SQLite sidecars.
        for suffix in ("-wal", "-shm", "-journal"):
            path = Path(str(self.layout.database) + suffix)
            if path.exists() or path.is_symlink():
                _private(path)
                path.unlink()
        for source_file, target in (
            (source.database, self.layout.database),
            (source.master_key, self.layout.master_key),
            (source.manifest, self.layout.manifest),
        ):
            if target.exists() or target.is_symlink():
                _private(target)
            temporary = target.with_name(target.name + ".recovery-new")
            if temporary.exists() or temporary.is_symlink():
                _private(temporary)
                temporary.unlink()
            _copy_file(source_file, temporary)
            os.replace(temporary, target)
            _sync(target.parent)
            if self.phase_observer:
                label = {
                    self.layout.database: "published_database",
                    self.layout.master_key: "published_master_key",
                    self.layout.manifest: "published_manifest",
                }[target]
                self.phase_observer(label)
        for source_dir, target in (
            (source.wireguard, self.layout.wireguard),
            (source.provider_egress, self.layout.provider_egress),
        ):
            _private(target, directory=True)
            for entry in target.iterdir():
                _private(entry)
                entry.unlink()
            for entry in source_dir.iterdir():
                _copy_file(entry, target / entry.name)
            _sync(target)
            if self.phase_observer:
                self.phase_observer(
                    "published_wireguard"
                    if target == self.layout.wireguard
                    else "published_provider_egress"
                )

    async def _resume(self) -> StateInventory:
        inventory = self.state.validate()
        if inventory.recovery_required:
            raise ContainerRecoveryError("container_state_recovery_required")
        await self.hooks.reconcile(inventory)
        if await self.hooks.health() is not True:
            raise ContainerRecoveryError("recovery_health_failed")
        await self.hooks.reopen()
        return inventory

    def _cleanup(self, transaction: str) -> None:
        self._leased()
        candidate, _ = self._paths(transaction)
        _private(candidate.parent, directory=True)
        _sync_tree(candidate.parent)
        # The coherent pair is committed and networking proven. Remove the
        # receipt first so a crash during cleanup cannot reference deleted files.
        self.journal.unlink()
        _sync(self.layout.recovery)
        shutil.rmtree(candidate.parent)
        _sync(self.layout.recovery)

    async def startup(self) -> StateInventory:
        try:
            return await self._startup()
        except (ContainerRecoveryError, ContainerStateError, lifecycle.LifecycleError):
            raise
        except Exception:  # noqa: BLE001 - hooks must never expose credential-bearing errors
            raise ContainerRecoveryError("recovery_required") from None

    async def _startup(self) -> StateInventory:
        """Run before ingress/app workers. Existing unmanifested state is never adopted."""
        self._leased()
        root = self.layout.root
        if not root.exists():
            root.mkdir(mode=0o700)
        _private(root, directory=True)
        if not any(root.iterdir()):
            for directory in (
                self.layout.config,
                self.layout.state,
                self.layout.wireguard,
                self.layout.provider_egress,
                self.layout.recovery,
                self.layout.backups,
            ):
                directory.mkdir(mode=0o700)
            transaction = str(uuid.uuid4())
            candidate, _ = self._paths(transaction)
            candidate.parent.mkdir(mode=0o700)
            self._record(transaction, "init_preparing", ())
            self.state.stage_empty(candidate)
            _sync_tree(candidate)
            self._record(transaction, "init_ready", ())
        if self.journal.exists() or self.journal.is_symlink():
            record = self._read_journal()
            transaction, phase = record["transaction"], record["phase"]
            candidate, previous = self._paths(transaction)
            await self.hooks.guard(tuple(IngressIdentity(**item) for item in record["ingress"]))
            await self.hooks.quiesce()
            await self.hooks.reset_egress()
            if phase == "init_preparing":
                if candidate.exists():
                    _sync_tree(candidate)
                    shutil.rmtree(candidate)
                self.state.stage_empty(candidate)
                _sync_tree(candidate)
                self._record(transaction, "init_ready", ())
                phase = "init_ready"
            if phase == "init_ready":
                self._publish(ContainerLayout(candidate))
            elif phase == "committed":
                self.state.validate()
            elif phase != "prepared":
                self._publish(ContainerLayout(previous))
            inventory = await self._resume()
            self._cleanup(transaction)
            return inventory
        try:
            self.state.validate()  # Key/manifest and private paths precede networking.
        except ContainerStateError as error:
            if error.code != 'container_state_sqlite_recovery_required':
                raise
            # The running namespace's known ingress must be blocked even when
            # the DB cannot yet supply restored selectors. guard(()) still owns
            # this fail-closed runtime boundary; it is not an empty/no-op policy.
            await self.hooks.guard(())
            await self.hooks.quiesce()
            self._leased()
            self.state.recover_database(guard_observed=lambda: True)
        await self.hooks.guard(ingress_identities(self.layout.database))
        await self.hooks.quiesce()
        await self.hooks.reset_egress()
        return await self._resume()

    async def backup(self, destination: Path, passphrase: str) -> lifecycle.BackupInfo:
        self._leased()
        self.state.validate()
        destination = Path(destination)
        if destination.parent != self.layout.backups or destination.name in {"", ".", ".."}:
            raise ContainerRecoveryError("backup_destination_invalid")
        _private(destination.parent, directory=True)
        if destination.exists() or destination.is_symlink():
            _private(destination)
        staging = self.layout.recovery / str(uuid.uuid4())
        staging.mkdir(mode=0o700)
        try:
            database = staging / "database.sqlite3"
            lifecycle._database_snapshot(self.layout.database, database)
            key = staging / "master-key"
            _copy_file(self.layout.master_key, key)
            files = [
                lifecycle._inventory_entry("database", database.name, database, 0o600),
                lifecycle._inventory_entry("master_key", key.name, key, 0o600),
            ]
            sources = sorted(self.layout.wireguard.iterdir())
            if len(sources) > lifecycle.MAX_FILES - 2:
                raise ContainerRecoveryError("recovery_inventory_too_large")
            for index, source in enumerate(sources):
                copy = staging / f"wireguard-{index:03d}.conf"
                _copy_file(source, copy)
                entry = lifecycle._inventory_entry("wireguard_config", copy.name, copy, 0o600)
                entry["original_name"] = source.name
                files.append(entry)
            manifest = {
                "format": "exitlane-appliance-backup",
                "format_version": 1,
                "backup_id": str(uuid.uuid4()),
                "created_at": datetime.now(UTC).isoformat(),
                "exitlane_version": __version__,
                "database_schema_version": 1,
                "files": files,
            }
            self._leased()
            return lifecycle.encrypt_staged_backup(staging, manifest, destination, passphrase)
        finally:
            passphrase = None
            shutil.rmtree(staging)

    async def restore(
        self, source: Path, passphrase: str, *, confirmation: str
    ) -> lifecycle.BackupInfo:
        self._leased()
        if confirmation != "RESTORE EXITLANE":
            raise ContainerRecoveryError("confirmation_required")
        self.state.validate()
        if self.journal.exists() or self.journal.is_symlink():
            raise ContainerRecoveryError("recovery_required")
        transaction = str(uuid.uuid4())
        candidate, previous = self._paths(transaction)
        candidate.parent.mkdir(mode=0o700)
        archive = candidate.parent / "archive"
        archive.mkdir(mode=0o700)
        journalled = False
        try:
            prepared = lifecycle.prepare_restore(source, passphrase, archive)
            passphrase = None
            inventory = self.state.validate_pair(
                prepared.database, prepared.master_key, prepared.wireguard
            )
            if inventory.recovery_required:
                raise ContainerRecoveryError("container_state_recovery_required")
            candidate.mkdir(mode=0o700)
            staged = ContainerLayout(candidate)
            for directory in (
                staged.config,
                staged.state,
                staged.provider_egress,
                staged.recovery,
                staged.backups,
            ):
                directory.mkdir(mode=0o700)
            _copy_file(prepared.database, staged.database)
            _copy_file(prepared.master_key, staged.master_key)
            _copy_directory(prepared.wireguard, staged.wireguard)
            self.state.write_manifest(staged)
            _sync_tree(candidate)
            ingress = tuple(
                dict.fromkeys(
                    (
                        *ingress_identities(self.layout.database),
                        *ingress_identities(staged.database),
                    )
                )
            )
            self._record(transaction, "prepared", ingress)
            journalled = True
            await self.hooks.guard(ingress)
            await self.hooks.quiesce()
            self._snapshot(previous)
            self._record(transaction, "snapshot_ready", ingress)
            await self.hooks.reset_egress()
            self._record(transaction, "publishing", ingress)
            self._publish(staged)
            self._record(transaction, "installed", ingress)
            with sqlite3.connect(self.layout.database) as connection:
                for statement in (
                    "DELETE FROM sessions",
                    "DELETE FROM mfa_challenges",
                    "DELETE FROM mfa_enrollments",
                ):
                    connection.execute(statement)
            _sync(self.layout.database)
            _sync(self.layout.state)
            self._leased()
            inventory = self.state.validate()
            await self.hooks.reconcile(inventory)
            if await self.hooks.health() is not True:
                raise ContainerRecoveryError("recovery_health_failed")
            self._record(transaction, "validated", ingress)
            # A committed receipt only follows all safety postconditions; startup
            # may retain this new pair and re-prove networking before reopening.
            self._record(transaction, "committed", ingress)
            await self.hooks.reopen()
            self._cleanup(transaction)
            return lifecycle._backup_info(prepared.manifest)
        except Exception:
            if journalled:
                try:
                    await self.hooks.guard(
                        tuple(IngressIdentity(**item) for item in self._read_journal()["ingress"])
                    )
                    await self.hooks.quiesce()
                    await self.hooks.reset_egress()
                    if previous.exists():
                        self._record(transaction, "rollback_required", ingress)
                        self._publish(ContainerLayout(previous))
                        await self._resume()
                        self._cleanup(transaction)
                    else:
                        await self._resume()
                        self._cleanup(transaction)
                except Exception:  # noqa: BLE001 - retain guards and sanitize callback failures
                    # Rollback health may have started a candidate writer. Keep
                    # the receipt and block/reap it too, even if guard readback
                    # fails; neither failure may reopen ingress.
                    with suppress(Exception):
                        await self.hooks.guard(
                            tuple(
                                IngressIdentity(**item) for item in self._read_journal()["ingress"]
                            )
                        )
                    with suppress(Exception):
                        await self.hooks.quiesce()
                    raise ContainerRecoveryError("recovery_required") from None
                raise ContainerRecoveryError("restore_failed_rolled_back") from None
            shutil.rmtree(candidate.parent)
            raise
        finally:
            passphrase = None
