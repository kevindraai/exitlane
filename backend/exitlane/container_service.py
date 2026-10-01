"""Fixed supervisor control operations; passphrases stay in IPC memory only."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

from exitlane import lifecycle
from exitlane.container_control import ControlError
from exitlane.container_recovery import ContainerRecoveryError
from exitlane.container_state import ContainerStateError

BACKUP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.elbackup\Z")


class ContainerRecoveryService:
    def __init__(self, coordinator, authority, *, worker_running=lambda: False):
        self.coordinator = coordinator
        self.authority = authority
        self.worker_running = worker_running

    @property
    def callbacks(self):
        return {"backup": self.backup, "restore": self.restore, "status": self.status}

    def _payload(self, payload, fields):
        if set(payload) != fields or self.authority.owner is None:
            raise ControlError("control_invalid_request")
        passphrase = payload.get("passphrase")
        if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 1024:
            raise ControlError("control_invalid_request")
        return passphrase

    async def backup(self, payload):
        passphrase = self._payload(payload, {"passphrase"})
        name = f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{uuid4().hex[:12]}.elbackup"
        try:
            await self.coordinator.backup(self.coordinator.layout.backups / name, passphrase)
            return {"name": name}
        except (lifecycle.LifecycleError, ContainerStateError):
            return {"ok": False, "error": "backup_rejected"}
        finally:
            passphrase = None
            payload.clear()

    async def restore(self, payload):
        passphrase = self._payload(payload, {"name", "passphrase", "confirmation"})
        name = payload["name"]
        if not isinstance(name, str) or BACKUP_NAME.fullmatch(name) is None:
            raise ControlError("control_invalid_request")
        try:
            await self.coordinator.restore(
                self.coordinator.layout.backups / name,
                passphrase,
                confirmation=payload["confirmation"],
            )
            return {"restored": True}
        except (lifecycle.LifecycleError, ContainerStateError):
            # The coordinator validates incoming crypto/state before networking.
            # Return a completed refusal rather than pretending the writer died.
            return {"restored": False, "error": "restore_rejected"}
        except ContainerRecoveryError as error:
            if error.code not in {"restore_failed_rolled_back", "confirmation_required"}:
                self.authority.require_recovery()
            return {"restored": False, "error": "restore_failed"}
        finally:
            passphrase = None
            payload.clear()

    async def status(self, payload):
        if payload:
            raise ControlError("control_invalid_request")
        recovery = self.coordinator.journal.exists() or self.coordinator.journal.is_symlink()
        return {
            "state": "recovery_required" if recovery or not self.authority.available else "ready",
            "available": self.authority.available,
            "recovery_required": recovery,
            "worker_running": self.worker_running() is True,
        }
