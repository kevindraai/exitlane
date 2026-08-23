from __future__ import annotations

import asyncio
import logging
import platform
import shutil
from datetime import UTC, datetime
from pathlib import Path

from exitlane.core import command

logger = logging.getLogger("exitlane.speedtest_installation")

TOOL = "speedtest"
INSTALL_UNIT = "exitlane-speedtest-install.service"
INSTALL_PHASE_FILE = Path("/run/exitlane-speedtest-install/installation.phase")
OFFICIAL_EXECUTABLE = "/usr/bin/speedtest"
OFFICIAL_PACKAGE = "speedtest"
OFFICIAL_VERSION = "1.2.0.84-1.ea6b6773cf"
INSTALL_START_TIMEOUT_SECONDS = 10

PHASES = (
    "checking_system",
    "downloading_package",
    "verifying_package",
    "installing_package",
    "validating_installation",
)
RESPONSE_PHASES = frozenset((*PHASES, "completed", "unavailable", "unsupported", "failed"))
ERROR_CODES = frozenset(
    {
        "speedtest_tool_unavailable",
        "speedtest_cli_unverified",
        "unsupported_platform",
        "package_operation_in_progress",
        "package_download_failed",
        "package_verification_failed",
        "client_install_failed",
        "speedtest_validation_failed",
        "preexisting_speedtest_unverified",
        "helper_timeout",
        "installation_start_failed",
        "installation_failed",
        "insufficient_privileges",
        "arguments_not_allowed",
    }
)
HELPER_ERROR_MAP = {
    "package_download_failed": "package_download_failed",
    "package_verification_failed": "package_verification_failed",
    "client_install_failed": "client_install_failed",
    "speedtest_validation_failed": "speedtest_validation_failed",
    "preexisting_speedtest_unverified": "preexisting_speedtest_unverified",
    "unsupported_platform": "unsupported_platform",
    "package_operation_in_progress": "package_operation_in_progress",
}

_operation_lock: asyncio.Lock | None = None
_starting = False
_started_at: str | None = None
_monitor_task: asyncio.Task | None = None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _operation_started_at() -> str | None:
    if _started_at is not None:
        return _started_at
    try:
        return datetime.fromtimestamp(INSTALL_PHASE_FILE.stat().st_mtime, UTC).isoformat()
    except OSError:
        return None


def _supports_managed_installation() -> bool:
    try:
        values = {
            key: value.strip().strip('"')
            for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
            if "=" in line
            for key, value in [line.split("=", 1)]
        }
    except OSError:
        return False
    return (
        values.get("ID") == "debian"
        and values.get("VERSION_ID") == "13"
        and platform.machine()
        in {
            "amd64",
            "x86_64",
        }
    )


async def _official_cli_state() -> tuple[bool, str]:
    """Validate package ownership and path only; never execute the bandwidth action."""
    executable = shutil.which(TOOL)
    if executable is None:
        return False, "speedtest_tool_unavailable"
    if executable != OFFICIAL_EXECUTABLE:
        return False, "speedtest_cli_unverified"
    rc, output, _error = await command(
        "dpkg-query",
        "--showformat=${Package}|${Version}|${Status}",
        "--show",
        OFFICIAL_PACKAGE,
        timeout=5,
    )
    if rc != 0 or output.strip() != f"{OFFICIAL_PACKAGE}|{OFFICIAL_VERSION}|install ok installed":
        return False, "speedtest_cli_unverified"
    rc, output, _error = await command("dpkg-query", "--listfiles", OFFICIAL_PACKAGE, timeout=5)
    if rc != 0 or OFFICIAL_EXECUTABLE not in output.splitlines():
        return False, "speedtest_cli_unverified"
    return True, ""


def _read_phase() -> tuple[str | None, str | None, str | None]:
    try:
        value = INSTALL_PHASE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None, None, None
    if value in PHASES:
        return value, None, None
    fields = value.split("|")
    if len(fields) == 3 and fields[0] == "failed" and fields[1] in PHASES:
        return "failed", fields[1], HELPER_ERROR_MAP.get(fields[2], "installation_failed")
    if value == "completed":
        return "completed", None, None
    return None, None, None


def _unit_error_code(unit_output: str) -> str:
    values = dict(line.split("=", 1) for line in unit_output.splitlines() if "=" in line)
    if values.get("Result") == "timeout":
        return "helper_timeout"
    return {
        "64": "unsupported_platform",
        "65": "package_download_failed",
        "66": "client_install_failed",
        "68": "speedtest_validation_failed",
        "70": "preexisting_speedtest_unverified",
        "75": "package_operation_in_progress",
        "77": "insufficient_privileges",
    }.get(values.get("ExecMainStatus", ""), "installation_failed")


def _clear_stale_failed_phase() -> None:
    """Remove only a completed prior-attempt failure before an accepted retry."""
    phase, _failed_phase, _error_code = _read_phase()
    if phase != "failed":
        return
    try:
        INSTALL_PHASE_FILE.unlink()
    except FileNotFoundError:
        return
    except OSError:
        logger.warning("Could not clear the stale Speedtest installation failure phase")


def _response(
    *,
    status: str,
    phase: str,
    error_code: str | None = None,
    available: bool = False,
    supported_runtime: bool,
    can_install: bool,
    installation_in_progress: bool = False,
    failed_phase: str | None = None,
) -> dict:
    safe_status = (
        status if status in {"pending", "running", "passed", "warning", "failed"} else "failed"
    )
    safe_phase = phase if phase in RESPONSE_PHASES else "failed"
    safe_error = error_code if error_code in ERROR_CODES else None
    active_phase = failed_phase if safe_status == "failed" else safe_phase
    active_index = PHASES.index(active_phase) if active_phase in PHASES else len(PHASES)
    steps = []
    for index, item in enumerate(PHASES):
        step_status = (
            "completed"
            if safe_phase == "completed"
            else "failed"
            if safe_status == "failed" and index == active_index
            else "completed"
            if index < active_index
            else "active"
            if installation_in_progress and index == active_index
            else "pending"
        )
        steps.append(
            {
                "phase": item,
                "status": step_status,
                "error_code": safe_error if step_status == "failed" else None,
            }
        )
    return {
        "tool": TOOL,
        "status": safe_status,
        "phase": safe_phase,
        "steps": steps,
        "error_code": safe_error,
        "started_at": _operation_started_at(),
        "available": available,
        "supported_runtime": supported_runtime,
        "can_install": can_install,
        "installation_in_progress": installation_in_progress,
        "requires_terms_confirmation": True,
    }


async def status() -> dict:
    """Return the browser-safe installation snapshot and reconcile a reload."""
    global _starting
    supported_runtime = _supports_managed_installation()
    available, cli_error = await _official_cli_state()
    if available:
        _starting = False
        return _response(
            status="passed",
            phase="completed",
            available=True,
            supported_runtime=supported_runtime,
            can_install=False,
        )
    if not supported_runtime:
        _starting = False
        return _response(
            status="warning",
            phase="unsupported",
            error_code="unsupported_platform",
            supported_runtime=False,
            can_install=False,
        )

    rc, unit_output, _error = await command(
        "systemctl",
        "show",
        INSTALL_UNIT,
        "--property=ActiveState,Result,ExecMainStatus",
        timeout=5,
    )
    phase, failed_phase, phase_error = _read_phase()
    active = rc == 0 and any(
        line in {"ActiveState=active", "ActiveState=activating"}
        for line in unit_output.splitlines()
    )
    # A current systemd operation wins over stale phase data from a prior attempt.
    if active:
        return _response(
            status="running",
            phase=phase if phase in PHASES else "checking_system",
            error_code=None,
            supported_runtime=True,
            can_install=False,
            installation_in_progress=True,
        )
    # A completed failure must win over the optimistic accepted-start marker.
    # systemd may finish before the browser's first status poll.
    if phase == "failed" or (rc == 0 and "ActiveState=failed" in unit_output.splitlines()):
        _starting = False
        return _response(
            status="failed",
            phase="failed",
            error_code=phase_error or _unit_error_code(unit_output),
            supported_runtime=True,
            can_install=cli_error == "speedtest_tool_unavailable",
            failed_phase=failed_phase or "installing_package",
        )
    if _starting:
        return _response(
            status="pending",
            phase=phase if phase in PHASES else "checking_system",
            error_code=None,
            supported_runtime=True,
            can_install=False,
            installation_in_progress=True,
        )
    _starting = False
    return _response(
        status="warning",
        phase="unavailable",
        error_code=cli_error,
        supported_runtime=True,
        can_install=cli_error == "speedtest_tool_unavailable",
    )


async def start_installation() -> dict:
    """Start exactly one fixed systemd operation, or return its running snapshot."""
    global _operation_lock, _starting, _started_at, _monitor_task
    if _operation_lock is None:
        _operation_lock = asyncio.Lock()
    async with _operation_lock:
        current = await status()
        if current["installation_in_progress"] or not current["can_install"]:
            return current
        _clear_stale_failed_phase()
        _starting = True
        _started_at = _now()
        await command(
            "systemctl", "reset-failed", INSTALL_UNIT, timeout=INSTALL_START_TIMEOUT_SECONDS
        )
        rc, _output, _error = await command(
            "systemctl",
            "start",
            "--no-block",
            INSTALL_UNIT,
            timeout=INSTALL_START_TIMEOUT_SECONDS,
        )
        if rc != 0:
            _starting = False
            return _response(
                status="failed",
                phase="failed",
                error_code="helper_timeout" if rc == 124 else "installation_start_failed",
                supported_runtime=True,
                can_install=True,
                failed_phase="checking_system",
            )
        if _monitor_task is None or _monitor_task.done():
            _monitor_task = asyncio.create_task(_monitor())
        return _response(
            status="pending",
            phase="checking_system",
            supported_runtime=True,
            can_install=False,
            installation_in_progress=True,
        )


async def _monitor() -> None:
    for _ in range(360):
        await asyncio.sleep(1)
        if not (await status())["installation_in_progress"]:
            return
    logger.warning("Speedtest installation monitor reached its bounded deadline")


def reset_for_tests() -> None:
    global _operation_lock, _starting, _started_at, _monitor_task
    _operation_lock = None
    _starting = False
    _started_at = None
    if _monitor_task is not None:
        _monitor_task.cancel()
    _monitor_task = None
