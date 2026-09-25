#!/usr/bin/env python3
"""Bounded WireGuard dataplane readiness gate for live QA."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Protocol


class ReadinessChecks(Protocol):
    def interface_ready(self) -> bool: ...

    def route_ready(self) -> bool: ...

    def latest_handshake(self) -> int | None: ...

    def dataplane_probe(self, timeout_seconds: float) -> bool: ...

    def steady_state_probe(self) -> bool: ...


@dataclass(frozen=True)
class ReadinessResult:
    ready: bool
    reason: str
    attempts: int
    elapsed_ms: int
    interface_ready: bool
    route_ready: bool
    handshake_advanced: bool
    dataplane_ready: bool
    steady_state_ready: bool


def wait_for_wireguard_dataplane(
    checks: ReadinessChecks,
    *,
    deadline_seconds: float,
    probe_timeout_seconds: float,
    poll_interval_seconds: float = 0.1,
    monotonic: Callable[[], float] = time.monotonic,
    wait: Callable[[float], None] = time.sleep,
) -> ReadinessResult:
    """Actively prove bootstrap readiness, then require a separate stable flow."""
    if deadline_seconds <= 0:
        raise ValueError("deadline_seconds must be positive")
    if probe_timeout_seconds <= 0:
        raise ValueError("probe_timeout_seconds must be positive")
    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be positive")

    started_at = monotonic()
    deadline = started_at + deadline_seconds
    initial_handshake = checks.latest_handshake()
    last_handshake = initial_handshake
    interface_ready = False
    route_ready = False
    dataplane_ready = False
    attempts = 0

    while monotonic() < deadline:
        interface_ready = checks.interface_ready()
        route_ready = interface_ready and checks.route_ready()
        if route_ready:
            attempts += 1
            remaining = max(0.0, deadline - monotonic())
            if remaining <= 0:
                break
            dataplane_ready = checks.dataplane_probe(
                min(probe_timeout_seconds, remaining)
            )
            last_handshake = checks.latest_handshake()
            if dataplane_ready:
                break

        remaining = max(0.0, deadline - monotonic())
        if remaining:
            wait(min(poll_interval_seconds, remaining))

    elapsed_ms = round((monotonic() - started_at) * 1000)
    handshake_advanced = (
        last_handshake is not None
        and last_handshake > 0
        and (initial_handshake is None or last_handshake > initial_handshake)
    )
    if not dataplane_ready:
        if not interface_ready:
            reason = "interface_unavailable"
        elif not route_ready:
            reason = "route_unavailable"
        else:
            reason = "dataplane_timeout"
        return ReadinessResult(
            ready=False,
            reason=reason,
            attempts=attempts,
            elapsed_ms=elapsed_ms,
            interface_ready=interface_ready,
            route_ready=route_ready,
            handshake_advanced=handshake_advanced,
            dataplane_ready=False,
            steady_state_ready=False,
        )

    steady_state_ready = checks.steady_state_probe()
    return ReadinessResult(
        ready=steady_state_ready,
        reason="ready" if steady_state_ready else "steady_state_failed",
        attempts=attempts,
        elapsed_ms=elapsed_ms,
        interface_ready=interface_ready,
        route_ready=route_ready,
        handshake_advanced=handshake_advanced,
        dataplane_ready=True,
        steady_state_ready=steady_state_ready,
    )


class SystemChecks:
    def __init__(
        self,
        *,
        interface: str,
        target: str,
        namespace: str | None,
        probe_timeout_seconds: float,
        steady_count: int,
    ) -> None:
        self.interface = interface
        self.target = target
        self.namespace = namespace
        self.probe_timeout_seconds = probe_timeout_seconds
        self.steady_count = steady_count

    def _command(self, *arguments: str, timeout: float = 5) -> subprocess.CompletedProcess[str]:
        prefix = ["ip", "netns", "exec", self.namespace] if self.namespace else []
        try:
            return subprocess.run(
                [*prefix, *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return subprocess.CompletedProcess(arguments, 127, "", "")

    def interface_ready(self) -> bool:
        result = self._command("ip", "-json", "link", "show", "dev", self.interface)
        if result.returncode != 0:
            return False
        try:
            link = json.loads(result.stdout)[0]
        except (IndexError, TypeError, ValueError):
            return False
        return "UP" in link.get("flags", [])

    def route_ready(self) -> bool:
        result = self._command("ip", "-json", "route", "get", self.target)
        if result.returncode != 0:
            return False
        try:
            route = json.loads(result.stdout)[0]
        except (IndexError, TypeError, ValueError):
            return False
        return route.get("type", "unicast") == "unicast" and route.get("dev") == self.interface

    def latest_handshake(self) -> int | None:
        result = self._command("wg", "show", self.interface, "latest-handshakes")
        if result.returncode != 0:
            return None
        handshakes = []
        for line in result.stdout.splitlines():
            try:
                handshakes.append(int(line.rsplit(maxsplit=1)[-1]))
            except (IndexError, ValueError):
                return None
        return max(handshakes, default=0)

    def dataplane_probe(self, timeout_seconds: float) -> bool:
        packet_timeout = max(1, math.ceil(timeout_seconds))
        result = self._command(
            "ping",
            "-n",
            "-I",
            self.interface,
            "-c",
            "1",
            "-W",
            str(packet_timeout),
            self.target,
            timeout=packet_timeout + 1,
        )
        return result.returncode == 0

    def steady_state_probe(self) -> bool:
        packet_timeout = max(1, math.ceil(self.probe_timeout_seconds))
        result = self._command(
            "ping",
            "-n",
            "-I",
            self.interface,
            "-c",
            str(self.steady_count),
            "-W",
            str(packet_timeout),
            self.target,
            timeout=(self.steady_count * packet_timeout) + 2,
        )
        if result.returncode != 0:
            return False
        summary = re.search(
            r"(\d+) packets transmitted, (\d+) (?:packets )?received",
            result.stdout,
        )
        return bool(
            summary
            and int(summary.group(1)) == self.steady_count
            and int(summary.group(2)) == self.steady_count
        )


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or not 0 < parsed <= 120:
        raise argparse.ArgumentTypeError("must be between 0 and 120 seconds")
    return parsed


def bounded_count(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 20:
        raise argparse.ArgumentTypeError("must be between 1 and 20")
    return parsed


def safe_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise argparse.ArgumentTypeError("contains unsupported characters")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True, type=safe_name)
    parser.add_argument("--target", required=True, type=ipaddress.ip_address)
    parser.add_argument("--namespace", type=safe_name)
    parser.add_argument("--deadline-seconds", type=positive_float, default=35.0)
    parser.add_argument("--probe-timeout-seconds", type=positive_float, default=1.0)
    parser.add_argument("--poll-interval-seconds", type=positive_float, default=0.1)
    parser.add_argument("--steady-count", type=bounded_count, default=5)
    arguments = parser.parse_args()
    checks = SystemChecks(
        interface=arguments.interface,
        target=str(arguments.target),
        namespace=arguments.namespace,
        probe_timeout_seconds=arguments.probe_timeout_seconds,
        steady_count=arguments.steady_count,
    )
    result = wait_for_wireguard_dataplane(
        checks,
        deadline_seconds=arguments.deadline_seconds,
        probe_timeout_seconds=arguments.probe_timeout_seconds,
        poll_interval_seconds=arguments.poll_interval_seconds,
    )
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
