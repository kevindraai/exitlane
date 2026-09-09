import importlib.util
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "wireguard_dataplane_readiness.py"
SPEC = importlib.util.spec_from_file_location("wireguard_dataplane_readiness", MODULE_PATH)
assert SPEC and SPEC.loader
readiness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = readiness
SPEC.loader.exec_module(readiness)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.waits = []

    def monotonic(self):
        return self.value

    def wait(self, duration):
        self.waits.append(duration)
        self.value += duration


class FakeChecks:
    def __init__(
        self,
        *,
        interface: Iterable[bool] = (True,),
        route: Iterable[bool] = (True,),
        handshakes: Iterable[int | None] = (0,),
        probes: Iterable[bool] = (True,),
        steady=True,
        clock=None,
        probe_duration=0.0,
    ) -> None:
        self.interface_values = iter(interface)
        self.route_values = iter(route)
        self.handshake_values = iter(handshakes)
        self.probe_values = iter(probes)
        self.interface_last = False
        self.route_last = False
        self.handshake_last = None
        self.probe_last = False
        self.steady = steady
        self.clock = clock
        self.probe_duration = probe_duration
        self.probe_calls = 0
        self.steady_calls = 0

    @staticmethod
    def _next(values, last):
        try:
            return next(values)
        except StopIteration:
            return last

    def interface_ready(self):
        self.interface_last = self._next(self.interface_values, self.interface_last)
        return self.interface_last

    def route_ready(self):
        self.route_last = self._next(self.route_values, self.route_last)
        return self.route_last

    def latest_handshake(self):
        self.handshake_last = self._next(self.handshake_values, self.handshake_last)
        return self.handshake_last

    def dataplane_probe(self, _timeout_seconds):
        self.probe_calls += 1
        if self.clock:
            self.clock.value += self.probe_duration
        self.probe_last = self._next(self.probe_values, self.probe_last)
        return self.probe_last

    def steady_state_probe(self):
        self.steady_calls += 1
        return self.steady


def run(checks, clock, *, deadline=5):
    return readiness.wait_for_wireguard_dataplane(
        checks,
        deadline_seconds=deadline,
        probe_timeout_seconds=1,
        poll_interval_seconds=0.1,
        monotonic=clock.monotonic,
        wait=clock.wait,
    )


def test_restart_waits_for_route_then_probe_triggers_handshake_and_data():
    clock = FakeClock()
    checks = FakeChecks(
        interface=(False, True, True, True),
        route=(False, True, True),
        handshakes=(0, 0, 0, 42),
        probes=(False, False, True),
        steady=True,
        clock=clock,
        probe_duration=0.5,
    )

    result = run(checks, clock)

    assert result.ready is True
    assert result.reason == "ready"
    assert result.attempts == 3
    assert result.handshake_advanced is True
    assert result.dataplane_ready is True
    assert result.steady_state_ready is True
    assert checks.probe_calls == 3
    assert checks.steady_calls == 1


def test_missing_handshake_has_bounded_timeout_and_never_reports_ready():
    clock = FakeClock()
    checks = FakeChecks(
        handshakes=(0,),
        probes=(False,),
        steady=True,
        clock=clock,
        probe_duration=0.4,
    )

    result = run(checks, clock, deadline=1)

    assert result.ready is False
    assert result.reason == "dataplane_timeout"
    assert result.handshake_advanced is False
    assert result.elapsed_ms == pytest.approx(1000, abs=100)
    assert checks.steady_calls == 0


def test_handshake_without_working_data_remains_not_ready():
    clock = FakeClock()
    checks = FakeChecks(
        handshakes=(0, 77),
        probes=(False,),
        steady=True,
        clock=clock,
        probe_duration=0.4,
    )

    result = run(checks, clock, deadline=1)

    assert result.ready is False
    assert result.reason == "dataplane_timeout"
    assert result.handshake_advanced is True
    assert result.dataplane_ready is False
    assert checks.steady_calls == 0


def test_probe_waits_for_interface_and_route_and_times_out_without_them():
    clock = FakeClock()
    checks = FakeChecks(
        interface=(False, True),
        route=(False,),
        probes=(True,),
        clock=clock,
    )

    result = run(checks, clock, deadline=0.5)

    assert result.ready is False
    assert result.reason == "route_unavailable"
    assert result.attempts == 0
    assert checks.probe_calls == 0
    assert checks.steady_calls == 0


def test_fast_existing_session_has_no_polling_delay():
    clock = FakeClock()
    checks = FakeChecks(
        handshakes=(100, 100),
        probes=(True,),
        steady=True,
        clock=clock,
    )

    result = run(checks, clock)

    assert result.ready is True
    assert result.attempts == 1
    assert result.elapsed_ms == 0
    assert result.handshake_advanced is False
    assert clock.waits == []


def test_bootstrap_success_does_not_mask_steady_state_packet_loss():
    clock = FakeClock()
    checks = FakeChecks(probes=(True,), steady=False, clock=clock)

    result = run(checks, clock)

    assert result.ready is False
    assert result.reason == "steady_state_failed"
    assert result.dataplane_ready is True
    assert result.steady_state_ready is False


@pytest.mark.parametrize("value", ["0", "121", "inf", "nan"])
def test_cli_time_bounds_reject_unbounded_values(value):
    with pytest.raises(readiness.argparse.ArgumentTypeError):
        readiness.positive_float(value)
