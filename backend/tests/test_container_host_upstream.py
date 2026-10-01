"""Synthetic upstream injection must not replace appliance networking."""

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "host_upstream", ROOT / "scripts/qualification/container_host_upstream.py"
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def test_configuration_rejects_symlink_and_world_readable(tmp_path):
    config = tmp_path / "config"
    config.write_text(json.dumps({"address": "192.168.99.2", "port": 8991, "token": "a" * 64}))
    config.chmod(0o644)
    with pytest.raises(ValueError, match="qualification_configuration_invalid"):
        fixture.configuration(config)
    config.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(config)
    with pytest.raises(OSError):
        fixture.configuration(link)


@pytest.mark.parametrize(
    "change",
    [
        {"address": "1.1.1.1"},
        {"address": "127.0.0.1"},
        {"address": "0.0.0.0"},
        {"port": True},
        {"port": 80},
        {"token": "bad"},
        {"unexpected": "state"},
    ],
)
def test_fixture_control_contract_is_bounded(tmp_path, change):
    config = tmp_path / "config"
    value = {"address": "192.168.99.2", "port": 8991, "token": "a" * 64} | change
    config.write_text(json.dumps(value))
    config.chmod(0o600)
    with pytest.raises(ValueError):
        fixture.configuration(config)


def test_real_singletons_only_factories_are_replaced(monkeypatch):
    from exitlane.providers import mullvad, pia
    from exitlane.providers.catalog import provider_registry

    old_m, old_p = mullvad.provider.api_factory, pia.provider.api_factory
    objects = (mullvad.provider, pia.provider)
    wireguard = (objects[0].wireguard, objects[1].wireguard)
    try:
        fixture.install({"address": "192.168.99.2", "port": 8991, "token": "a" * 64})
        assert (mullvad.provider, pia.provider) == objects
        assert (objects[0].wireguard, objects[1].wireguard) == wireguard
        assert provider_registry.get("mullvad") is objects[0]
        assert provider_registry.get("pia") is objects[1]
        assert isinstance(objects[0].api_factory("synthetic"), fixture.MullvadResponses)
        assert isinstance(objects[1].api_factory("synthetic", "synthetic"), fixture.PiaResponses)
    finally:
        objects[0].api_factory, objects[1].api_factory = old_m, old_p


def test_actual_generated_public_key_is_registered():
    calls = []
    key = "A" * 43 + "="

    class Service:
        async def call(self, action, **fields):
            calls.append((action, fields))
            return {
                "id": "d6-device",
                "name": "Synthetic device",
                "pubkey": key,
                "ipv4_address": "10.64.0.2/32",
                "ipv6_address": None,
            }

    device = asyncio.run(fixture.MullvadResponses(Service()).create_device(key))
    assert device.pubkey == key
    assert calls == [("mullvad_register", {"public_key": key})]


def test_sitecustomize_failure_is_not_ignored_by_python(tmp_path):
    (tmp_path / "sitecustomize.py").write_text(
        (ROOT / "docker/testing/sitecustomize_d6.py").read_text()
    )
    (tmp_path / "_exitlane_d6_upstream.py").write_text(
        'def install():\n raise ValueError("synthetic-secret-must-not-leak")\n'
    )
    result = subprocess.run(
        [sys.executable, "-m", "exitlane.container_entrypoint", "worker"],
        env=dict(os.environ, PYTHONPATH=str(tmp_path)),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 78
    assert result.stderr == "qualification_upstream_initialization_failed\n"
    assert "synthetic-secret" not in result.stdout + result.stderr


@pytest.mark.parametrize("arguments", [["-c", 'print("healthy")'], ["-m", "json.tool"]])
def test_nonworker_process_does_not_install_fixture(tmp_path, arguments):
    (tmp_path / "sitecustomize.py").write_text(
        (ROOT / "docker/testing/sitecustomize_d6.py").read_text()
    )
    (tmp_path / "_exitlane_d6_upstream.py").write_text('raise RuntimeError("must not import")\n')
    result = subprocess.run(
        [sys.executable, *arguments],
        input="{}",
        env=dict(os.environ, PYTHONPATH=str(tmp_path)),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert not result.stderr


def test_fifo_is_rejected_before_a_blocking_read(tmp_path):
    import os

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError):
        fixture.configuration(fifo)
