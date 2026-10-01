from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "scripts/install_security_cli.sh"


@pytest.mark.parametrize("tool", ["syft", "trivy", "gitleaks"])
def test_corrupted_upstream_archive_is_rejected_before_extraction_or_install(tmp_path, tool):
    binaries = tmp_path / "bin"
    binaries.mkdir()
    curl = binaries / "curl"
    curl.write_text(
        '#!/bin/sh\nwhile [ $# -gt 0 ]; do\n if [ "$1" = -o ]; then shift; printf bad > "$1"; exit 0; fi\n shift\ndone\nexit 2\n'
    )
    curl.chmod(0o755)
    for name in ("tar", "sudo"):
        executable = binaries / name
        executable.write_text('#!/bin/sh\ntouch "$INSTALL_SENTINEL"\nexit 99\n')
        executable.chmod(0o755)
    sentinel = tmp_path / "must-not-extract-or-install"
    env = dict(
        os.environ,
        PATH=str(binaries) + os.pathsep + os.environ["PATH"],
        INSTALL_SENTINEL=str(sentinel),
    )
    result = subprocess.run(
        ["bash", str(INSTALLER), tool], env=env, capture_output=True, timeout=10, check=False
    )
    assert result.returncode != 0
    assert not sentinel.exists()


def test_unknown_tool_cannot_select_an_arbitrary_download():
    result = subprocess.run(
        ["bash", str(INSTALLER), "untrusted"], capture_output=True, timeout=10, check=False
    )
    assert result.returncode == 2
    assert b"security_cli_unknown" in result.stderr
