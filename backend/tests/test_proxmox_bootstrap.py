"""Run the actual Bash launcher against bounded HTTPS and engine fixtures."""

import hashlib
import json
import os
import pty
import select
import signal
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "installer/proxmox.sh"
TAG = "v0.3.0-rc.3"
ENGINE = """import json, os, sys
open(os.environ['ARGS_LOG'], 'w').write(json.dumps(sys.argv[1:]))
print('Canonical plan: ' + repr(sys.argv[1:]), flush=True)
answer = input('Create? [y/N]: ')
if answer == 'y':
    open(os.environ['MUTATION_LOG'], 'w').write('created')
    sys.exit(int(os.environ.get('ENGINE_EXIT', '0')))
sys.exit(1)
"""


@pytest.fixture
def bootstrap(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in {
        "pveversion": '#!/bin/sh\nexit "${PVE_EXIT:-0}"\n',
        "curl": """#!/usr/bin/env python3
import os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
url = args[-1]
root = Path(os.environ['FIXTURES'])
with open(root / 'urls', 'a') as log:
    log.write(url + '\\n')
if os.environ.get('NETWORK_FAIL'):
    sys.exit(22)
output = args[args.index('--output') + 1]
source = 'releases.json' if '/releases' in url else 'helper.json' if '/contents/' in url else 'helper.py'
shutil.copyfile(root / source, output)
""",
    }.items():
        path = bin_dir / name
        path.write_text(text)
        path.chmod(0o755)
    (tmp_path / "releases.json").write_text(
        json.dumps(
            [
                {
                    "tag_name": TAG,
                    "draft": False,
                    "prerelease": False,
                    "published_at": "2026-09-30T15:11:06Z",
                }
            ]
        )
    )
    payload = ENGINE.encode()
    (tmp_path / "helper.py").write_bytes(payload)
    digest = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    (tmp_path / "helper.json").write_text(
        json.dumps(
            {
                "type": "file",
                "path": "installer/create-proxmox-lxc.py",
                "sha": digest,
                "size": len(payload),
            }
        )
    )
    env = dict(
        os.environ,
        PATH=f"{bin_dir}:/usr/bin:/bin",
        FIXTURES=str(tmp_path),
        ARGS_LOG=str(tmp_path / "args"),
        MUTATION_LOG=str(tmp_path / "mutation"),
    )
    env.pop("EXITLANE_VERSION", None)
    return tmp_path, env


def launch(env, text="1\ny\n", interrupt=False):
    before = set(Path("/tmp").glob("exitlane-bootstrap.*"))
    master, slave = pty.openpty()
    process = subprocess.Popen(
        ["bash", "-c", SCRIPT.read_text().replace("$EUID", "0")],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        start_new_session=True,
    )
    os.close(slave)
    output = b""
    sent = False
    deadline = time.monotonic() + 8
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    output += os.read(master, 65536)
                except OSError:
                    break
            if b"Choose [1]:" in output and not sent:
                if interrupt:
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    os.write(master, text.encode())
                sent = True
            if process.poll() is not None:
                break
        process.wait(timeout=2)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
    assert set(Path("/tmp").glob("exitlane-bootstrap.*")) == before
    return process.returncode, output.decode(errors="replace")


def test_default_plan_exact_tag_and_cleanup(bootstrap):
    root, env = bootstrap
    code, output = launch(env, "\ny\n")
    assert code == 0
    assert json.loads((root / "args").read_text()) == ["--ref", TAG]
    assert output.count("Canonical plan:") == 1
    assert (root / "mutation").exists()
    assert f"/{TAG}/installer/create-proxmox-lxc.py" in (root / "urls").read_text()
    assert f"?ref={TAG}" in (root / "urls").read_text()


def test_advanced_arguments_are_literal(bootstrap):
    root, env = bootstrap
    values = [
        "214",
        "exitlane",
        "local-lvm",
        "local",
        "vmbr0",
        "192.0.2.20/24",
        "192.0.2.1",
        "192.0.2.53",
        "42",
        "4",
        "4096",
        "32",
        "lab",
        "order=2,up=30",
    ]
    assert launch(env, "2\n" + "\n".join(values) + "\ny\n")[0] == 0
    args = json.loads((root / "args").read_text())
    assert args[:2] == ["--ref", TAG]
    assert args[3::2] == values
    assert "--yes" not in args


@pytest.mark.parametrize("text", ["3\n", "$(touch hostile)\n", "1\nn\n"])
def test_cancellation_and_hostile_menu_never_mutate(bootstrap, text):
    root, env = bootstrap
    launch(env, text)
    assert not (root / "mutation").exists()


def test_hostile_advanced_value_is_one_argument(bootstrap):
    root, env = bootstrap
    value = "$(touch hostile); spaces"
    launch(env, "2\n\n" + value + "\n" + "\n" * 12 + "n\n")
    assert json.loads((root / "args").read_text())[3] == value
    assert not (root / "mutation").exists()


@pytest.mark.parametrize(
    "value",
    [
        "{}",
        "[]",
        "null",
        '[{"tag_name":"main"}]',
        '[{"tag_name":"v1.0.0","draft":false,"prerelease":false}]',
    ],
)
def test_invalid_release_response(bootstrap, value):
    root, env = bootstrap
    (root / "releases.json").write_text(value)
    assert launch(env)[0] != 0
    assert not (root / "args").exists()


@pytest.mark.parametrize("version", ["main", "v1.0.0;id", "v1.0.0/evil", "v1.0.0\n"])
def test_invalid_tag(bootstrap, version):
    root, env = bootstrap
    env["EXITLANE_VERSION"] = version
    assert launch(env)[0] != 0
    assert not (root / "urls").exists()


def test_explicit_version_and_mismatched_response(bootstrap):
    root, env = bootstrap
    releases = json.loads((root / "releases.json").read_text())
    (root / "releases.json").write_text(json.dumps(releases[0]))
    env["EXITLANE_VERSION"] = TAG
    assert launch(env)[0] == 0
    assert f"/releases/tags/{TAG}" in (root / "urls").read_text()
    (root / "args").unlink()
    env["EXITLANE_VERSION"] = "v9.0.0"
    assert launch(env)[0] != 0
    assert not (root / "args").exists()


@pytest.mark.parametrize("failure", ["network", "empty", "mismatch", "host"])
def test_download_and_host_failures(bootstrap, failure):
    root, env = bootstrap
    if failure == "network":
        env["NETWORK_FAIL"] = "1"
    elif failure == "host":
        env["PVE_EXIT"] = "1"
    elif failure == "empty":
        (root / "helper.py").write_text("")
    else:
        (root / "helper.py").write_text('print("wrong")')
    assert launch(env)[0] != 0
    assert not (root / "args").exists()
    assert not (root / "mutation").exists()


def test_no_tty_and_no_root(bootstrap):
    _, env = bootstrap
    result = subprocess.run(
        ["bash", "-c", SCRIPT.read_text().replace("$EUID", "0")],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode != 0 and b"terminal" in result.stderr
    # Exercise the root refusal without setuid (sandbox/CI need no privilege).
    result = subprocess.run(
        ["bash", "-c", SCRIPT.read_text().replace("$EUID", "65534")],
        capture_output=True,
        env=env,
        check=False,
    )
    assert result.returncode != 0 and b"root" in result.stderr


def test_engine_failure_propagates(bootstrap):
    _, env = bootstrap
    env["ENGINE_EXIT"] = "37"
    assert launch(env)[0] == 37


def test_interrupted_launcher_cleans_temporary_files(bootstrap):
    root, env = bootstrap
    assert launch(env, interrupt=True)[0] == 143
    assert not (root / "mutation").exists()
