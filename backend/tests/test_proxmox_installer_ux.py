"""Operator UI and secret-safe execution boundary without PVE mutation."""

import base64
import importlib.util
import json
import os
import subprocess
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "installer/create-proxmox-lxc.py"
SPEC = importlib.util.spec_from_file_location("installer_ux", SOURCE)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
KEY = "ssh-ed25519 " + base64.b64encode(BLOB).decode()


def test_capability_query_has_no_host_or_mutation(capsys):
    with patch.object(helper, "plan", side_effect=AssertionError("mutation")):
        assert helper.main(["--bootstrap-capabilities"]) == 0
    assert json.loads(capsys.readouterr().out) == {"schema": 1, "interactive": True}


@pytest.mark.parametrize(
    "line", ["PRIVATE KEY", "command=foo " + KEY, "ssh-ed25519 YWJj", "ssh-rsa " + KEY.split()[1]]
)
def test_unsafe_key_rejected(line):
    with pytest.raises(helper.PreflightError):
        helper.public_key(line)


def test_discovery_deduplicates_and_ignores_restricted_keys(tmp_path):
    (tmp_path / "first.pub").write_text(KEY + " user@example\n")
    (tmp_path / "second.pub").write_text(KEY + " duplicate\n")
    (tmp_path / "authorized_keys").write_text("command=restricted " + KEY + "\ninvalid\n")
    assert helper.discover_keys(tmp_path) == [KEY]
    assert "SHA256:" in helper.key_label(KEY)
    assert KEY.split()[1] not in helper.key_label(KEY)


def test_explicit_public_key_file(tmp_path):
    path = tmp_path / "key.pub"
    path.write_text(KEY + "\n" + KEY + "\n")
    args = helper.parse_args(["--ssh-public-key-file", str(path)])
    assert args.ssh_keys == [KEY]


def ui(monkeypatch, answers, passwords=(), width=80):
    iterator = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _: next(iterator))
    monkeypatch.setattr(helper.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(helper.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(helper, "check_host", lambda: None)
    monkeypatch.setattr(helper, "discover_keys", lambda: [KEY])
    monkeypatch.setattr(
        helper.shutil, "get_terminal_size", lambda *_, **__: os.terminal_size((width, 24))
    )
    masked = iter(passwords)
    monkeypatch.setattr(helper.getpass, "getpass", lambda _: next(masked))
    return helper.interactive(helper.parse_args(["--interactive"]))


def test_recommended_plain_narrow_and_no_credentials(monkeypatch, capsys):
    args = ui(monkeypatch, ["", "", "4", ""], width=30)
    assert args.cores == 2 and args.memory == 2048
    assert not args.root_password and not args.ssh_password_auth and not args.ssh_keys
    assert "┌" not in capsys.readouterr().out


def test_password_masked_confirmed_and_key_only(monkeypatch, capsys):
    args = ui(monkeypatch, ["1", "y", "1", "1", "1"], ["synthetic-fixture", "synthetic-fixture"])
    assert args.root_password == "synthetic-fixture"
    assert args.ssh_keys == [KEY] and not args.ssh_password_auth
    assert "synthetic-fixture" not in capsys.readouterr().out


def test_password_mismatch(monkeypatch):
    with pytest.raises(helper.PreflightError, match="confirmation"):
        ui(monkeypatch, ["1", "y"], ["synthetic-one", "synthetic-two"])


def test_unmasked_password_fallback_fails_before_reading(monkeypatch):
    def unavailable(_prompt):
        warnings.warn("terminal echo unavailable", helper.getpass.GetPassWarning)
        raise AssertionError("must not read password with echo")

    iterator = iter(["1", "y"])
    monkeypatch.setattr("builtins.input", lambda _: next(iterator))
    monkeypatch.setattr(helper.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(helper.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(helper, "check_host", lambda: None)
    monkeypatch.setattr(helper.getpass, "getpass", unavailable)
    with pytest.raises(helper.PreflightError, match="Masked password input unavailable"):
        helper.interactive(helper.parse_args(["--interactive"]))


@pytest.mark.parametrize("answer", ["3", "hostile;echo", "99"])
def test_menu_cancel_invalid_no_plan(monkeypatch, answer):
    with pytest.raises(helper.PreflightError):
        ui(monkeypatch, [answer])


@pytest.mark.parametrize("mode,visible", [("standard", False), ("verbose", True), ("quiet", False)])
def test_streaming_modes_permissions_and_log(tmp_path, capsys, mode, visible):
    log = helper.InstallationLog(123, "v1.2.3", mode, tmp_path / "logs")
    log.stage("Fixture")
    result = log.execute(("python3", "-c", "print('child-output')"))
    log.close()
    assert result.stdout == "child-output\n"
    assert ("child-output" in capsys.readouterr().out) is visible
    assert "STAGE Fixture" in log.path.read_text()
    assert "child-output" in log.path.read_text()
    assert log.path.stat().st_mode & 0o777 == 0o600
    assert log.path.parent.stat().st_mode & 0o777 == 0o700


def test_safe_transfer_no_secret_in_command_log_exception(tmp_path):
    log = helper.InstallationLog(123, "v1.2.3", "verbose", tmp_path / "logs")
    args = helper.parse_args([])
    args.root_password = "synthetic-secret-marker"
    args.ssh_keys = [KEY]
    seen = []

    def execute(command, **kwargs):
        seen.append((command, kwargs))
        assert args.root_password is None
        assert "synthetic-secret-marker" not in repr(command)
        payload = json.loads(kwargs["secret_input"])
        assert payload["password"] == "synthetic-secret-marker"
        assert payload["keys"] == [KEY]

    with (
        patch.object(helper, "INSTALL_LOG", log),
        patch.object(log, "execute", side_effect=execute),
    ):
        helper.configure_access(123, args)
    log.close()
    assert seen and "synthetic-secret-marker" not in log.path.read_text()


def test_secret_child_output_suppressed_on_failure(tmp_path, capsys):
    log = helper.InstallationLog(123, "v1.2.3", "verbose", tmp_path / "logs")
    with pytest.raises(subprocess.CalledProcessError) as error:
        log.execute(
            ("python3", "-c", "import sys; print(sys.stdin.read()); sys.exit(4)"),
            secret_input=b"synthetic-secret-marker",
        )
    log.failure()
    log.close()
    assert "synthetic-secret-marker" not in repr(error.value)
    assert "synthetic-secret-marker" not in log.path.read_text()
    assert "synthetic-secret-marker" not in str(capsys.readouterr())


def test_subprocess_failure_tail_and_bounded_capture(tmp_path, capsys):
    log = helper.InstallationLog(123, "v1.2.3", "standard", tmp_path / "logs")
    log.stage("Prerequisites")
    with pytest.raises(subprocess.CalledProcessError) as error:
        log.execute(
            ("python3", "-c", "import sys; print('x'*100000); print('failure-tail'); sys.exit(100)")
        )
    assert len(error.value.output) <= 65536
    log.failure()
    log.close()
    assert "failure-tail" in capsys.readouterr().err


def test_key_survives_guest_configuration_and_default_policy():
    assert 'f.write_text("\\n".join(keys)' in helper.ACCESS_SCRIPT
    assert "prohibit-password" in helper.ACCESS_SCRIPT
    assert "KbdInteractiveAuthentication no" in helper.ACCESS_SCRIPT
    assert "if ssh:" in helper.ACCESS_SCRIPT  # Console-only leaves SSH unchanged.


def test_closed_output_child_timeout_kills_and_reaps(tmp_path):
    log = helper.InstallationLog(123, "v1.2.3", "standard", tmp_path / "logs")
    with pytest.raises(subprocess.TimeoutExpired):
        log.execute(
            ("python3", "-c", "import os,time; os.close(1); os.close(2); time.sleep(20)"),
            timeout=0.1,
        )
    log.close()


@pytest.mark.parametrize("enabled", [False, True])
def test_guest_ssh_effective_policy_and_password_stdin(tmp_path, enabled):
    import io

    payload = json.dumps(
        {"password": "synthetic-marker", "keys": [KEY], "ssh": True, "password_auth": enabled}
    )
    calls = []
    real_path = Path

    def guest_path(value):
        return real_path(tmp_path / str(value).lstrip("/"))

    (tmp_path / "root").mkdir()
    (tmp_path / "etc/ssh/sshd_config.d").mkdir(parents=True)
    (tmp_path / "run").mkdir()

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        assert "synthetic-marker" not in repr(command)
        if command[:2] == ["sshd", "-T"]:
            return subprocess.CompletedProcess(
                command,
                0,
                "passwordauthentication "
                + ("yes" if enabled else "no")
                + "\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin "
                + ("yes" if enabled else "without-password")
                + "\nauthenticationmethods "
                + ("any" if enabled else "publickey")
                + "\n",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch("pathlib.Path", side_effect=guest_path),
        patch("subprocess.run", side_effect=execute),
        patch("sys.stdin", io.StringIO(payload)),
    ):
        exec(helper.ACCESS_SCRIPT, {})  # noqa: S102 — exercise repository-owned guest script
    assert (tmp_path / "root/.ssh/authorized_keys").read_text().strip() == KEY
    assert calls[0][0] == ["chpasswd"]
    assert calls[0][1]["input"] == "root:synthetic-marker\n"
    assert any(command[:2] == ["sshd", "-T"] for command, _ in calls)
    commands = [command for command, _ in calls]
    assert commands[-1] == ["systemctl", "restart", "ssh"]
    assert ["systemctl", "reload", "ssh"] not in commands


def test_advanced_grouped_inputs_password_ssh_explicit(monkeypatch):
    answers = [
        "2",
        "",
        "",
        "4",
        "",
        "",
        "",
        "",
        "",
        "",
        "vmbr0",
        "135",
        "",
        "",
        "",
        "y",
        "2",
        KEY,
        "y",
        "2",
    ]
    args = ui(monkeypatch, answers, ["synthetic-fixture", "synthetic-fixture"])
    assert args.cores == 4 and args.vlan == 135
    assert args.ssh_keys == [KEY] and args.ssh_password_auth
    assert args.output == "verbose"


def test_interactive_requires_tty(monkeypatch):
    monkeypatch.setattr(helper.sys.stdin, "isatty", lambda: False)
    with pytest.raises(helper.PreflightError, match="terminal"):
        helper.interactive(helper.parse_args(["--interactive"]))
