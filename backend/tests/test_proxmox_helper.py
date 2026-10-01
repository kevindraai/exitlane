"""Deterministic preflight and command-generation coverage without a PVE host."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "installer" / "create-proxmox-lxc.py"
SPEC = importlib.util.spec_from_file_location("proxmox_helper", SOURCE)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def result(stdout: str = "", code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess((), code, stdout, "")


@pytest.fixture
def pve(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "LOG_DIRECTORY", tmp_path / "logs")
    config_dir = tmp_path / "pve" / "lxc"
    config_dir.mkdir(parents=True)
    bridge_root = tmp_path / "net"
    (bridge_root / "vmbr0" / "bridge").mkdir(parents=True)
    state = {
        "downloaded": False,
        "commands": [],
        "collision": False,
        "fail_installer": False,
        "fail_create": False,
    }

    def fake_run(*command, **_kwargs):
        state["commands"].append(command)
        if command[:3] == ("pvesh", "get", "/cluster/nextid"):
            if "--vmid" in command:
                return result(code=int(state["collision"]))
            return result("200\n")
        if command[:2] == ("pvesm", "status"):
            storage = "local-lvm" if "rootdir" in command else "local"
            return result(
                f"Name Type Status Total Used Available %\n{storage} dir active 100 1 99 1%\n"
            )
        if command[:2] == ("pveam", "list"):
            volume = (
                "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst 200MB\n"
                if state["downloaded"]
                else ""
            )
            return result(volume)
        if command[:2] == ("pveam", "available"):
            return result("system debian-13-standard_13.1-1_amd64.tar.zst\n")
        if command[:2] == ("pveam", "download"):
            state["downloaded"] = True
        if command[:2] == ("pct", "create"):
            (config_dir / "200.conf").write_text("arch: amd64\nunprivileged: 0\n")
            if state["fail_create"]:
                raise subprocess.CalledProcessError(1, command, stderr="partial create")
        if (
            command[:2] == ("pct", "exec")
            and command[-1].endswith("install-debian.sh")
            and state["fail_installer"]
        ):
            raise subprocess.CalledProcessError(1, command, stderr="installer failed")
        return result()

    with patch.object(helper, "check_host"), patch.object(helper, "run", side_effect=fake_run):
        yield config_dir, bridge_root, state


def test_wrong_host_and_unsupported_architecture(tmp_path):
    with (
        patch.object(helper.os, "geteuid", return_value=0),
        pytest.raises(helper.PreflightError, match="PVE LXC"),
    ):
        helper.check_host(tmp_path / "missing")
    (tmp_path / "lxc").mkdir()
    with (
        patch.object(helper.os, "geteuid", return_value=0),
        patch.object(helper.platform, "machine", return_value="aarch64"),
        pytest.raises(helper.PreflightError, match="amd64"),
    ):
        helper.check_host(tmp_path / "lxc")
    with (
        patch.object(helper.os, "geteuid", return_value=0),
        patch.object(helper.platform, "machine", return_value="x86_64"),
        pytest.raises(helper.PreflightError, match="/dev/net/tun"),
    ):
        helper.check_host(tmp_path / "lxc", tmp_path / "missing-tun")


@pytest.mark.parametrize(
    "input_args",
    [
        ["--ctid", "99"],
        ["--hostname", "bad host"],
        ["--storage", "foo;rm"],
        ["--bridge", "$(id)"],
        ["--ip", "192.0.2.5/24"],
        ["--ip", "192.0.2.0/24", "--gateway", "192.0.2.1"],
        ["--ip", "192.0.2.5/24", "--gateway", "not-ip"],
        ["--ip", "dhcp", "--gateway", "192.0.2.1"],
        ["--vlan", "4095"],
        ["--ref", "main"],
        ["--ref", "v1.0.0;id"],
        ["--startup", "order=1;id"],
        ["--pool", "foo bar"],
        ["--dns", "invalid"],
    ],
)
def test_invalid_or_malicious_input_rejected(input_args):
    with pytest.raises(helper.PreflightError):
        helper.parse_args(input_args)


def test_default_selection_and_command_generation(pve):
    config_dir, bridge_root, state = pve
    ctid, template, commands, download = helper.plan(helper.parse_args([]), config_dir, bridge_root)
    assert (ctid, download) == (200, True)
    assert template == "local:vztmpl/debian-13-standard_13.1-1_amd64.tar.zst"
    assert commands[0][:2] == ["pveam", "download"]
    create = commands[1]
    assert create[:3] == ["pct", "create", "200"]
    assert create[create.index("--unprivileged") + 1] == "0"
    assert create[create.index("--rootfs") + 1] == "local-lvm:16"
    assert create[create.index("--net0") + 1] == "name=eth0,bridge=vmbr0,ip=dhcp,ip6=manual"
    assert create[create.index("--onboot") + 1] == "1"
    assert commands[-1][-1] == "/root/exitlane-source/installer/install-debian.sh"
    assert commands[-2][commands[-2].index("--branch") + 1] == "v0.3.0-rc.4"
    assert not any(command[:2] == ("pct", "destroy") for command in state["commands"])


def test_existing_pve_template_skips_download(pve):
    config_dir, bridge_root, state = pve
    state["downloaded"] = True
    _, template, commands, download = helper.plan(helper.parse_args([]), config_dir, bridge_root)
    assert template.endswith("debian-13-standard_13.1-1_amd64.tar.zst")
    assert download is False
    assert commands[0][:2] == ["pct", "create"]


def test_missing_pve_managed_template_is_refused():
    with (
        patch.object(
            helper,
            "run",
            side_effect=[result(""), result("system debian-12-standard_12.1-1_amd64.tar.zst\n")],
        ),
        pytest.raises(helper.PreflightError, match="No PVE-managed Debian 13"),
    ):
        helper.select_template("local")


def test_static_vlan_dns_pool_and_startup_rendered(pve):
    config_dir, bridge_root, _ = pve
    args = helper.parse_args(
        [
            "--ctid",
            "200",
            "--ip",
            "192.0.2.20/24",
            "--gateway",
            "192.0.2.1",
            "--dns",
            "192.0.2.53",
            "--vlan",
            "42",
            "--pool",
            "lab",
            "--startup",
            "order=2,up=30",
            "--cores",
            "4",
            "--memory",
            "4096",
            "--disk",
            "32",
        ]
    )
    _, _, commands, _ = helper.plan(args, config_dir, bridge_root)
    create = commands[1]
    assert create[create.index("--net0") + 1] == (
        "name=eth0,bridge=vmbr0,ip=192.0.2.20/24,ip6=manual,gw=192.0.2.1,tag=42"
    )
    for flag, value in (
        ("--nameserver", "192.0.2.53"),
        ("--pool", "lab"),
        ("--startup", "order=2,up=30"),
        ("--cores", "4"),
        ("--memory", "4096"),
        ("--rootfs", "local-lvm:32"),
    ):
        assert create[create.index(flag) + 1] == value


def test_collision_and_existing_config_refused(pve):
    config_dir, bridge_root, state = pve
    state["collision"] = True
    with pytest.raises(helper.PreflightError, match="already exists"):
        helper.plan(helper.parse_args([]), config_dir, bridge_root)
    state["collision"] = False
    (config_dir / "200.conf").touch()
    with pytest.raises(helper.PreflightError, match="existing"):
        helper.plan(helper.parse_args([]), config_dir, bridge_root)


def test_missing_storage_bridge_and_template_refused(pve):
    config_dir, bridge_root, _ = pve
    with pytest.raises(helper.PreflightError, match="rootdir"):
        helper.plan(helper.parse_args(["--storage", "missing"]), config_dir, bridge_root)
    with pytest.raises(helper.PreflightError, match="template capability"):
        helper.plan(helper.parse_args(["--template-storage", "missing"]), config_dir, bridge_root)
    with pytest.raises(helper.PreflightError, match="Bridge"):
        helper.plan(helper.parse_args(["--bridge", "vmbr9"]), config_dir, bridge_root)
    with (
        patch.object(helper, "select_template", side_effect=helper.PreflightError("No template")),
        pytest.raises(helper.PreflightError, match="No template"),
    ):
        helper.plan(helper.parse_args([]), config_dir, bridge_root)


def test_dry_run_has_no_mutation_and_quotes_preview(pve, capsys):
    config_dir, bridge_root, state = pve
    assert helper.main(["--dry-run"], config_dir, bridge_root) == 0
    output = capsys.readouterr().out
    assert "pveam download" in output and "Dry run: no resources changed" in output
    assert "CTID 200" in output
    assert not state["downloaded"]
    assert not (config_dir / "200.conf").exists()
    assert all(
        command[1] not in {"download", "create", "start", "exec"} for command in state["commands"]
    )


def test_creation_reuses_installer_and_adds_only_tun_lines(pve, capsys):
    config_dir, bridge_root, state = pve
    with patch.object(helper, "wait_ready", return_value="192.0.2.20"):
        assert helper.main(["--yes"], config_dir, bridge_root) == 0
    assert (config_dir / "200.conf").read_text().splitlines()[-2:] == list(helper.TUN_LINES)
    assert any(command[:2] == ("pct", "create") for command in state["commands"])
    assert any(
        command[:2] == ("pct", "exec") and command[-1].endswith("install-debian.sh")
        for command in state["commands"]
    )
    assert "http://192.0.2.20:8787" in capsys.readouterr().out


def test_quiet_automation_executes_frozen_plan(pve, capsys):
    config_dir, bridge_root, state = pve
    with patch.object(helper, "wait_ready", return_value="192.0.2.20"):
        assert helper.main(["--yes", "--output", "quiet"], config_dir, bridge_root) == 0
    assert (config_dir / "200.conf").exists()
    assert sum(command[:2] == ("pct", "create") for command in state["commands"]) == 1
    assert "Planned operations" not in capsys.readouterr().out


def test_installer_failure_retains_created_ct(pve, capsys):
    config_dir, bridge_root, state = pve
    state["fail_installer"] = True
    with (
        patch.object(helper, "wait_ready", return_value="192.0.2.20"),
        pytest.raises(subprocess.CalledProcessError),
    ):
        helper.main(["--yes"], config_dir, bridge_root)
    assert (config_dir / "200.conf").exists()
    assert "was not deleted" in capsys.readouterr().err
    assert not any(command[:2] == ("pct", "destroy") for command in state["commands"])


def test_interrupted_creation_retains_ct(pve, capsys):
    config_dir, bridge_root, state = pve
    with (
        patch.object(helper, "wait_ready", side_effect=KeyboardInterrupt),
        pytest.raises(KeyboardInterrupt),
    ):
        helper.main(["--yes"], config_dir, bridge_root)
    assert (config_dir / "200.conf").exists()
    assert "was not deleted" in capsys.readouterr().err
    assert not any(command[:2] == ("pct", "destroy") for command in state["commands"])


def test_failed_pct_create_warns_and_preserves_partial_config(pve, capsys):
    config_dir, bridge_root, state = pve
    state["fail_create"] = True
    with pytest.raises(subprocess.CalledProcessError):
        helper.main(["--yes"], config_dir, bridge_root)
    assert (config_dir / "200.conf").exists()
    assert "partially allocated" in capsys.readouterr().err
    assert not any(command[:2] == ("pct", "destroy") for command in state["commands"])


def test_readiness_has_one_monotonic_deadline():
    clock = [0.0]
    timeouts = []

    def slow_run(*command, **kwargs):
        timeouts.append(kwargs["timeout"])
        clock[0] += min(4.0, kwargs["timeout"])
        return result("status: running\n" if command[:2] == ("pct", "status") else "", code=1)

    with (
        patch.object(helper, "run", side_effect=slow_run),
        patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]),
        patch.object(
            helper.time,
            "sleep",
            side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        ),
        pytest.raises(helper.PreflightError, match="within 10s"),
    ):
        helper.wait_ready(200, timeout_seconds=10, interval=2)
    assert clock[0] == 10
    assert timeouts == [5, 4]


def test_readiness_requires_running_tun_dns_and_ipv4():
    observations = []

    def ready_run(*command, **_kwargs):
        observations.append(command)
        if command[:2] == ("pct", "status"):
            return result("status: running\n")
        if command[-1] == "-I":
            return result("192.0.2.20 2001:db8::20\n")
        if command[-1] == "default":
            return result("default via 192.0.2.1 dev eth0\n")
        if command[-1] == "/etc/resolv.conf" and "cat" in command:
            return result("nameserver 172.16.0.12\n")
        if "ahostsv4" in command:
            return result("192.0.2.10 STREAM answer\n")
        return result()

    with patch.object(helper, "run", side_effect=ready_run):
        assert helper.wait_ready(200, timeout_seconds=1, interval=0) == "192.0.2.20"
    assert any(command[-3:] == ("test", "-c", "/dev/net/tun") for command in observations)
    assert any(command[-2:] == ("ahostsv4", "github.com") for command in observations)


@pytest.mark.parametrize(
    "failure",
    ["permanent", "first-only", "intermittent", "debian", "github", "route", "access", "empty"],
)
def test_readiness_rejects_false_positive_and_reports_facts(failure):
    clock = [0.0]
    rounds = [0]
    observations = []

    def fake_run(*command, **kwargs):
        observations.append(command)
        assert 0 < kwargs["timeout"] <= 5
        if command[:2] == ("pct", "status"):
            rounds[0] += 1
            return result("status: running\n")
        if command[-1] == "-I":
            return result("192.0.2.20\n")
        if command[-1] == "default":
            return result("" if failure == "route" else "default via 192.0.2.1 dev eth0\n")
        if "cat" in command:
            return result("nameserver 172.16.0.12\nnameserver 172.16.0.4\n")
        if "-r" in command:
            return result(code=int(failure == "access"))
        if "ahostsv4" in command:
            assert command[4:8] == ("runuser", "-u", "_apt", "--")
            fails = (
                failure == "permanent"
                or failure == "first-only"
                and rounds[0] > 1
                or failure == "intermittent"
                and rounds[0] % 2 == 0
                or failure == "debian"
                and command[-1] == "deb.debian.org"
                or failure == "github"
                and command[-1] == "github.com"
            )
            return result("" if failure == "empty" else "192.0.2.10 STREAM answer\n", int(fails))
        return result()

    with (
        patch.object(helper, "run", side_effect=fake_run),
        patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]),
        patch.object(
            helper.time,
            "sleep",
            side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        ),
        pytest.raises(helper.PreflightError) as error,
    ):
        helper.wait_ready(200, timeout_seconds=7)
    assert clock[0] == 7
    assert rounds[0] == 4
    text = str(error.value)
    for fact in (
        "CTID 200",
        "192.0.2.20",
        "172.16.0.12",
        "_apt DNS",
        "Guest preserved",
        "pct config 200",
    ):
        assert fact in text
    assert not any("apt-get" in command for command in observations)


def test_readiness_requires_two_complete_stable_rounds_after_failure():
    clock = [0.0]
    rounds = [0]
    dns_calls = []

    def fake_run(*command, **_kwargs):
        if command[:2] == ("pct", "status"):
            rounds[0] += 1
            return result("status: running\n")
        if command[-1] == "-I":
            return result("192.0.2.20\n")
        if command[-1] == "default":
            return result("default via 192.0.2.1 dev eth0\n")
        if "cat" in command:
            return result("nameserver 172.16.0.12\n")
        if "ahostsv4" in command:
            dns_calls.append((rounds[0], command[-1]))
            return result(
                "192.0.2.10 STREAM answer\n",
                int(rounds[0] == 2 and command[-1] == "security.debian.org"),
            )
        return result()

    with (
        patch.object(helper, "run", side_effect=fake_run),
        patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]),
        patch.object(
            helper.time,
            "sleep",
            side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        ),
    ):
        assert helper.wait_ready(200, timeout_seconds=10) == "192.0.2.20"
    assert rounds[0] == 4
    assert len(dns_calls) == 12


def test_readiness_failure_preserves_guest_before_packages(pve, capsys):
    config_dir, bridge_root, state = pve
    with (
        patch.object(
            helper, "wait_ready", side_effect=helper.PreflightError("_apt DNS unavailable")
        ),
        pytest.raises(helper.PreflightError, match="_apt DNS"),
    ):
        helper.main(["--yes"], config_dir, bridge_root)
    assert (config_dir / "200.conf").exists()
    assert "not deleted" in capsys.readouterr().err
    assert not any(
        "apt-get" in command or command[:2] == ("pct", "destroy") for command in state["commands"]
    )


def test_apt_update_error_is_hard_failure_with_bounded_retries(pve, capsys):
    config_dir, bridge_root, state = pve
    original_run = helper.run

    def fail_update(*command, **kwargs):
        if "apt-get" in command and command[-1] == "update":
            assert "APT::Update::Error-Mode=any" in command
            assert "Acquire::Retries=2" in command
            raise subprocess.CalledProcessError(100, command, stderr="repository fetch failed")
        return original_run(*command, **kwargs)

    with (
        patch.object(helper, "run", side_effect=fail_update),
        patch.object(helper, "wait_ready", return_value="192.0.2.20"),
        pytest.raises(subprocess.CalledProcessError) as error,
    ):
        helper.main(["--yes"], config_dir, bridge_root)
    assert error.value.returncode == 100
    assert (config_dir / "200.conf").exists()
    assert "not deleted" in capsys.readouterr().err
    assert not any("install" in command or "clone" in command for command in state["commands"])


def test_run_does_not_inherit_restrictive_caller_umask():
    with patch.object(helper.subprocess, "run", return_value=result()) as execute:
        helper.run("pct", "create", "200")
    assert execute.call_args.kwargs["umask"] == 0o022


def test_real_child_umask_keeps_parent_private(tmp_path):
    target = tmp_path / "pve-generated.conf"
    previous = helper.os.umask(0o077)
    try:
        helper.run(
            "python3",
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('public configuration')",
            str(target),
        )
        assert target.stat().st_mode & 0o777 == 0o644
        assert helper.os.umask(0o077) == 0o077
        assert tmp_path.stat().st_mode & 0o777 == 0o700
    finally:
        helper.os.umask(previous)


def test_readiness_probe_timeout_is_bounded_and_diagnostic():
    clock = [0.0]

    def timed_out(*command, **kwargs):
        clock[0] += kwargs["timeout"]
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    with (
        patch.object(helper, "run", side_effect=timed_out),
        patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]),
        pytest.raises(helper.PreflightError, match="running: timed out"),
    ):
        helper.wait_ready(200, timeout_seconds=3)
    assert clock[0] == 3


def test_confirmation_cancellation_has_no_mutation(pve):
    config_dir, bridge_root, state = pve
    with (
        patch.object(helper.sys.stdin, "isatty", return_value=True),
        patch("builtins.input", return_value="n"),
        pytest.raises(helper.PreflightError, match="cancelled"),
    ):
        helper.main([], config_dir, bridge_root)
    assert not state["downloaded"]
    assert not (config_dir / "200.conf").exists()


def test_storage_change_after_confirmation_fails_closed(pve):
    config_dir, bridge_root, state = pve
    original = helper.active_storages
    calls = [0]

    def storages(content):
        calls[0] += 1
        if calls[0] > 2 and content == "rootdir":
            return []
        return original(content)

    with (
        patch.object(helper, "active_storages", side_effect=storages),
        pytest.raises(helper.PreflightError, match="rootdir"),
    ):
        helper.main(["--yes"], config_dir, bridge_root)
    assert not state["downloaded"]
    assert not (config_dir / "200.conf").exists()


def test_collision_during_template_download_refuses_creation(pve):
    config_dir, bridge_root, state = pve
    original = helper.run

    def run(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[:2] == ("pveam", "download"):
            state["collision"] = True
        return result

    with (
        patch.object(helper, "run", side_effect=run),
        pytest.raises(helper.PreflightError, match="already exists"),
    ):
        helper.main(["--yes"], config_dir, bridge_root)
    assert not any(command[:2] == ("pct", "create") for command in state["commands"])


def test_explicit_release_reaches_guest_clone(pve):
    config_dir, bridge_root, state = pve
    with patch.object(helper, "wait_ready", return_value="192.0.2.20"):
        helper.main(["--yes", "--ref", "v1.2.3-rc.4"], config_dir, bridge_root)
    clone = next(command for command in state["commands"] if "clone" in command)
    assert clone[clone.index("--branch") + 1] == "v1.2.3-rc.4"
