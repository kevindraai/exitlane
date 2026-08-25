import subprocess
from pathlib import Path

from exitlane.services import network_security

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "installer" / "install-debian.sh"
DEFAULTS = ROOT / "installer" / "exitlane.default"
DEPLOY_SCRIPT = ROOT / "scripts" / "deploy_worktree_to_test.sh"


def test_new_installer_defaults_omit_optional_reverse_proxy_environment_variables():
    defaults = DEFAULTS.read_text(encoding="utf-8")

    for environment in network_security.ENVIRONMENT_KEYS.values():
        assert environment not in defaults


def test_installer_creates_new_defaults_and_preserves_existing_installation(tmp_path):
    target = tmp_path / "exitlane.default"
    command = f"source {INSTALLER}; install_defaults_file {DEFAULTS} {target}"

    subprocess.run(["bash", "-c", command], check=True)
    assert target.read_text(encoding="utf-8") == DEFAULTS.read_text(encoding="utf-8")
    assert target.stat().st_mode & 0o777 == 0o600

    target.write_text("EXISTING_CONFIGURATION=preserved\n", encoding="utf-8")
    subprocess.run(["bash", "-c", command], check=True)
    assert target.read_text(encoding="utf-8") == "EXISTING_CONFIGURATION=preserved\n"


def test_installer_has_locked_upgrade_snapshot_and_rollback_contract():
    installer = INSTALLER.read_text(encoding="utf-8")

    assert 'flock -n "${LOCK_FD}"' in installer
    assert "snapshot_sqlite_database" in installer
    assert "snapshot_system_timezone" in installer
    assert "timedatectl show --property=Timezone --value" in installer
    assert "restore_system_timezone" in installer
    assert 'timedatectl set-timezone "${timezone}"' in installer
    assert "source.backup(destination)" in installer
    assert "prepare_upgrade_recovery" in installer
    assert "rollback_upgrade" in installer
    assert 'cp -a "${RECOVERY_DIR}/files/." /' not in installer
    assert 'cp -a "${top_level}/." "/$(basename "${top_level}")/"' not in installer
    assert (
        'restore_recovery_files "${RECOVERY_DIR}/files" "${RECOVERY_DIR}/path-state" /' in installer
    )
    assert "snapshot_recovery_path" in installer
    assert 'rm -rf -- "${destination}"' in installer
    assert "commit_upgrade" in installer
    assert 'readonly PACKAGE_VERSION="0.2.0rc1"' in installer
    assert 'dpkg --compare-versions "${CURRENT_VERSION}" gt "${PACKAGE_VERSION}"' in installer
    assert installer.index("prepare_upgrade_recovery") < installer.index("stop_existing_service")
    assert installer.index("stop_existing_service") < installer.index("copy_application")


def test_installer_includes_wireguard_firewall_runtime():
    installer = INSTALLER.read_text(encoding="utf-8")

    assert "    iptables \\\n" in installer
    assert "    nftables \\\n" in installer
    assert "    procps \\\n" in installer
    assert 'install -d -m 0755 "$(dirname "${IP_FORWARDING_TARGET}")"' in installer


def test_installer_supports_only_debian_13_amd64():
    installer = INSTALLER.read_text(encoding="utf-8")

    assert '"${VERSION_ID:-}" != "13"' in installer
    assert '"$(dpkg --print-architecture)" != "amd64"' in installer
    assert installer.count("This release supports Debian 13 on amd64 only.") == 2
    assert "12|13" not in installer
    assert "Use Debian 12 or 13" not in installer


def test_installer_user_visible_output_is_english():
    installer = INSTALLER.read_text(encoding="utf-8")

    assert "ExitLane installation failed." in installer
    assert "Clean ExitLane installation detected" in installer
    assert "ExitLane service is running" in installer
    assert "ExitLane ${INSTALLER_VERSION} is installed" in installer
    for dutch_text in (
        "installatie mislukt",
        "gedetecteerd",
        "geïnstalleerd",
        "ontbreekt",
        "Voer dit installatiescript",
        "Volgende stap",
    ):
        assert dutch_text not in installer


def test_alpha_package_version_is_not_classified_as_newer_than_beta():
    subprocess.run(
        ["dpkg", "--compare-versions", "0.2.0a1", "lt", "0.2.0b1"],
        check=True,
    )


def test_explicit_installer_failure_invokes_upgrade_rollback(tmp_path):
    marker = tmp_path / "rollback-called"
    command = (
        f"source {INSTALLER}; "
        "UPGRADE_MODE=1; UPGRADE_COMMITTED=0; RECOVERY_DIR=/tmp/recovery-test; "
        f"rollback_upgrade() {{ printf rolled-back > {marker}; }}; "
        "fail injected-test-failure"
    )

    result = subprocess.run(["bash", "-c", command], check=False, capture_output=True, text=True)

    assert result.returncode == 1
    assert marker.read_text(encoding="utf-8") == "rolled-back"


def test_deploy_script_fails_closed_on_unexpected_lxc_identity():
    deploy = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert 'HOST="${EXITLANE_TEST_HOST:-exitlane-reference}"' in deploy
    assert 'EXPECTED_TEST_IP="${EXITLANE_TEST_IP:-172.16.130.81}"' in deploy
    assert 'REMOTE_IPS="$(ssh "$HOST" hostname -I)"' in deploy
    assert 'grep -Fx -- "$EXPECTED_TEST_IP"' in deploy
    assert 'mktemp -d "${REMOTE_BASE}/exitlane-candidate.XXXXXXXX"' in deploy
    assert '[[ ! "$REMOTE_DIR" =~ ^/home/exitlane-test/exitlane-candidate\\.' in deploy
    assert 'ssh "$HOST" rm -rf -- "$REMOTE_DIR"' in deploy
    assert "chown -R" not in deploy
    assert '--exclude ".codex/"' in deploy
    assert "'hostname -I" not in deploy
    assert 'sudo bash "${REMOTE_DIR}/installer/install-debian.sh"' in deploy
    assert "install-exitlane-candidate" not in deploy
    assert deploy.index("EXPECTED_TEST_IP") < deploy.index("rsync -az")
    assert "Refusing deployment" in deploy


def test_recovery_file_restore_preserves_parent_directory_modes(tmp_path):
    recovery = tmp_path / "recovery"
    target = tmp_path / "target"
    (recovery / "etc" / "exitlane").mkdir(parents=True, mode=0o700)
    (recovery / "opt" / "exitlane").mkdir(parents=True, mode=0o700)
    (recovery / "etc").chmod(0o700)
    (recovery / "opt").chmod(0o700)
    (recovery / "etc" / "exitlane" / "setting").write_text("preserved", encoding="utf-8")
    (recovery / "opt" / "exitlane" / "version").write_text("beta", encoding="utf-8")
    (target / "etc").mkdir(parents=True, mode=0o755)
    (target / "opt").mkdir(parents=True, mode=0o755)
    state = tmp_path / "path-state"
    state.write_text("present|/etc/exitlane\npresent|/opt/exitlane\n", encoding="utf-8")
    command = f"source {INSTALLER}; restore_recovery_files {recovery} {state} {target}"

    subprocess.run(["bash", "-c", command], check=True)

    assert (target / "etc").stat().st_mode & 0o777 == 0o755
    assert (target / "opt").stat().st_mode & 0o777 == 0o755
    assert (target / "etc" / "exitlane" / "setting").read_text(encoding="utf-8") == "preserved"
    assert (target / "opt" / "exitlane" / "version").read_text(encoding="utf-8") == "beta"


def test_rollback_restores_exact_prior_paths_and_removes_candidate_only_paths(tmp_path):
    recovery = tmp_path / "recovery"
    files = recovery / "files"
    target = tmp_path / "target"
    state = recovery / "path-state"

    saved_paths = {
        "/opt/exitlane": ("version", "previous"),
        "/etc/exitlane": ("setting", "preserved"),
        "/etc/default/exitlane": (None, "EXISTING_CONFIGURATION=preserved\n"),
        "/usr/local/libexec/exitlane-install-nordvpn": (None, "previous provider helper\n"),
        "/etc/systemd/system/exitlane-provider-install-nordvpn.service": (None, "previous unit\n"),
    }
    for absolute_path, (child, contents) in saved_paths.items():
        saved = files / absolute_path.lstrip("/")
        if child is None:
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_text(contents, encoding="utf-8")
        else:
            saved.mkdir(parents=True, exist_ok=True)
            (saved / child).write_text(contents, encoding="utf-8")

    state.write_text(
        "present|/opt/exitlane\n"
        "present|/etc/exitlane\n"
        "present|/etc/default/exitlane\n"
        "present|/usr/local/libexec/exitlane-install-nordvpn\n"
        "present|/etc/systemd/system/exitlane-provider-install-nordvpn.service\n"
        "absent|/usr/local/libexec/exitlane-install-speedtest\n"
        "absent|/etc/systemd/system/exitlane-speedtest-install.service\n",
        encoding="utf-8",
    )

    for relative_path, contents in {
        "opt/exitlane/version": "candidate",
        "opt/exitlane/candidate-only": "remove",
        "etc/exitlane/setting": "candidate",
        "etc/default/exitlane": "candidate\n",
        "usr/local/libexec/exitlane-install-nordvpn": "candidate provider helper\n",
        "usr/local/libexec/exitlane-install-speedtest": "candidate speedtest helper\n",
        "etc/systemd/system/exitlane-provider-install-nordvpn.service": "candidate unit\n",
        "etc/systemd/system/exitlane-speedtest-install.service": "candidate speedtest unit\n",
        "var/lib/exitlane/exitlane.db": "preserve data",
        "etc/wireguard/wg0.conf": "preserve wireguard",
    }.items():
        live = target / relative_path
        live.parent.mkdir(parents=True, exist_ok=True)
        live.write_text(contents, encoding="utf-8")

    command = f"source {INSTALLER}; restore_recovery_files {files} {state} {target}"
    subprocess.run(["bash", "-c", command], check=True)

    assert (target / "opt/exitlane/version").read_text(encoding="utf-8") == "previous"
    assert not (target / "opt/exitlane/candidate-only").exists()
    assert (target / "etc/exitlane/setting").read_text(encoding="utf-8") == "preserved"
    assert (target / "etc/default/exitlane").read_text(
        encoding="utf-8"
    ) == "EXISTING_CONFIGURATION=preserved\n"
    assert (target / "usr/local/libexec/exitlane-install-nordvpn").read_text(
        encoding="utf-8"
    ) == "previous provider helper\n"
    assert not (target / "usr/local/libexec/exitlane-install-speedtest").exists()
    assert (target / "etc/systemd/system/exitlane-provider-install-nordvpn.service").read_text(
        encoding="utf-8"
    ) == "previous unit\n"
    assert not (target / "etc/systemd/system/exitlane-speedtest-install.service").exists()
    assert (target / "var/lib/exitlane/exitlane.db").read_text(encoding="utf-8") == "preserve data"
    assert (target / "etc/wireguard/wg0.conf").read_text(encoding="utf-8") == "preserve wireguard"
