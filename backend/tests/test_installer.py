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
    assert "source.backup(destination)" in installer
    assert "prepare_upgrade_recovery" in installer
    assert "rollback_upgrade" in installer
    assert 'cp -a "${RECOVERY_DIR}/files/." /' not in installer
    assert 'cp -a "${top_level}/." "/$(basename "${top_level}")/"' not in installer
    assert 'restore_recovery_files "${RECOVERY_DIR}/files" /' in installer
    assert "commit_upgrade" in installer
    assert 'readonly PACKAGE_VERSION="0.2.0b2"' in installer
    assert 'dpkg --compare-versions "${CURRENT_VERSION}" gt "${PACKAGE_VERSION}"' in installer
    assert installer.index("prepare_upgrade_recovery") < installer.index("stop_existing_service")
    assert installer.index("stop_existing_service") < installer.index("copy_application")


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
    assert "'hostname -I" not in deploy
    assert 'sudo bash "${REMOTE_DIR}installer/install-debian.sh"' in deploy
    assert "install-exitlane-candidate" not in deploy
    assert deploy.index("EXPECTED_TEST_IP") < deploy.index("rsync -az")
    assert "Refusing deployment" in deploy


def test_recovery_file_restore_preserves_top_level_directory_modes(tmp_path):
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
    command = f"source {INSTALLER}; restore_recovery_files {recovery} {target}"

    subprocess.run(["bash", "-c", command], check=True)

    assert (target / "etc").stat().st_mode & 0o777 == 0o755
    assert (target / "opt").stat().st_mode & 0o777 == 0o755
    assert (target / "etc" / "exitlane" / "setting").read_text(encoding="utf-8") == "preserved"
    assert (target / "opt" / "exitlane" / "version").read_text(encoding="utf-8") == "beta"
