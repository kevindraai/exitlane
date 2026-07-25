import subprocess
from pathlib import Path

from exitlane.services import network_security

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "installer" / "install-debian.sh"
DEFAULTS = ROOT / "installer" / "exitlane.default"


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
    assert "commit_upgrade" in installer
    assert 'readonly PACKAGE_VERSION="0.2.0b1"' in installer
    assert 'dpkg --compare-versions "${CURRENT_VERSION}" gt "${PACKAGE_VERSION}"' in installer
    assert installer.index("prepare_upgrade_recovery") < installer.index("stop_existing_service")
    assert installer.index("stop_existing_service") < installer.index("copy_application")


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
