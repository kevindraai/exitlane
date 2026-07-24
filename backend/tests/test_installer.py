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
