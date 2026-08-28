import hashlib
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "installer" / "install-mullvad.sh"
INSTALLER = ROOT / "installer" / "install-debian.sh"
UNIT = ROOT / "systemd" / "exitlane-provider-install-mullvad.service"
EARLY_BOOT_DROPIN = (
    ROOT / "systemd" / "mullvad-early-boot-blocking.service.d" / "exitlane.conf"
)
DAEMON_DROPIN = ROOT / "systemd" / "mullvad-daemon.service.d" / "exitlane.conf"
LIVE_TEST = ROOT / "scripts" / "test_mullvad_package_lifecycle.sh"


def test_mullvad_helper_and_unit_are_shipped_with_safe_modes():
    assert HELPER.is_file()
    assert UNIT.is_file()
    assert HELPER.stat().st_mode & 0o777 == 0o755
    assert UNIT.stat().st_mode & 0o777 == 0o644
    assert EARLY_BOOT_DROPIN.stat().st_mode & 0o777 == 0o644
    assert DAEMON_DROPIN.stat().st_mode & 0o777 == 0o644
    assert LIVE_TEST.stat().st_mode & 0o777 == 0o755
    subprocess.run(["bash", "-n", str(HELPER)], check=True)
    subprocess.run(["bash", "-n", str(LIVE_TEST)], check=True)
    subprocess.run(["shellcheck", str(HELPER)], check=True)
    subprocess.run(["shellcheck", str(LIVE_TEST)], check=True)


def test_helper_uses_only_official_stable_apt_repository_with_pinned_key():
    helper = HELPER.read_text(encoding="utf-8")
    assert 'KEY_URL="https://repository.mullvad.net/deb/mullvad-keyring.asc"' in helper
    assert 'REPOSITORY_URL="https://repository.mullvad.net/deb/stable"' in helper
    assert (
        'INRELEASE_URL="https://repository.mullvad.net/deb/stable/dists/stable/InRelease"' in helper
    )
    assert 'KEY_FINGERPRINT="A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF"' in helper
    assert "signed-by=${KEYRING_TARGET}" in helper
    assert "gpgv --keyring" in helper
    assert "primary_fingerprints" in helper
    assert "want_fingerprint" in helper
    assert "/beta" not in helper
    assert " beta " not in helper
    assert "trusted=yes" not in helper
    assert "apt-key" not in helper
    assert "curl |" not in helper
    assert "curl --fail --silent --show-error --location" in helper


def test_helper_is_fixed_input_idempotent_and_has_bounded_readiness():
    helper = HELPER.read_text(encoding="utf-8")
    assert '[[ "$#" -eq 0 ]]' in helper
    assert '"${VERSION_ID:-}" == "13"' in helper
    assert '"$(dpkg --print-architecture)" == "amd64"' in helper
    assert "if ! command -v mullvad" not in helper
    assert helper.index("prepare_repository") < helper.index("apt-get update -qq")
    assert "apt-get install --reinstall -y -qq mullvad-vpn" in helper
    assert "SYSTEMD_OFFLINE=1 DEBIAN_FRONTEND=noninteractive" in helper
    assert "dpkg --configure -a" in helper
    assert "prepare_systemctl_guard" not in helper
    assert 'guard_path="${guard_dir}/systemctl"' not in helper
    assert "systemctl enable --now mullvad-daemon" not in helper
    assert 'systemctl start "${DAEMON_UNIT}"' in helper
    assert "mullvad status --json" in helper
    assert "provider_command lan set allow" in helper
    assert "provider_command lockdown-mode set off" in helper
    assert "provider_command auto-connect set off" in helper
    assert "provider_command disconnect" in helper
    assert "provider_authenticated" in helper
    assert "mullvad account get 2>/dev/null |" in helper
    assert 'value = bytearray(4096)' in helper
    assert 'value[:] = b"\\0" * len(value)' in helper
    assert 'b"Mullvad account:" in value' in helper
    assert "provider_command tunnel set ipv6 off" in helper
    assert "provider_command split-tunnel clear" in helper
    assert helper.index("if provider_authenticated; then") < helper.index(
        "provider_command tunnel set ipv6 off"
    )
    assert helper.index("wait_for_provider\n  apply_gateway_settings") < helper.index(
        'set_phase "validating_installation"'
    )
    assert "PROVIDER_READY_TIMEOUT_SECONDS=45" in helper
    assert 'flock -n "${PACKAGE_LOCK_FD}"' in helper
    assert "/run/lock/exitlane-package-operation.lock" in helper
    assert "eval " not in helper
    assert "shell=True" not in helper
    assert "account login" not in helper
    assert "account_number" not in helper
    assert "ACCOUNT_NUMBER" not in helper
    for phase in (
        "checking_system",
        "preparing_repository",
        "verifying_repository",
        "refreshing_packages",
        "installing_client",
        "starting_daemon",
        "waiting_for_provider",
        "applying_gateway_settings",
        "validating_installation",
    ):
        assert phase in helper
    for code in ("64", "65", "66", "67", "68", "69", "75", "77"):
        assert f"die {code} " in helper


def test_package_time_services_and_early_boot_firewall_are_suppressed_by_two_boundaries():
    helper = HELPER.read_text(encoding="utf-8")
    early_dropin = EARLY_BOOT_DROPIN.read_text(encoding="utf-8")
    daemon_dropin = DAEMON_DROPIN.read_text(encoding="utf-8")

    assert (
        "ConditionPathExists=/run/exitlane-provider-install/"
        "mullvad-early-boot-blocking-allowed"
    ) in early_dropin
    assert "mullvad-early-boot-blocking-allowed" not in helper.replace(
        '"ConditionPathExists=/run/exitlane-provider-install/'
        'mullvad-early-boot-blocking-allowed"',
        "",
    )
    assert (
        "ConditionPathExists=|/run/exitlane-provider-install/mullvad-daemon-start-allowed"
        in daemon_dropin
    )
    assert (
        "ConditionPathExists=|/etc/exitlane/mullvad-installation-complete" in daemon_dropin
    )
    assert "verify_service_suppression_files" in helper
    assert "verify_package_service_state" in helper
    assert 'systemctl is-active --quiet "${EARLY_BOOT_UNIT}"' in helper
    assert "mullvad_firewall_table_present" in helper
    assert "nft delete" not in helper
    assert "nft flush" not in helper

    main = helper[helper.index("main() {") :]
    offline_install = "SYSTEMD_OFFLINE=1 DEBIAN_FRONTEND=noninteractive"
    assert main.index("verify_service_suppression_files") < main.index(offline_install)
    assert main.index("prepare_provider_for_package_transaction") < main.index(offline_install)
    assert main.index(offline_install) < main.index("verify_package_service_state")
    assert main.index("repair_interrupted_package_transaction") < main.index(
        "apt-get install --reinstall -y -qq mullvad-vpn"
    )
    assert main.index("verify_package_service_state") < main.index(
        "start_provider_under_exitlane_control"
    )
    controlled_start = helper[
        helper.index("start_provider_under_exitlane_control()") : helper.index(
            "prepare_repository()"
        )
    ]
    assert controlled_start.index(
        'install -o root -g root -m 0600 /dev/null "${CONTROLLED_START_MARKER}"'
    ) < controlled_start.index('systemctl start "${DAEMON_UNIT}"')
    assert controlled_start.index('systemctl start "${DAEMON_UNIT}"') < controlled_start.rindex(
        'rm -f -- "${CONTROLLED_START_MARKER}"'
    )
    assert main.index('set_phase "validating_installation"') < main.index(
        'install -o root -g root -m 0600 /dev/null "${INSTALLATION_COMPLETE_MARKER}"'
    )


def test_dropin_digests_are_pinned_by_the_root_helper():
    helper = HELPER.read_text(encoding="utf-8")
    for path, variable in (
        (EARLY_BOOT_DROPIN, "EARLY_BOOT_DROPIN_SHA256"),
        (DAEMON_DROPIN, "DAEMON_DROPIN_SHA256"),
    ):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert f'readonly {variable}="{digest}"' in helper


def test_incident_model_requires_offline_transaction_and_permanent_early_boot_condition():
    def package_transaction(*, systemd_offline: bool, early_boot_condition_allows: bool):
        daemon_active = False
        early_boot_active = False
        mullvad_blocking_table = False
        # Mullvad 2026.4 postinst enables both units and asks systemd to start the daemon.
        if not systemd_offline:
            daemon_active = True
            if early_boot_condition_allows:
                early_boot_active = True
                mullvad_blocking_table = True
        return daemon_active, early_boot_active, mullvad_blocking_table

    assert package_transaction(systemd_offline=False, early_boot_condition_allows=True) == (
        True,
        True,
        True,
    )
    assert package_transaction(systemd_offline=True, early_boot_condition_allows=False) == (
        False,
        False,
        False,
    )


def test_live_reinstall_regression_monitors_every_package_time_network_mutation():
    script = LIVE_TEST.read_text(encoding="utf-8")

    assert "EXITLANE_MULLVAD_LIVE_TEST" in script
    assert "I_ACCEPT_DISPOSABLE_TEST_MUTATION" in script
    assert "SYSTEMD_OFFLINE=1 DEBIAN_FRONTEND=noninteractive" in script
    assert "apt-get install --reinstall -y -qq mullvad-vpn" in script
    assert 'systemctl is-active --quiet "${DAEMON_UNIT}"' in script
    assert 'systemctl is-active --quiet "${EARLY_BOOT_UNIT}"' in script
    assert "firewall_table_present" in script
    assert '[[ ! -e "${monitor_dir}/daemon-active" ]]' in script
    assert '[[ ! -e "${monitor_dir}/early-active" ]]' in script
    assert '[[ ! -e "${monitor_dir}/firewall-table" ]]' in script
    assert '"${HELPER}"' in script
    assert "nft delete" not in script
    assert "nft flush" not in script


def test_systemd_unit_runs_only_the_root_owned_fixed_helper():
    unit = UNIT.read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/libexec/exitlane-install-mullvad" in unit
    assert "Type=oneshot" in unit
    assert "TimeoutStartSec=5min" in unit
    assert "UMask=0077" in unit
    assert "Environment=HOME=/run/exitlane-provider-install" in unit
    assert "PrivateTmp=true" in unit
    assert "RestrictSUIDSGID=false" in unit
    assert "mullvad-exclude" in unit
    assert "ProtectHome=true" in unit
    assert "bash -c" not in unit


def test_main_installer_validates_installs_snapshots_and_rolls_back_mullvad_files():
    installer = INSTALLER.read_text(encoding="utf-8")
    expected = (
        "MULLVAD_HELPER_SOURCE",
        "MULLVAD_HELPER_TARGET",
        "MULLVAD_INSTALL_SERVICE_SOURCE",
        "MULLVAD_INSTALL_SERVICE_TARGET",
        "MULLVAD_EARLY_BOOT_DROPIN_SOURCE",
        "MULLVAD_EARLY_BOOT_DROPIN_TARGET",
        "MULLVAD_DAEMON_DROPIN_SOURCE",
        "MULLVAD_DAEMON_DROPIN_TARGET",
    )
    for name in expected:
        assert name in installer
    assert '[[ -f "${MULLVAD_HELPER_SOURCE}" ]]' in installer
    assert '[[ -f "${MULLVAD_INSTALL_SERVICE_SOURCE}" ]]' in installer
    assert '[[ -f "${MULLVAD_EARLY_BOOT_DROPIN_SOURCE}" ]]' in installer
    assert '[[ -f "${MULLVAD_DAEMON_DROPIN_SOURCE}" ]]' in installer
    assert 'install -o root -g root -m 0755 "${MULLVAD_HELPER_SOURCE}"' in installer
    assert "    gpgv \\\n" in installer
    assert 'snapshot_recovery_path "${path}"' in installer
    assert '"${MULLVAD_HELPER_TARGET}"' in installer
    assert '"${MULLVAD_INSTALL_SERVICE_TARGET}"' in installer
    assert '"${MULLVAD_EARLY_BOOT_DROPIN_TARGET}"' in installer
    assert '"${MULLVAD_DAEMON_DROPIN_TARGET}"' in installer
    assert '"${MULLVAD_EARLY_BOOT_DROPIN_SOURCE}"' in installer
    assert '"${MULLVAD_DAEMON_DROPIN_SOURCE}"' in installer
    assert "apt-get install -y -qq mullvad-vpn" not in installer


def test_helper_contains_no_world_readable_temporary_or_credential_file_path():
    helper = HELPER.read_text(encoding="utf-8")
    assert 'work_dir="$(mktemp -d)"' in helper
    assert 'chmod 0700 "${work_dir}"' in helper
    assert "RuntimeDirectoryMode=0700" in UNIT.read_text(encoding="utf-8")
    assert not any(
        word in helper.casefold()
        for word in ("mullvad-account", "account-number", "credential-file")
    )
    assert os.access(HELPER, os.X_OK)
