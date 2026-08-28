#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly KEY_URL="https://repository.mullvad.net/deb/mullvad-keyring.asc"
readonly KEY_FINGERPRINT="A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF"
readonly INRELEASE_URL="https://repository.mullvad.net/deb/stable/dists/stable/InRelease"
readonly REPOSITORY_URL="https://repository.mullvad.net/deb/stable"
readonly KEYRING_TARGET="/usr/share/keyrings/mullvad-keyring.asc"
readonly SOURCE_TARGET="/etc/apt/sources.list.d/mullvad.list"
readonly PACKAGE_OPERATION_LOCK="/run/lock/exitlane-package-operation.lock"
readonly PHASE_FILE="/run/exitlane-provider-install/mullvad.phase"
readonly DAEMON_UNIT="mullvad-daemon.service"
readonly EARLY_BOOT_UNIT="mullvad-early-boot-blocking.service"
readonly EARLY_BOOT_DROPIN="/etc/systemd/system/${EARLY_BOOT_UNIT}.d/exitlane.conf"
readonly DAEMON_DROPIN="/etc/systemd/system/${DAEMON_UNIT}.d/exitlane.conf"
readonly EARLY_BOOT_DROPIN_SHA256="0011d34401ee536c0650920774e8af1f54054064fa766557c30571e52c2a67eb"
readonly DAEMON_DROPIN_SHA256="7994b692fb2e5313391ae0976a3d36528b50dba9ea3ab3ba74aba541bfddcb26"
readonly CONTROLLED_START_MARKER="/run/exitlane-provider-install/mullvad-daemon-start-allowed"
readonly INSTALLATION_COMPLETE_MARKER="/etc/exitlane/mullvad-installation-complete"
readonly PROVIDER_READY_TIMEOUT_SECONDS=45
readonly PROVIDER_CLI_TIMEOUT_SECONDS=3
readonly GATEWAY_SETTING_TIMEOUT_SECONDS=10

work_dir=""
current_phase="checking_system"
PACKAGE_LOCK_FD=""
managed_daemon_started=0
installation_completed=0

cleanup() {
  local exit_code=$?
  trap - EXIT
  rm -f -- "${CONTROLLED_START_MARKER}"
  if [[ "${exit_code}" -ne 0 && "${managed_daemon_started}" -eq 1 && \
    "${installation_completed}" -eq 0 ]]; then
    if ! systemctl stop "${DAEMON_UNIT}" >/dev/null 2>&1; then
      printf '%s\n' "warning: provider_daemon_cleanup_failed" >&2
    fi
    if ! systemctl stop "${EARLY_BOOT_UNIT}" >/dev/null 2>&1; then
      printf '%s\n' "warning: provider_early_boot_cleanup_failed" >&2
    fi
    if mullvad_firewall_table_present; then
      printf '%s\n' "warning: provider_firewall_cleanup_required" >&2
    fi
  fi
  if [[ -n "${work_dir:-}" && -d "${work_dir}" ]]; then
    if ! rm -rf -- "${work_dir}"; then
      printf '%s\n' "warning: provider_installation_cleanup_failed" >&2
    fi
  fi
  exit "${exit_code}"
}

trap cleanup EXIT

die() {
  local code="$1"
  local message="$2"
  printf 'failed|%s|%s\n' "${current_phase}" "${message}" >"${PHASE_FILE}" || true
  printf '%s\n' "${message}" >&2
  exit "${code}"
}

set_phase() {
  local phase="$1"
  case "${phase}" in
    checking_system|preparing_repository|verifying_repository|\
      refreshing_packages|installing_client|starting_daemon|\
      waiting_for_provider|applying_gateway_settings|validating_installation|completed|failed)
      current_phase="${phase}"
      printf '%s\n' "${phase}" >"${PHASE_FILE}"
      ;;
    *)
      die 68 "provider_installation_validation_failed"
      ;;
  esac
}

require_debian_13_amd64() {
  [[ -r /etc/os-release ]] || die 64 "unsupported_platform"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] ||
    die 64 "unsupported_platform"
  [[ "$(dpkg --print-architecture)" == "amd64" ]] || die 64 "unsupported_platform"
}

acquire_package_lock() {
  install -d -m 0755 /run/lock
  exec {PACKAGE_LOCK_FD}>"${PACKAGE_OPERATION_LOCK}"
  flock -n "${PACKAGE_LOCK_FD}" || die 75 "package_operation_in_progress"
}

mullvad_firewall_table_present() {
  nft list table inet mullvad >/dev/null 2>&1
}

management_network_ready() {
  ip -4 -o addr show scope global | awk 'NR == 1 {found=1} END {exit !found}' &&
    ip -4 route show default | grep -Eq '^default([[:space:]]|$)' &&
    ! mullvad_firewall_table_present
}

verify_managed_dropin() {
  local path="$1"
  local expected_sha256="$2"
  local file_state=""
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  file_state="$(stat -c '%U:%G:%a' "${path}" 2>/dev/null)" || return 1
  [[ "${file_state}" == "root:root:644" ]] || return 1
  printf '%s  %s\n' "${expected_sha256}" "${path}" | sha256sum --check --status
}

verify_service_suppression_files() {
  verify_managed_dropin "${EARLY_BOOT_DROPIN}" "${EARLY_BOOT_DROPIN_SHA256}" ||
    die 70 "provider_service_suppression_failed"
  verify_managed_dropin "${DAEMON_DROPIN}" "${DAEMON_DROPIN_SHA256}" ||
    die 70 "provider_service_suppression_failed"
}

provider_ready() {
  command -v mullvad >/dev/null 2>&1 || return 1
  [[ "$(systemctl show mullvad-daemon --property=LoadState --value 2>/dev/null)" == "loaded" ]] ||
    return 1
  systemctl is-active --quiet mullvad-daemon || return 1
  timeout --signal=TERM "${PROVIDER_CLI_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad status --json >/dev/null 2>&1
}

provider_disconnected() {
  local output
  output="$(timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad status --json 2>/dev/null)" || return 1
  python3 -c '
import json
import sys

try:
    value = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if isinstance(value, dict) and value.get("state") == "disconnected" else 1)
' <<<"${output}"
}

provider_authenticated() {
  timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad account get 2>/dev/null |
    python3 -c '
import sys

value = bytearray(4096)
try:
    sys.stdin.buffer.readinto(value)
    authenticated = b"Mullvad account:" in value
finally:
    value[:] = b"\0" * len(value)
raise SystemExit(0 if authenticated else 1)
'
}

wait_for_provider() {
  local attempt=0 delay_seconds deadline started_at
  set_phase "waiting_for_provider"
  started_at="${SECONDS}"
  deadline=$((SECONDS + PROVIDER_READY_TIMEOUT_SECONDS))
  printf '%s\n' "mullvad readiness: daemon active" >&2
  while ((SECONDS < deadline)); do
    attempt=$((attempt + 1))
    if provider_ready; then
      printf '%s\n' \
        "mullvad readiness: CLI ready attempts=${attempt} duration_seconds=$((SECONDS - started_at))" \
        >&2
      return 0
    fi
    case "${attempt}" in
      1) delay_seconds="0.25" ;;
      2) delay_seconds="0.5" ;;
      *) delay_seconds="1" ;;
    esac
    sleep "${delay_seconds}"
  done
  die 69 "provider_readiness_timeout"
}

provider_command() {
  timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad "$@" >/dev/null 2>&1
}

gateway_settings_ready() {
  local output
  output="$(timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad auto-connect get 2>/dev/null)" || return 1
  [[ "${output}" == "Autoconnect: off" ]] || return 1
  output="$(timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad lan get 2>/dev/null)" || return 1
  [[ "${output}" == "Local network sharing setting: allow" ]] || return 1
  output="$(timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
    env LC_ALL=C LANG=C mullvad lockdown-mode get 2>/dev/null)" || return 1
  [[ "${output}" == "Block traffic when the VPN is disconnected: off" ]] || return 1
  if provider_authenticated; then
    output="$(timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
      env LC_ALL=C LANG=C mullvad tunnel get 2>/dev/null)" || return 1
    grep -Fxq -- "IPv6: off" <<<"${output}" || return 1
    output="$(timeout --signal=TERM "${GATEWAY_SETTING_TIMEOUT_SECONDS}" \
      env LC_ALL=C LANG=C mullvad split-tunnel list 2>/dev/null)" || return 1
    [[ "${output}" == "Excluded PIDs:" ]] || return 1
  fi
  provider_disconnected
}

configure_gateway_baseline() {
  provider_command lan set allow || die 68 "gateway_settings_failed"
  provider_command lockdown-mode set off || die 68 "gateway_settings_failed"
  provider_command auto-connect set off || die 68 "gateway_settings_failed"
  provider_command disconnect || die 68 "gateway_settings_failed"
  if provider_authenticated; then
    provider_command tunnel set ipv6 off || die 68 "gateway_settings_failed"
    provider_command split-tunnel clear || die 68 "gateway_settings_failed"
  fi
  gateway_settings_ready || die 68 "gateway_settings_failed"
}

apply_gateway_settings() {
  set_phase "applying_gateway_settings"
  configure_gateway_baseline
}

prepare_provider_for_package_transaction() {
  rm -f -- "${CONTROLLED_START_MARKER}"
  systemctl stop "${EARLY_BOOT_UNIT}" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "${DAEMON_UNIT}"; then
    provider_ready || die 67 "provider_daemon_failed"
    configure_gateway_baseline
    systemctl stop "${DAEMON_UNIT}" || die 67 "provider_daemon_failed"
  fi
  if systemctl is-active --quiet "${DAEMON_UNIT}"; then
    die 70 "provider_service_suppression_failed"
  fi
  if systemctl is-active --quiet "${EARLY_BOOT_UNIT}"; then
    die 70 "provider_service_suppression_failed"
  fi
  if mullvad_firewall_table_present; then
    die 71 "provider_firewall_unsafe"
  fi
  management_network_ready || die 72 "management_connectivity_unavailable"
  rm -f -- "${INSTALLATION_COMPLETE_MARKER}"
}

verify_package_service_state() {
  local daemon_definition early_boot_definition
  systemctl daemon-reload || die 70 "provider_service_suppression_failed"
  [[ "$(systemctl show "${DAEMON_UNIT}" --property=LoadState --value 2>/dev/null)" == \
    "loaded" ]] || die 70 "provider_service_suppression_failed"
  [[ "$(systemctl show "${EARLY_BOOT_UNIT}" --property=LoadState --value 2>/dev/null)" == \
    "loaded" ]] || die 70 "provider_service_suppression_failed"
  daemon_definition="$(systemctl cat --no-pager "${DAEMON_UNIT}" 2>/dev/null)" ||
    die 70 "provider_service_suppression_failed"
  early_boot_definition="$(systemctl cat --no-pager "${EARLY_BOOT_UNIT}" 2>/dev/null)" ||
    die 70 "provider_service_suppression_failed"
  grep -Fxq -- "ConditionPathExists=|${CONTROLLED_START_MARKER}" \
    <<<"${daemon_definition}" ||
    die 70 "provider_service_suppression_failed"
  grep -Fxq -- "ConditionPathExists=|${INSTALLATION_COMPLETE_MARKER}" \
    <<<"${daemon_definition}" ||
    die 70 "provider_service_suppression_failed"
  grep -Fxq -- \
    "ConditionPathExists=/run/exitlane-provider-install/mullvad-early-boot-blocking-allowed" \
    <<<"${early_boot_definition}" ||
    die 70 "provider_service_suppression_failed"
  systemctl is-enabled --quiet "${DAEMON_UNIT}" ||
    die 70 "provider_service_suppression_failed"
  systemctl is-enabled --quiet "${EARLY_BOOT_UNIT}" ||
    die 70 "provider_service_suppression_failed"
  if systemctl is-active --quiet "${DAEMON_UNIT}"; then
    die 70 "provider_service_suppression_failed"
  fi
  if systemctl is-active --quiet "${EARLY_BOOT_UNIT}"; then
    die 70 "provider_service_suppression_failed"
  fi
  if mullvad_firewall_table_present; then
    die 71 "provider_firewall_unsafe"
  fi
  management_network_ready || die 72 "management_connectivity_unavailable"
}

start_provider_under_exitlane_control() {
  set_phase "starting_daemon"
  install -d -o root -g root -m 0700 "$(dirname "${CONTROLLED_START_MARKER}")"
  install -o root -g root -m 0600 /dev/null "${CONTROLLED_START_MARKER}"
  managed_daemon_started=1
  if ! systemctl start "${DAEMON_UNIT}"; then
    rm -f -- "${CONTROLLED_START_MARKER}"
    die 67 "provider_daemon_failed"
  fi
  rm -f -- "${CONTROLLED_START_MARKER}"
  if systemctl is-active --quiet "${EARLY_BOOT_UNIT}"; then
    die 70 "provider_service_suppression_failed"
  fi
}

prepare_repository() {
  local key_file binary_key inrelease primary_fingerprints
  work_dir="$(mktemp -d)"
  chmod 0700 "${work_dir}"
  key_file="${work_dir}/mullvad-keyring.asc"
  binary_key="${work_dir}/mullvad-keyring.gpg"
  inrelease="${work_dir}/InRelease"

  set_phase "preparing_repository"
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
    "${KEY_URL}" --output "${key_file}" || die 65 "repository_download_failed"
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 \
    "${INRELEASE_URL}" --output "${inrelease}" || die 65 "repository_download_failed"

  set_phase "verifying_repository"
  primary_fingerprints="$(
    GNUPGHOME="${work_dir}" gpg --batch --show-keys --with-colons --with-fingerprint \
      --import-options show-only "${key_file}" 2>/dev/null |
      awk -F: '$1 == "pub" {want_fingerprint=1; next} want_fingerprint && $1 == "fpr" {print $10; want_fingerprint=0}'
  )"
  [[ "${primary_fingerprints}" == "${KEY_FINGERPRINT}" ]] ||
    die 65 "repository_verification_failed"
  GNUPGHOME="${work_dir}" gpg --batch --yes --dearmor \
    --output "${binary_key}" "${key_file}" 2>/dev/null ||
    die 65 "repository_verification_failed"
  gpgv --keyring "${binary_key}" "${inrelease}" >/dev/null 2>&1 ||
    die 65 "repository_verification_failed"

  install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
  install -o root -g root -m 0644 "${key_file}" "${KEYRING_TARGET}"
  printf '%s\n' \
    "deb [arch=amd64 signed-by=${KEYRING_TARGET}] ${REPOSITORY_URL} stable main" \
    >"${SOURCE_TARGET}"
  chmod 0644 "${SOURCE_TARGET}"
}

repair_interrupted_package_transaction() {
  SYSTEMD_OFFLINE=1 DEBIAN_FRONTEND=noninteractive \
    dpkg --configure -a || die 66 "client_install_failed"
}

main() {
  set_phase "checking_system"
  [[ "${EUID}" -eq 0 ]] || die 77 "insufficient_privileges"
  [[ "$#" -eq 0 ]] || die 64 "arguments_not_allowed"
  require_debian_13_amd64
  acquire_package_lock
  verify_service_suppression_files
  prepare_provider_for_package_transaction

  prepare_repository
  set_phase "refreshing_packages"
  apt-get update -qq || die 66 "package_index_failed"
  set_phase "installing_client"
  repair_interrupted_package_transaction
  SYSTEMD_OFFLINE=1 DEBIAN_FRONTEND=noninteractive \
    apt-get install --reinstall -y -qq mullvad-vpn ||
    die 66 "client_install_failed"

  verify_package_service_state
  start_provider_under_exitlane_control
  wait_for_provider
  apply_gateway_settings
  set_phase "validating_installation"
  if ! provider_ready || ! gateway_settings_ready ||
    systemctl is-active --quiet "${EARLY_BOOT_UNIT}" ||
    mullvad_firewall_table_present || ! management_network_ready; then
    die 68 "provider_installation_validation_failed"
  fi
  install -d -o root -g root -m 0700 "$(dirname "${INSTALLATION_COMPLETE_MARKER}")"
  install -o root -g root -m 0600 /dev/null "${INSTALLATION_COMPLETE_MARKER}"
  installation_completed=1
  managed_daemon_started=0
  set_phase "completed"
  printf '%s\n' "installation_available"
}

main "$@"
