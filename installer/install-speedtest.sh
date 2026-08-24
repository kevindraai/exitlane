#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly PACKAGE_URL="https://packagecloud.io/ookla/speedtest-cli/packages/debian/trixie/speedtest_1.2.0.84-1.ea6b6773cf_amd64.deb/download.deb?distro_version_id=221"
readonly PACKAGE_SHA256="35e084567a6388631fb10cf01e5e0d6b57a67d34ede2b72ba111b3d9164c8b94"
readonly PACKAGE_NAME="speedtest"
readonly PACKAGE_VERSION="1.2.0.84-1.ea6b6773cf"
readonly PACKAGE_OPERATION_LOCK="/run/lock/exitlane-package-operation.lock"
readonly PHASE_FILE="/run/exitlane-speedtest-install/installation.phase"
readonly PACKAGE_TIMEOUT_SECONDS=120

work_dir=""
current_phase="checking_system"
PACKAGE_LOCK_FD=""

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ -n "${work_dir:-}" && -d "${work_dir}" ]]; then
    rm -rf -- "${work_dir}" || printf '%s\n' "warning: speedtest_installation_cleanup_failed" >&2
  fi
  exit "${exit_code}"
}

trap cleanup EXIT

write_phase() {
  local value="$1"
  local temporary_file="${PHASE_FILE}.tmp.$$"
  umask 077
  printf '%s\n' "${value}" >"${temporary_file}"
  chmod 0600 "${temporary_file}"
  mv -f -- "${temporary_file}" "${PHASE_FILE}"
}

die() {
  local code="$1"
  local message="$2"
  write_phase "failed|${current_phase}|${message}" || true
  printf '%s\n' "${message}" >&2
  exit "${code}"
}

set_phase() {
  local phase="$1"
  case "${phase}" in
    checking_system|downloading_package|verifying_package|installing_package|validating_installation|completed)
      current_phase="${phase}"
      write_phase "${phase}"
      ;;
    *) die 68 "speedtest_validation_failed" ;;
  esac
}

acquire_package_lock() {
  install -d -m 0755 /run/lock
  exec {PACKAGE_LOCK_FD}>"${PACKAGE_OPERATION_LOCK}"
  flock -n "${PACKAGE_LOCK_FD}" || die 75 "package_operation_in_progress"
}

require_debian_13_amd64() {
  [[ -r /etc/os-release ]] || die 64 "unsupported_platform"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] || die 64 "unsupported_platform"
  [[ "$(dpkg --print-architecture)" == "amd64" ]] || die 64 "unsupported_platform"
}

official_cli_installed() {
  local package_status
  command -v speedtest >/dev/null 2>&1 || return 1
  [[ "$(command -v speedtest)" == "/usr/bin/speedtest" ]] || return 1
  package_status="$(dpkg-query --showformat='${Package}|${Version}|${Status}' --show "${PACKAGE_NAME}" 2>/dev/null)" || return 1
  [[ "${package_status}" == "${PACKAGE_NAME}|${PACKAGE_VERSION}|install ok installed" ]] || return 1
  dpkg-query --listfiles "${PACKAGE_NAME}" 2>/dev/null | grep -Fx -- "/usr/bin/speedtest" >/dev/null || return 1
  [[ -x /usr/bin/speedtest ]]
}

main() {
  set_phase "checking_system"
  [[ "${EUID}" -eq 0 ]] || die 77 "insufficient_privileges"
  [[ "$#" -eq 0 ]] || die 64 "arguments_not_allowed"
  require_debian_13_amd64
  acquire_package_lock

  if command -v speedtest >/dev/null 2>&1; then
    official_cli_installed || die 70 "preexisting_speedtest_unverified"
    set_phase "completed"
    return
  fi

  work_dir="$(mktemp -d /run/exitlane-speedtest-install/.package.XXXXXX)"
  chmod 0700 "${work_dir}"
  local package_file="${work_dir}/speedtest.deb"

  set_phase "downloading_package"
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time "${PACKAGE_TIMEOUT_SECONDS}" \
    "${PACKAGE_URL}" --output "${package_file}" || die 65 "package_download_failed"
  set_phase "verifying_package"
  printf '%s  %s\n' "${PACKAGE_SHA256}" "${package_file}" | sha256sum --check --status ||
    die 65 "package_verification_failed"
  set_phase "installing_package"
  timeout --signal=TERM "${PACKAGE_TIMEOUT_SECONDS}" \
    env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${package_file}" \
    >/dev/null || die 66 "client_install_failed"
  set_phase "validating_installation"
  official_cli_installed || die 68 "speedtest_validation_failed"
  set_phase "completed"
}

main "$@"
