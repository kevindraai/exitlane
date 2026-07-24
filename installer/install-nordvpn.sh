#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly RELEASE_URL="https://repo.nordvpn.com/deb/nordvpn/debian/pool/main/n/nordvpn-release/nordvpn-release_1.0.0_all.deb"
readonly RELEASE_SHA256="16a05919b7259e679e4483aa39f61ef9bc9c07cbe040276e04884b5f9d7f933d"
readonly PHASE_FILE="/run/exitlane-provider-install/nordvpn.phase"
readonly PROVIDER_READY_TIMEOUT_SECONDS=45
readonly PROVIDER_CLI_TIMEOUT_SECONDS=2

work_dir=""
current_phase="checking_system"

cleanup() {
  local exit_code=$?
  trap - EXIT
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
      waiting_for_provider|validating_installation|completed|failed)
      current_phase="${phase}"
      printf '%s\n' "${phase}" >"${PHASE_FILE}"
      ;;
    *)
      die 68 "provider_installation_validation_failed"
      ;;
  esac
}

require_debian_13() {
  [[ -r /etc/os-release ]] || die 64 "unsupported_platform"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] ||
    die 64 "unsupported_platform"
}

provider_ready() {
  local provider_status status_code
  command -v nordvpn >/dev/null 2>&1 || return 1
  [[ "$(systemctl show nordvpnd --property=LoadState --value 2>/dev/null)" == "loaded" ]] ||
    return 1
  systemctl is-active --quiet nordvpnd || return 1
  status_code=0
  provider_status="$(
    timeout --signal=TERM "${PROVIDER_CLI_TIMEOUT_SECONDS}" \
      nordvpn status 2>&1
  )" || status_code=$?
  if ((status_code != 0)); then
    provider_status="${provider_status,,}"
    [[ "${provider_status}" == *"not logged in"* ||
      "${provider_status}" == *"not signed in"* ]] || return 1
  fi
}

wait_for_provider() {
  local attempt=0 delay_seconds deadline started_at
  set_phase "waiting_for_provider"
  started_at="${SECONDS}"
  deadline=$((SECONDS + PROVIDER_READY_TIMEOUT_SECONDS))
  printf '%s\n' "nordvpn readiness: daemon active" >&2
  while ((SECONDS < deadline)); do
    attempt=$((attempt + 1))
    if provider_ready; then
      printf '%s\n' \
        "nordvpn readiness: CLI ready attempts=${attempt} duration_seconds=$((SECONDS - started_at))" \
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
  printf '%s\n' \
    "nordvpn readiness: timeout category=provider_cli_unavailable attempts=${attempt} duration_seconds=$((SECONDS - started_at))" \
    >&2
  die 69 "provider_readiness_timeout"
}

main() {
  set_phase "checking_system"
  [[ "${EUID}" -eq 0 ]] || die 77 "insufficient_privileges"
  [[ "$#" -eq 0 ]] || die 64 "arguments_not_allowed"
  require_debian_13

  if command -v nordvpn >/dev/null 2>&1; then
    set_phase "starting_daemon"
    systemctl enable --now nordvpnd || die 67 "provider_daemon_failed"
    wait_for_provider
    printf '%s\n' "installation_available"
    return
  fi

  local release_package
  work_dir="$(mktemp -d)"
  release_package="${work_dir}/nordvpn-release.deb"

  set_phase "preparing_repository"
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 \
    "${RELEASE_URL}" --output "${release_package}" ||
    die 65 "repository_download_failed"
  set_phase "verifying_repository"
  printf '%s  %s\n' "${RELEASE_SHA256}" "${release_package}" |
    sha256sum --check --status ||
    die 65 "repository_verification_failed"

  dpkg --install "${release_package}" >/dev/null ||
    die 66 "repository_setup_failed"
  set_phase "refreshing_packages"
  apt-get update -qq || die 66 "package_index_failed"
  set_phase "installing_client"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nordvpn ||
    die 66 "client_install_failed"
  set_phase "starting_daemon"
  systemctl enable --now nordvpnd || die 67 "provider_daemon_failed"
  wait_for_provider
  printf '%s\n' "installation_available"
}

main "$@"
