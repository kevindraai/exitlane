#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly RELEASE_URL="https://repo.nordvpn.com/deb/nordvpn/debian/pool/main/n/nordvpn-release/nordvpn-release_1.0.0_all.deb"
readonly RELEASE_SHA256="16a05919b7259e679e4483aa39f61ef9bc9c07cbe040276e04884b5f9d7f933d"

work_dir=""

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
  printf '%s\n' "${message}" >&2
  exit "${code}"
}

require_debian_13() {
  [[ -r /etc/os-release ]] || die 64 "unsupported_platform"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] ||
    die 64 "unsupported_platform"
}

validate_installation() {
  local provider_status
  command -v nordvpn >/dev/null 2>&1 ||
    die 68 "provider_installation_validation_failed"
  [[ "$(systemctl show nordvpnd --property=LoadState --value 2>/dev/null)" == "loaded" ]] ||
    die 68 "provider_installation_validation_failed"
  systemctl is-active --quiet nordvpnd ||
    die 67 "provider_daemon_failed"
  if ! provider_status="$(nordvpn status 2>&1)"; then
    provider_status="${provider_status,,}"
    [[ "${provider_status}" == *"not logged in"* ||
      "${provider_status}" == *"not signed in"* ]] ||
      die 68 "provider_installation_validation_failed"
  fi
}

main() {
  [[ "${EUID}" -eq 0 ]] || die 77 "insufficient_privileges"
  [[ "$#" -eq 0 ]] || die 64 "arguments_not_allowed"
  require_debian_13

  if command -v nordvpn >/dev/null 2>&1; then
    systemctl enable --now nordvpnd || die 67 "provider_daemon_failed"
    validate_installation
    printf '%s\n' "installation_available"
    return
  fi

  local release_package
  work_dir="$(mktemp -d)"
  release_package="${work_dir}/nordvpn-release.deb"

  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 \
    "${RELEASE_URL}" --output "${release_package}" ||
    die 65 "repository_download_failed"
  printf '%s  %s\n' "${RELEASE_SHA256}" "${release_package}" |
    sha256sum --check --status ||
    die 65 "repository_verification_failed"

  dpkg --install "${release_package}" >/dev/null ||
    die 66 "repository_setup_failed"
  apt-get update -qq || die 66 "package_index_failed"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nordvpn ||
    die 66 "client_install_failed"
  systemctl enable --now nordvpnd || die 67 "provider_daemon_failed"
  validate_installation
  printf '%s\n' "installation_available"
}

main "$@"
