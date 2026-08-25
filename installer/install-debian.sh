#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="0.2.0-beta.5"
readonly PACKAGE_VERSION="0.2.0b5"
readonly LIFECYCLE_LOCK="${EXITLANE_LIFECYCLE_LOCK:-/run/lock/exitlane-lifecycle.lock}"
readonly RECOVERY_ROOT="${EXITLANE_RECOVERY_ROOT:-/var/lib/exitlane/recovery}"
UPGRADE_MODE=0
UPGRADE_COMMITTED=0
RECOVERY_DIR=""
LOCK_FD=""
CURRENT_VERSION=""

# The repository containing this script.
SOURCE_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1
  pwd
)"
readonly SOURCE_DIR
# Override for testing:
# TARGET=/tmp/exitlane-test ./installer/install-debian.sh
readonly TARGET="${TARGET:-/opt/exitlane}"
readonly VENV_DIR="${TARGET}/venv"
readonly CLI_TARGET="/usr/local/sbin/exitlane-cli"
readonly NORDVPN_HELPER_SOURCE="${SOURCE_DIR}/installer/install-nordvpn.sh"
readonly NORDVPN_HELPER_TARGET="/usr/local/libexec/exitlane-install-nordvpn"
readonly SPEEDTEST_HELPER_SOURCE="${SOURCE_DIR}/installer/install-speedtest.sh"
readonly SPEEDTEST_HELPER_TARGET="/usr/local/libexec/exitlane-install-speedtest"

readonly CONFIG_DIR="${EXITLANE_CONFIG_DIR:-/etc/exitlane}"
readonly DATA_DIR="${EXITLANE_DATA_DIR:-/var/lib/exitlane}"
readonly LOG_DIR="${EXITLANE_LOG_DIR:-/var/log/exitlane}"
readonly MASTER_KEY="${CONFIG_DIR}/secret.key"

readonly SERVICE_NAME="exitlane.service"
readonly SERVICE_SOURCE="${SOURCE_DIR}/systemd/${SERVICE_NAME}"
readonly SERVICE_TARGET="/etc/systemd/system/${SERVICE_NAME}"
readonly KILLSWITCH_SERVICE_SOURCE="${SOURCE_DIR}/systemd/exitlane-killswitch.service"
readonly KILLSWITCH_SERVICE_TARGET="/etc/systemd/system/exitlane-killswitch.service"
readonly PROVIDER_INSTALL_SERVICE_SOURCE="${SOURCE_DIR}/systemd/exitlane-provider-install-nordvpn.service"
readonly PROVIDER_INSTALL_SERVICE_TARGET="/etc/systemd/system/exitlane-provider-install-nordvpn.service"
readonly SPEEDTEST_INSTALL_SERVICE_SOURCE="${SOURCE_DIR}/systemd/exitlane-speedtest-install.service"
readonly SPEEDTEST_INSTALL_SERVICE_TARGET="/etc/systemd/system/exitlane-speedtest-install.service"

readonly DEFAULTS_SOURCE="${SOURCE_DIR}/installer/exitlane.default"
readonly DEFAULTS_TARGET="/etc/default/exitlane"
readonly IP_FORWARDING_TARGET="/etc/sysctl.d/99-exitlane.conf"

on_error() {
  local exit_code=$?
  local line_number="${1:-unknown}"

  if [[ "${UPGRADE_MODE}" -eq 1 && "${UPGRADE_COMMITTED}" -eq 0 && -n "${RECOVERY_DIR}" ]]; then
    rollback_upgrade || true
  fi
  echo
  echo "ExitLane installation failed."
  echo "Line: ${line_number}"
  echo "Exit code: ${exit_code}"
  echo
  echo "If needed, inspect:"
  echo "  journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  exit "${exit_code}"
}

trap 'on_error "$LINENO"' ERR

log() {
  printf '\n\033[1;34m==>\033[0m %s\n' "$*"
}

success() {
  printf '\033[1;32m✓\033[0m %s\n' "$*"
}

warning() {
  printf '\033[1;33m!\033[0m %s\n' "$*"
}

fail() {
  printf '\033[1;31m✗\033[0m %s\n' "$*" >&2
  if [[ "${UPGRADE_MODE}" -eq 1 && "${UPGRADE_COMMITTED}" -eq 0 && -n "${RECOVERY_DIR}" ]]; then
    rollback_upgrade || true
    RECOVERY_DIR=""
  fi
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this installation script as root or with sudo."
  fi
}

acquire_lifecycle_lock() {
  install -d -m 0755 "$(dirname "${LIFECYCLE_LOCK}")"
  exec {LOCK_FD}>"${LIFECYCLE_LOCK}"
  if ! flock -n "${LOCK_FD}"; then
    fail "Another ExitLane lifecycle action is already active."
  fi
  success "Exclusive lifecycle lock acquired"
}

detect_installation_mode() {
  if [[ -f "${TARGET}/backend/pyproject.toml" || -f "${DATA_DIR}/exitlane.db" ]]; then
    UPGRADE_MODE=1
    if [[ -f "${DATA_DIR}/installed-version" ]]; then
      CURRENT_VERSION="$(head -n 1 "${DATA_DIR}/installed-version")"
    elif [[ -f "${TARGET}/backend/pyproject.toml" ]]; then
      CURRENT_VERSION="$(
        sed -n 's/^version="\([^"]*\)"$/\1/p' \
          "${TARGET}/backend/pyproject.toml" |
          head -n 1
      )"
    fi
    if [[ -n "${CURRENT_VERSION}" ]] &&
      dpkg --compare-versions "${CURRENT_VERSION}" gt "${PACKAGE_VERSION}"; then
      fail "Downgrade from ${CURRENT_VERSION} to ${INSTALLER_VERSION} is not allowed."
    fi
    log "Existing ExitLane installation detected"
    [[ -z "${CURRENT_VERSION}" ]] ||
      success "Current version ${CURRENT_VERSION}; target version ${INSTALLER_VERSION}"
  else
    UPGRADE_MODE=0
    log "Clean ExitLane installation detected"
  fi
}

check_free_space() {
  local required_kib=524288
  local available_kib
  available_kib="$(df -Pk "${TARGET%/*}" | awk 'NR==2 {print $4}')"
  if [[ ! "${available_kib}" =~ ^[0-9]+$ ]] || (( available_kib < required_kib )); then
    fail "At least 512 MiB of free space is required for installation and recovery."
  fi
  success "Sufficient free disk space available"
}

snapshot_sqlite_database() {
  local source="$1"
  local destination="$2"
  python3 -c '
import sqlite3
import sys
with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as source:
    with sqlite3.connect(sys.argv[2]) as destination:
        source.backup(destination)
' "${source}" "${destination}"
  chmod 0600 "${destination}"
}

prepare_upgrade_recovery() {
  [[ "${UPGRADE_MODE}" -eq 1 ]] || return 0
  install -d -o root -g root -m 0700 "${RECOVERY_ROOT}"
  RECOVERY_DIR="$(mktemp -d "${RECOVERY_ROOT}/pre-upgrade.XXXXXXXX")"
  chmod 0700 "${RECOVERY_DIR}"
  install -d -m 0700 "${RECOVERY_DIR}/files"
  : > "${RECOVERY_DIR}/path-state"
  chmod 0600 "${RECOVERY_DIR}/path-state"

  if [[ -f "${DATA_DIR}/exitlane.db" ]]; then
    snapshot_sqlite_database \
      "${DATA_DIR}/exitlane.db" \
      "${RECOVERY_DIR}/exitlane.db"
  fi
  for path in \
    "${TARGET}" \
    "${CONFIG_DIR}" \
    "${CLI_TARGET}" \
    "${SERVICE_TARGET}" \
    "${KILLSWITCH_SERVICE_TARGET}" \
    "${PROVIDER_INSTALL_SERVICE_TARGET}" \
    "${SPEEDTEST_INSTALL_SERVICE_TARGET}" \
    "${NORDVPN_HELPER_TARGET}" \
    "${SPEEDTEST_HELPER_TARGET}" \
    "${DEFAULTS_TARGET}" \
    "${IP_FORWARDING_TARGET}"; do
    snapshot_recovery_path "${path}"
  done
  printf '%s\n' "${INSTALLER_VERSION}" > "${RECOVERY_DIR}/target-version"
  chmod -R go-rwx "${RECOVERY_DIR}"
  success "Root-only pre-upgrade recovery snapshot created"
}

rollback_upgrade() {
  warning "Upgrade failed; restoring the previous ExitLane installation"
  systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
  if [[ -d "${RECOVERY_DIR}/files" ]]; then
    restore_recovery_files "${RECOVERY_DIR}/files" "${RECOVERY_DIR}/path-state" /
  fi
  if [[ -f "${RECOVERY_DIR}/exitlane.db" ]]; then
    install -o root -g root -m 0600 \
      "${RECOVERY_DIR}/exitlane.db" \
      "${DATA_DIR}/exitlane.db"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
  warning "Rollback completed; recovery snapshot retained at ${RECOVERY_DIR}"
}

restore_recovery_files() {
  local recovery_files="$1"
  local path_state="$2"
  local destination_root="${3:-/}"
  local state
  local source_path
  local destination

  [[ -f "${path_state}" ]] || return 1
  while IFS='|' read -r state source_path; do
    [[ -n "${state}" ]] || continue
    case "${state}" in present|absent) ;; *) return 1 ;; esac
    case "${source_path}" in
      "${TARGET}"|"${CONFIG_DIR}"|"${CLI_TARGET}"|"${SERVICE_TARGET}"|"${KILLSWITCH_SERVICE_TARGET}"|"${PROVIDER_INSTALL_SERVICE_TARGET}"|"${SPEEDTEST_INSTALL_SERVICE_TARGET}"|"${NORDVPN_HELPER_TARGET}"|"${SPEEDTEST_HELPER_TARGET}"|"${DEFAULTS_TARGET}"|"${IP_FORWARDING_TARGET}") ;;
      *) return 1 ;;
    esac
    destination="${destination_root%/}${source_path}"
    [[ -n "${destination}" && "${destination}" != "${destination_root%/}" ]] || return 1
    rm -rf -- "${destination}"
    [[ "${state}" == "absent" ]] && continue
    source_path="${recovery_files}${source_path}"
    [[ -e "${source_path}" || -L "${source_path}" ]] || return 1
    install -d -m 0755 "$(dirname "${destination}")"
    cp -a "${source_path}" "$(dirname "${destination}")/"
  done < "${path_state}"
}

snapshot_recovery_path() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    printf 'present|%s\n' "${path}" >> "${RECOVERY_DIR}/path-state"
    cp -a --parents "${path}" "${RECOVERY_DIR}/files"
  else
    printf 'absent|%s\n' "${path}" >> "${RECOVERY_DIR}/path-state"
  fi
}

commit_upgrade() {
  [[ "${UPGRADE_MODE}" -eq 1 ]] || return 0
  printf '%s\n' "${INSTALLER_VERSION}" > "${DATA_DIR}/installed-version"
  chmod 0600 "${DATA_DIR}/installed-version"
  UPGRADE_COMMITTED=1
  success "Upgrade transaction completed; recovery: ${RECOVERY_DIR}"
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemd is unavailable. ExitLane currently requires systemd."
  fi

  if [[ ! -d /run/systemd/system ]]; then
    fail "systemd is not running as the init system."
  fi

  success "systemd available"
}

detect_operating_system() {
  if [[ ! -r /etc/os-release ]]; then
    fail "/etc/os-release is missing; the operating system cannot be determined."
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  if [[ "${ID:-}" != "debian" || "${VERSION_ID:-}" != "13" ]]; then
    fail "This release supports Debian 13 on amd64 only."
  fi

  if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
    fail "This release supports Debian 13 on amd64 only."
  fi

  success "Debian 13 amd64 detected"
}

check_source_layout() {
  [[ -f "${SOURCE_DIR}/backend/pyproject.toml" ]] ||
    fail "backend/pyproject.toml is missing."

  [[ -f "${SERVICE_SOURCE}" ]] ||
    fail "${SERVICE_SOURCE} is missing."

  [[ -f "${DEFAULTS_SOURCE}" ]] ||
    fail "${DEFAULTS_SOURCE} is missing."
  [[ -f "${NORDVPN_HELPER_SOURCE}" ]] ||
    fail "${NORDVPN_HELPER_SOURCE} is missing."
  [[ -f "${SPEEDTEST_HELPER_SOURCE}" ]] ||
    fail "${SPEEDTEST_HELPER_SOURCE} is missing."
  [[ -f "${PROVIDER_INSTALL_SERVICE_SOURCE}" ]] ||
    fail "${PROVIDER_INSTALL_SERVICE_SOURCE} is missing."
  [[ -f "${SPEEDTEST_INSTALL_SERVICE_SOURCE}" ]] ||
    fail "${SPEEDTEST_INSTALL_SERVICE_SOURCE} is missing."

  if [[ "$(realpath -m "${SOURCE_DIR}")" == "$(realpath -m "${TARGET}")" ]]; then
    fail "The Git repository and installation directory must not be the same directory.

For example, use:
  repository: /srv/exitlane
  installation: /opt/exitlane"
  fi

  success "Source layout verified"
}

check_tun_device() {
  if [[ ! -c /dev/net/tun ]]; then
    fail "/dev/net/tun is missing.

For a Proxmox LXC, add the following to /etc/pve/lxc/<CTID>.conf:

  lxc.cgroup2.devices.allow: c 10:200 rwm
  lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file

Then fully stop and start the LXC."
  fi

  success "/dev/net/tun available"
}

check_network_administration() {
  log "Checking WireGuard functionality"

  local test_interface="elwg$$"
  local output=""

  # Remove any leftover test interface.
  ip link delete "${test_interface}" >/dev/null 2>&1 || true

  if ! output="$(ip link add "${test_interface}" type wireguard 2>&1)"; then
    [[ -n "${output}" ]] && echo "${output}"
    fail "The container cannot create a WireGuard interface.

Verify that the LXC has sufficient NET_ADMIN privileges and preferably runs
as a privileged container."
  fi

  ip link delete "${test_interface}" >/dev/null 2>&1 || true

  success "WireGuard interface can be created"
}

check_connectivity() {
  if ! getent hosts deb.debian.org >/dev/null 2>&1; then
    fail "DNS resolution is not working."
  fi
  success "DNS resolution works"

  if ! curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --connect-timeout 10 \
    --max-time 20 \
    https://deb.debian.org/ \
    >/dev/null; then
    fail "No working HTTPS connection to the internet."
  fi
  success "Internet connection works"
}

install_system_packages() {
  log "Installing required Debian packages"

  export DEBIAN_FRONTEND=noninteractive

  apt-get update

  apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    iproute2 \
    iputils-ping \
    iptables \
    nftables \
    python3 \
    python3-pip \
    python3-venv \
    procps \
    rsync \
    wireguard-tools

  success "System packages installed"
}

create_directories() {
  log "Preparing installation and data directories"

  install -d -m 0755 "${TARGET}"
  install -d -m 0700 "${CONFIG_DIR}"
  install -d -m 0700 "${DATA_DIR}"
  install -d -m 0700 "${LOG_DIR}"

  success "Directories created"
}

create_master_key() {
  if [[ -e "${MASTER_KEY}" ]]; then
    chmod 0600 "${MASTER_KEY}"
    success "Existing application master key retained"
    return
  fi
  (
    umask 0177
    head -c 32 /dev/urandom > "${MASTER_KEY}"
  )
  chmod 0600 "${MASTER_KEY}"
  success "Application master key created securely"
}

stop_existing_service() {
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "Stopping existing ExitLane service"
    systemctl stop "${SERVICE_NAME}"
  fi
}

copy_application() {
  log "Copying ExitLane to ${TARGET}"

  rsync -a \
    --delete \
    --exclude='.git/' \
    --exclude='.github/' \
    --exclude='.venv/' \
    --exclude='venv/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='.pytest_cache/' \
    --exclude='.ruff_cache/' \
    --exclude='*.egg-info/' \
    --exclude='.env' \
    --exclude='exitlane.db' \
    "${SOURCE_DIR}/" \
    "${TARGET}/"

  success "Application files copied"
}

create_virtual_environment() {
  log "Preparing Python virtual environment"

  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    rm -rf "${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    success "New virtual environment created"
  else
    success "Existing virtual environment reused"
  fi

  "${VENV_DIR}/bin/python" -m pip install \
    --upgrade \
    pip \
    setuptools \
    wheel

  "${VENV_DIR}/bin/python" -m pip install \
    --upgrade \
    "${TARGET}/backend"

  chmod -R a+rX "${VENV_DIR}"
  success "ExitLane Python package installed"
}

install_cli() {
  log "Installing local management command"
  install -m 0755 "${VENV_DIR}/bin/exitlane-cli" "${CLI_TARGET}"
  success "${CLI_TARGET} installed"
}

install_provider_helper() {
  log "Installing fixed provider installation helper"
  install -d -m 0755 /usr/local/libexec
  install -o root -g root -m 0755 "${NORDVPN_HELPER_SOURCE}" "${NORDVPN_HELPER_TARGET}"
  success "${NORDVPN_HELPER_TARGET} installed"
}

install_speedtest_helper() {
  log "Installing fixed Speedtest installation helper"
  install -d -m 0755 /usr/local/libexec
  install -o root -g root -m 0755 "${SPEEDTEST_HELPER_SOURCE}" "${SPEEDTEST_HELPER_TARGET}"
  success "${SPEEDTEST_HELPER_TARGET} installed"
}

install_defaults_file() {
  local source_path="$1"
  local target_path="$2"

  if [[ -f "${target_path}" ]]; then
    warning "${target_path} already exists and was retained"
    return
  fi

  install -m 0600 "${source_path}" "${target_path}"
  success "${target_path} created"
}

install_service_files() {
  log "Installing systemd configuration"

  install \
    -m 0644 \
    "${SERVICE_SOURCE}" \
    "${SERVICE_TARGET}"
  install -m 0644 "${KILLSWITCH_SERVICE_SOURCE}" "${KILLSWITCH_SERVICE_TARGET}"
  install -o root -g root -m 0644 \
    "${PROVIDER_INSTALL_SERVICE_SOURCE}" \
    "${PROVIDER_INSTALL_SERVICE_TARGET}"
  install -o root -g root -m 0644 \
    "${SPEEDTEST_INSTALL_SERVICE_SOURCE}" \
    "${SPEEDTEST_INSTALL_SERVICE_TARGET}"

  install_defaults_file "${DEFAULTS_SOURCE}" "${DEFAULTS_TARGET}"

  systemctl daemon-reload
  success "systemd configuration loaded"
}

configure_ip_forwarding() {
  log "Configuring IPv4 forwarding"

  install -d -m 0755 "$(dirname "${IP_FORWARDING_TARGET}")"
  cat > "${IP_FORWARDING_TARGET}" <<'EOF'
# Required by ExitLane to forward ingress traffic through a VPN provider.
net.ipv4.ip_forward=1
EOF

  local current_value
  current_value="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"

  if [[ "${current_value}" != "1" ]]; then
    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
      fail "net.ipv4.ip_forward could not be enabled."
    fi
  fi

  current_value="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"

  if [[ "${current_value}" != "1" ]]; then
    fail "IPv4 forwarding is still disabled after configuration."
  fi

  success "IPv4 forwarding is enabled"
}

start_service() {
  log "Enabling and starting the ExitLane service"

  systemctl enable "${SERVICE_NAME}"
  systemctl enable exitlane-killswitch.service
  systemctl restart "${SERVICE_NAME}"

  sleep 2

  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl status "${SERVICE_NAME}" --no-pager --full || true
    fail "ExitLane did not start successfully."
  fi

  success "ExitLane service is running"
}

detect_management_ip() {
  local management_ip=""

  management_ip="$(
    ip -4 -o addr show scope global |
      awk '$2 != "lo" {
        split($4, address, "/")
        print address[1]
        exit
      }'
  )"

  if [[ -z "${management_ip}" ]]; then
    management_ip="<LXC-IP>"
  fi

  printf '%s' "${management_ip}"
}

show_summary() {
  local management_ip
  management_ip="$(detect_management_ip)"

  echo
  echo "============================================================"
  echo " ExitLane ${INSTALLER_VERSION} is installed"
  echo "============================================================"
  echo
  echo " Web interface:"
  echo "   http://${management_ip}:8787"
  echo
  echo " Application:"
  echo "   ${TARGET}"
  echo
  echo " Configuration:"
  echo "   ${CONFIG_DIR}"
  echo
  echo " Runtime data:"
  echo "   ${DATA_DIR}"
  echo
  echo " Service:"
  echo "   systemctl status ${SERVICE_NAME}"
  echo
  echo " Logs:"
  echo "   journalctl -u ${SERVICE_NAME} -f"
  echo
  echo " Next step:"
  echo "   Open the web interface and complete the first-run wizard."
  echo
}

main() {
  echo
  echo "ExitLane Installer ${INSTALLER_VERSION}"
  echo "Smart egress for every network"
  echo

  require_root
  acquire_lifecycle_lock
  detect_operating_system
  require_systemd
  check_source_layout
  check_tun_device

  # ip and curl may not be available yet on a truly minimal Debian installation.
  # Install the packages first, then run the remaining preflight checks.
  install_system_packages
  check_connectivity
  check_network_administration

  detect_installation_mode
  check_free_space
  create_directories
  create_master_key
  prepare_upgrade_recovery
  stop_existing_service
  copy_application
  create_virtual_environment
  install_cli
  install_provider_helper
  install_speedtest_helper
  install_service_files
  configure_ip_forwarding
  start_service
  commit_upgrade
  show_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
