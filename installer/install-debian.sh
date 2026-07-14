#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="0.1.0-alpha.1"

# De repository waarin dit script staat.
SOURCE_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1
  pwd
)"
readonly SOURCE_DIR
# Overschrijfbaar voor testdoeleinden:
# TARGET=/tmp/exitlane-test ./installer/install-debian.sh
readonly TARGET="${TARGET:-/opt/exitlane}"
readonly VENV_DIR="${TARGET}/venv"

readonly CONFIG_DIR="${EXITLANE_CONFIG_DIR:-/etc/exitlane}"
readonly DATA_DIR="${EXITLANE_DATA_DIR:-/var/lib/exitlane}"
readonly LOG_DIR="${EXITLANE_LOG_DIR:-/var/log/exitlane}"

readonly SERVICE_NAME="exitlane.service"
readonly SERVICE_SOURCE="${SOURCE_DIR}/systemd/${SERVICE_NAME}"
readonly SERVICE_TARGET="/etc/systemd/system/${SERVICE_NAME}"

readonly DEFAULTS_SOURCE="${SOURCE_DIR}/installer/exitlane.default"
readonly DEFAULTS_TARGET="/etc/default/exitlane"

on_error() {
  local exit_code=$?
  local line_number="${1:-unknown}"

  echo
  echo "Exitlane-installatie mislukt."
  echo "Regel: ${line_number}"
  echo "Exitcode: ${exit_code}"
  echo
  echo "Bekijk zo nodig:"
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
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Voer dit installatiescript uit als root of via sudo."
  fi
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemd is niet beschikbaar. Exitlane vereist momenteel systemd."
  fi

  if [[ ! -d /run/systemd/system ]]; then
    fail "systemd draait niet als init-systeem."
  fi

  success "systemd beschikbaar"
}

detect_operating_system() {
  if [[ ! -r /etc/os-release ]]; then
    fail "/etc/os-release ontbreekt; het besturingssysteem kan niet worden vastgesteld."
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  if [[ "${ID:-}" != "debian" ]]; then
    fail "Deze installer ondersteunt momenteel alleen Debian."
  fi

  case "${VERSION_ID:-}" in
    12|13)
      success "Debian ${VERSION_ID} gedetecteerd"
      ;;
    *)
      fail "Debian ${VERSION_ID:-onbekend} wordt nog niet ondersteund. Gebruik Debian 12 of 13."
      ;;
  esac
}

check_source_layout() {
  [[ -f "${SOURCE_DIR}/backend/pyproject.toml" ]] ||
    fail "backend/pyproject.toml ontbreekt."

  [[ -f "${SERVICE_SOURCE}" ]] ||
    fail "${SERVICE_SOURCE} ontbreekt."

  [[ -f "${DEFAULTS_SOURCE}" ]] ||
    fail "${DEFAULTS_SOURCE} ontbreekt."

  if [[ "$(realpath -m "${SOURCE_DIR}")" == "$(realpath -m "${TARGET}")" ]]; then
    fail "De Git-repository en installatiemap mogen niet dezelfde map zijn.

Gebruik bijvoorbeeld:
  repository: /srv/exitlane
  installatie: /opt/exitlane"
  fi

  success "Bronstructuur gecontroleerd"
}

check_tun_device() {
  if [[ ! -c /dev/net/tun ]]; then
    fail "/dev/net/tun ontbreekt.

Voeg bij een Proxmox-LXC bijvoorbeeld toe aan /etc/pve/lxc/<CTID>.conf:

  lxc.cgroup2.devices.allow: c 10:200 rwm
  lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file

Stop en start de LXC daarna volledig."
  fi

  success "/dev/net/tun beschikbaar"
}

check_network_administration() {
  log "WireGuard-functionaliteit controleren"

  local test_interface="elwg$$"
  local output=""

  # Verwijder een eventueel achtergebleven testinterface.
  ip link delete "${test_interface}" >/dev/null 2>&1 || true

  if ! output="$(ip link add "${test_interface}" type wireguard 2>&1)"; then
    [[ -n "${output}" ]] && echo "${output}"
    fail "De container kan geen WireGuard-interface aanmaken.

Controleer of de LXC voldoende NET_ADMIN-rechten heeft en bij voorkeur
privileged draait."
  fi

  ip link delete "${test_interface}" >/dev/null 2>&1 || true

  success "WireGuard-interface kan worden aangemaakt"
}

check_connectivity() {
  if ! getent hosts deb.debian.org >/dev/null 2>&1; then
    fail "DNS-resolutie werkt niet."
  fi
  success "DNS-resolutie werkt"

  if ! curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --connect-timeout 10 \
    --max-time 20 \
    https://deb.debian.org/ \
    >/dev/null; then
    fail "Geen werkende HTTPS-verbinding naar internet."
  fi
  success "Internetverbinding werkt"
}

install_system_packages() {
  log "Benodigde Debian-pakketten installeren"

  export DEBIAN_FRONTEND=noninteractive

  apt-get update

  apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    nftables \
    python3 \
    python3-pip \
    python3-venv \
    rsync \
    wireguard-tools

  success "Systeempakketten geïnstalleerd"
}

create_directories() {
  log "Installatie- en datamappen voorbereiden"

  install -d -m 0755 "${TARGET}"
  install -d -m 0700 "${CONFIG_DIR}"
  install -d -m 0750 "${DATA_DIR}"
  install -d -m 0750 "${LOG_DIR}"

  success "Mappen aangemaakt"
}

stop_existing_service() {
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "Bestaande Exitlane-service stoppen"
    systemctl stop "${SERVICE_NAME}"
  fi
}

copy_application() {
  log "Exitlane naar ${TARGET} kopiëren"

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

  success "Applicatiebestanden gekopieerd"
}

create_virtual_environment() {
  log "Python virtual environment voorbereiden"

  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    rm -rf "${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
    success "Nieuwe virtual environment aangemaakt"
  else
    success "Bestaande virtual environment hergebruikt"
  fi

  "${VENV_DIR}/bin/python" -m pip install \
    --upgrade \
    pip \
    setuptools \
    wheel

  "${VENV_DIR}/bin/python" -m pip install \
    --upgrade \
    "${TARGET}/backend"

  success "Exitlane Python-package geïnstalleerd"
}

install_service_files() {
  log "systemd-configuratie installeren"

  install \
    -m 0644 \
    "${SERVICE_SOURCE}" \
    "${SERVICE_TARGET}"

  if [[ ! -f "${DEFAULTS_TARGET}" ]]; then
    install \
      -m 0600 \
      "${DEFAULTS_SOURCE}" \
      "${DEFAULTS_TARGET}"

    success "${DEFAULTS_TARGET} aangemaakt"
  else
    warning "${DEFAULTS_TARGET} bestaat al en is behouden"
  fi

  systemctl daemon-reload
  success "systemd-configuratie geladen"
}

configure_ip_forwarding() {
  log "IPv4-forwarding configureren"

  cat > /etc/sysctl.d/99-exitlane.conf <<'EOF'
# Required by Exitlane to forward ingress traffic through a VPN provider.
net.ipv4.ip_forward=1
EOF

  local current_value
  current_value="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"

  if [[ "${current_value}" != "1" ]]; then
    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
      fail "net.ipv4.ip_forward kon niet worden ingeschakeld."
    fi
  fi

  current_value="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"

  if [[ "${current_value}" != "1" ]]; then
    fail "IPv4-forwarding is na configuratie nog steeds uitgeschakeld."
  fi

  success "IPv4-forwarding staat aan"
}

start_service() {
  log "Exitlane-service inschakelen en starten"

  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"

  sleep 2

  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl status "${SERVICE_NAME}" --no-pager --full || true
    fail "Exitlane is niet succesvol gestart."
  fi

  success "Exitlane-service draait"
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
  echo " Exitlane ${INSTALLER_VERSION} is geïnstalleerd"
  echo "============================================================"
  echo
  echo " Webinterface:"
  echo "   http://${management_ip}:8787"
  echo
  echo " Applicatie:"
  echo "   ${TARGET}"
  echo
  echo " Configuratie:"
  echo "   ${CONFIG_DIR}"
  echo
  echo " Runtime-data:"
  echo "   ${DATA_DIR}"
  echo
  echo " Service:"
  echo "   systemctl status ${SERVICE_NAME}"
  echo
  echo " Logs:"
  echo "   journalctl -u ${SERVICE_NAME} -f"
  echo
  echo " Volgende stap:"
  echo "   Open de webinterface en doorloop de first-runwizard."
  echo
}

main() {
  echo
  echo "Exitlane Installer ${INSTALLER_VERSION}"
  echo "Smart egress for every network"
  echo

  require_root
  detect_operating_system
  require_systemd
  check_source_layout
  check_tun_device

  # ip en curl zijn mogelijk nog niet aanwezig op een echt minimale Debian-
  # installatie. Installeer daarom eerst de packages en voer daarna de overige
  # preflightchecks uit.
  install_system_packages

  check_connectivity
  check_network_administration

  create_directories
  stop_existing_service
  copy_application
  create_virtual_environment
  install_service_files
  configure_ip_forwarding
  start_service
  show_summary
}

main "$@"
