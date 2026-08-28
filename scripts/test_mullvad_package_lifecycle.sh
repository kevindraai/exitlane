#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly DAEMON_UNIT="mullvad-daemon.service"
readonly EARLY_BOOT_UNIT="mullvad-early-boot-blocking.service"
readonly COMPLETE_MARKER="/etc/exitlane/mullvad-installation-complete"
readonly CONTROLLED_START_MARKER="/run/exitlane-provider-install/mullvad-daemon-start-allowed"
readonly HELPER="/usr/local/libexec/exitlane-install-mullvad"

monitor_pid=""
monitor_dir=""
test_completed=0

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "${monitor_pid}" ]]; then
    kill "${monitor_pid}" >/dev/null 2>&1 || true
    wait "${monitor_pid}" 2>/dev/null || true
  fi
  rm -f -- "${CONTROLLED_START_MARKER}"
  if [[ "${test_completed}" -eq 0 && ! -e "${COMPLETE_MARKER}" ]]; then
    systemctl stop "${DAEMON_UNIT}" >/dev/null 2>&1 || true
    systemctl stop "${EARLY_BOOT_UNIT}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${monitor_dir}" && -d "${monitor_dir}" ]]; then
    rm -rf -- "${monitor_dir}"
  fi
  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

firewall_table_present() {
  nft list table inet mullvad >/dev/null 2>&1
}

provider_disconnected() {
  timeout --signal=TERM 10 env LC_ALL=C LANG=C mullvad status --json 2>/dev/null |
    python3 -c '
import json
import sys

try:
    value = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if isinstance(value, dict) and value.get("state") == "disconnected" else 1)
'
}

prepare_disconnected_state() {
  if systemctl is-active --quiet "${DAEMON_UNIT}"; then
    timeout --signal=TERM 10 env LC_ALL=C LANG=C mullvad lan set allow >/dev/null
    timeout --signal=TERM 10 env LC_ALL=C LANG=C mullvad lockdown-mode set off >/dev/null
    timeout --signal=TERM 10 env LC_ALL=C LANG=C mullvad auto-connect set off >/dev/null
    timeout --signal=TERM 10 env LC_ALL=C LANG=C mullvad disconnect >/dev/null
    provider_disconnected || fail "Mullvad did not reach disconnected state before reinstall"
    systemctl stop "${DAEMON_UNIT}"
  fi
  systemctl stop "${EARLY_BOOT_UNIT}" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "${DAEMON_UNIT}"; then
    fail "daemon remained active before reinstall"
  fi
  if systemctl is-active --quiet "${EARLY_BOOT_UNIT}"; then
    fail "early-boot blocker remained active before reinstall"
  fi
  if firewall_table_present; then
    fail "Mullvad firewall table existed before reinstall"
  fi
}

start_package_monitor() {
  monitor_dir="$(mktemp -d /run/exitlane-mullvad-package-monitor.XXXXXXXX)"
  chmod 0700 "${monitor_dir}"
  (
    while [[ ! -e "${monitor_dir}/stop" ]]; do
      systemctl is-active --quiet "${DAEMON_UNIT}" && : >"${monitor_dir}/daemon-active"
      systemctl is-active --quiet "${EARLY_BOOT_UNIT}" && : >"${monitor_dir}/early-active"
      firewall_table_present && : >"${monitor_dir}/firewall-table"
      sleep 0.05
    done
  ) &
  monitor_pid=$!
}

stop_package_monitor() {
  : >"${monitor_dir}/stop"
  wait "${monitor_pid}"
  monitor_pid=""
}

main() {
  local daemon_definition early_boot_definition
  [[ "${EUID}" -eq 0 ]] || fail "run as root"
  [[ "${EXITLANE_MULLVAD_LIVE_TEST:-}" == "I_ACCEPT_DISPOSABLE_TEST_MUTATION" ]] ||
    fail "set EXITLANE_MULLVAD_LIVE_TEST=I_ACCEPT_DISPOSABLE_TEST_MUTATION"
  [[ -r /etc/os-release ]] || fail "missing os-release"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]] ||
    fail "Debian 13 is required"
  [[ "$(dpkg --print-architecture)" == "amd64" ]] || fail "amd64 is required"
  [[ -x "${HELPER}" ]] || fail "managed Mullvad helper is not installed"
  daemon_definition="$(systemctl cat --no-pager "${DAEMON_UNIT}" 2>/dev/null)" ||
    fail "daemon unit cannot be inspected"
  early_boot_definition="$(systemctl cat --no-pager "${EARLY_BOOT_UNIT}" 2>/dev/null)" ||
    fail "early-boot unit cannot be inspected"
  grep -Fxq \
    'ConditionPathExists=|/run/exitlane-provider-install/mullvad-daemon-start-allowed' \
    <<<"${daemon_definition}" ||
    fail "daemon controlled-start condition is missing"
  grep -Fxq \
    'ConditionPathExists=/run/exitlane-provider-install/mullvad-early-boot-blocking-allowed' \
    <<<"${early_boot_definition}" ||
    fail "early-boot suppression condition is missing"

  prepare_disconnected_state
  rm -f -- "${COMPLETE_MARKER}"
  start_package_monitor
  SYSTEMD_OFFLINE=1 DEBIAN_FRONTEND=noninteractive \
    apt-get install --reinstall -y -qq mullvad-vpn
  stop_package_monitor

  [[ ! -e "${monitor_dir}/daemon-active" ]] ||
    fail "package transaction activated mullvad-daemon"
  [[ ! -e "${monitor_dir}/early-active" ]] ||
    fail "package transaction activated the early-boot blocker"
  [[ ! -e "${monitor_dir}/firewall-table" ]] ||
    fail "package transaction created a Mullvad firewall table"
  systemctl is-active --quiet "${DAEMON_UNIT}" && fail "daemon active after offline package install"
  systemctl is-active --quiet "${EARLY_BOOT_UNIT}" &&
    fail "early-boot blocker active after offline package install"
  systemctl is-enabled --quiet "${DAEMON_UNIT}" || fail "daemon was not enabled by package"
  systemctl is-enabled --quiet "${EARLY_BOOT_UNIT}" ||
    fail "early-boot unit was not enabled by package"
  firewall_table_present && fail "firewall table existed after offline package install"

  "${HELPER}"
  systemctl is-active --quiet "${DAEMON_UNIT}" || fail "controlled daemon start failed"
  systemctl is-active --quiet "${EARLY_BOOT_UNIT}" &&
    fail "early-boot blocker ran during controlled daemon start"
  provider_disconnected || fail "provider is not disconnected after baseline"
  firewall_table_present && fail "disconnected provider retained a Mullvad firewall table"
  [[ -f "${COMPLETE_MARKER}" ]] || fail "completion marker was not written"
  ip -4 route show default | grep -Eq '^default([[:space:]]|$)' ||
    fail "management/default route is missing"

  test_completed=1
  printf 'PASS: Mullvad package-time services stayed offline; controlled baseline is safe\n'
  printf 'package=%s\n' "$(dpkg-query -W -f='${Version}' mullvad-vpn)"
  printf 'daemon=%s early_boot=%s firewall_table=absent status=disconnected\n' \
    "$(systemctl is-active "${DAEMON_UNIT}")" \
    "$(systemctl is-active "${EARLY_BOOT_UNIT}" || true)"
}

main "$@"
