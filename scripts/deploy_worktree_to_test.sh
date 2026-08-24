#!/usr/bin/env bash
set -euo pipefail

HOST="${EXITLANE_TEST_HOST:-exitlane-reference}"
EXPECTED_TEST_IP="${EXITLANE_TEST_IP:-172.16.130.81}"
SOURCE_DIR="/srv/exitlane/"
REMOTE_BASE="/home/exitlane-test"

REMOTE_IPS="$(ssh "$HOST" hostname -I)"
if ! tr ' ' '\n' <<<"$REMOTE_IPS" | grep -Fx -- "$EXPECTED_TEST_IP" >/dev/null; then
  echo "Refusing deployment: $HOST is not the expected test LXC $EXPECTED_TEST_IP." >&2
  exit 1
fi

REMOTE_DIR="$(ssh "$HOST" mktemp -d "${REMOTE_BASE}/exitlane-candidate.XXXXXXXX")"
if [[ ! "$REMOTE_DIR" =~ ^/home/exitlane-test/exitlane-candidate\.[A-Za-z0-9]+$ ]]; then
  echo "Refusing deployment: invalid remote staging path." >&2
  exit 1
fi

cleanup_remote_staging() {
  # REMOTE_DIR is accepted only after the exact fixed-prefix validation above.
  ssh "$HOST" rm -rf -- "$REMOTE_DIR"
}
trap cleanup_remote_staging EXIT

rsync -az --delete \
  --exclude ".git/" \
  --exclude ".agents/" \
  --exclude ".codex/" \
  --exclude ".ruff_cache/" \
  --exclude "backend/.venv/" \
  --exclude "backend/dist/" \
  --exclude ".pytest_cache/" \
  --exclude "__pycache__/" \
  "$SOURCE_DIR" \
  "$HOST:${REMOTE_DIR}/"

# REMOTE_DIR is a fixed repository constant, not operator or remote input.
# shellcheck disable=SC2029
ssh "$HOST" \
  sudo bash "${REMOTE_DIR}/installer/install-debian.sh"
