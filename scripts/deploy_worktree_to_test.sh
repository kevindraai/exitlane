#!/usr/bin/env bash
set -euo pipefail

HOST="${EXITLANE_TEST_HOST:-exitlane-reference}"
EXPECTED_TEST_IP="${EXITLANE_TEST_IP:-172.16.130.81}"
SOURCE_DIR="/srv/exitlane/"
REMOTE_DIR="/home/exitlane-test/exitlane-candidate/"

REMOTE_IPS="$(ssh "$HOST" hostname -I)"
if ! tr ' ' '\n' <<<"$REMOTE_IPS" | grep -Fx -- "$EXPECTED_TEST_IP" >/dev/null; then
  echo "Refusing deployment: $HOST is not the expected test LXC $EXPECTED_TEST_IP." >&2
  exit 1
fi

rsync -az --delete \
  --exclude ".git/" \
  --exclude "backend/.venv/" \
  --exclude "backend/dist/" \
  --exclude ".pytest_cache/" \
  --exclude "__pycache__/" \
  "$SOURCE_DIR" \
  "$HOST:$REMOTE_DIR"

# REMOTE_DIR is a fixed repository constant, not operator or remote input.
# shellcheck disable=SC2029
ssh "$HOST" \
  sudo bash "${REMOTE_DIR}installer/install-debian.sh"
