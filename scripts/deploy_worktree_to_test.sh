#!/usr/bin/env bash
set -euo pipefail

HOST="${EXITLANE_TEST_HOST:-exitlane-reference}"
EXPECTED_TEST_IP="${EXITLANE_TEST_IP:-172.16.130.81}"
SOURCE_DIR="/srv/exitlane/"
REMOTE_DIR="/home/exitlane-test/exitlane-candidate/"

# The expected IP is intentionally expanded as a separately quoted remote argv value.
# shellcheck disable=SC2029
if ! ssh "$HOST" \
  'hostname -I | tr " " "\n" | grep -Fx -- "$1" >/dev/null' \
  _ \
  "$EXPECTED_TEST_IP"; then
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

ssh "$HOST" \
  sudo /usr/local/sbin/install-exitlane-candidate
