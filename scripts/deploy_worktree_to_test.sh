#!/usr/bin/env bash
set -euo pipefail

HOST="${EXITLANE_TEST_HOST:-exitlane-test}"
SOURCE_DIR="/srv/exitlane/"
REMOTE_DIR="/home/exitlane-test/exitlane-candidate/"

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
