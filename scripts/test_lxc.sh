#!/usr/bin/env bash
set -euo pipefail

BRANCH="${1:-feat/application-state}"
HOST="${EXITLANE_TEST_HOST:-exitlane-test}"
REPO="/srv/exitlane"

ssh "$HOST" bash -s -- "$BRANCH" "$REPO" <<'REMOTE'
set -euo pipefail

BRANCH="$1"
REPO="$2"

cd "$REPO"

git fetch origin
git switch "$BRANCH"
git reset --hard "origin/$BRANCH"

sudo ./installer/install.sh

sudo systemctl restart exitlane
sudo systemctl is-active --quiet exitlane

curl --fail --silent \
  http://127.0.0.1:8787/api/health

echo

echo "Exitlane smoke test passed."
REMOTE
