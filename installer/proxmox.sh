#!/usr/bin/env bash
# Small public resolver/UI. All PVE planning and mutation belongs to the tagged engine.
set -Eeuo pipefail
umask 077

fail() { printf 'ExitLane: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail 'Run this on the Proxmox VE host as root.'
[[ -t 0 && -t 1 ]] || fail 'A terminal is required. Use the Python helper for automation.'
[[ $# -eq 0 ]] || fail 'Use EXITLANE_VERSION for an exact release override.'
if ! command -v pveversion >/dev/null || ! pveversion >/dev/null; then
  fail 'Proxmox VE is required.'
fi
for command in curl python3 mktemp; do
  command -v "$command" >/dev/null || fail "Required command unavailable: $command"
done
printf '\nExitLane LXC Installer\nSmart egress for every network\n\n✓ Proxmox VE detected\n'
version=${EXITLANE_VERSION:-}
[[ -z $version || $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || fail 'Invalid release tag.'
bootstrap_dir=$(mktemp -d /tmp/exitlane-bootstrap.XXXXXXXX)
cleanup() { rm -rf -- "$bootstrap_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
fetch() {
  curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 --max-filesize 2097152 \
    --header 'Accept: application/vnd.github+json' \
    --output "$2" "$1"
  [[ -s $2 ]] || fail 'Empty download; nothing will be executed.'
}
api=https://api.github.com/repos/kevindraai/exitlane
if [[ -n $version ]]; then
  fetch "$api/releases/tags/$version" "$bootstrap_dir/releases.json"
else
  fetch "$api/releases?per_page=100" "$bootstrap_dir/releases.json"
fi
# Recommended channel policy: highest semantic stable/RC version in the bounded
# published release window. RCs are intentional; GitHub's /latest is not our policy.
version=$(python3 - "$bootstrap_dir/releases.json" "$version" <<'PY'
import json, re, sys
from datetime import datetime
pattern = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?')
requested = sys.argv[2]
data = json.load(open(sys.argv[1]))
if requested:
    data = [data]
if not isinstance(data, list) or not data or len(data) > 100:
    sys.exit('Invalid release response')
candidates = []
for item in data:
    if not isinstance(item, dict) or type(item.get('draft')) is not bool or type(item.get('prerelease')) is not bool:
        sys.exit('Invalid release response')
    tag = item.get('tag_name')
    if not isinstance(tag, str):
        sys.exit('Invalid release tag')
    match = pattern.fullmatch(tag)
    if item['draft'] or not match:
        if requested:
            sys.exit('Requested release is not a published stable/RC tag')
        continue
    if requested and tag != requested:
        sys.exit('Release response does not match requested version')
    try:
        datetime.strptime(item['published_at'], '%Y-%m-%dT%H:%M:%SZ')
    except (KeyError, TypeError, ValueError):
        sys.exit('Invalid release publication date')
    major, minor, patch, rc = match.groups()
    key = (int(major), int(minor), int(patch), rc is None, int(rc or 0))
    candidates.append((key, tag))
if not candidates:
    sys.exit('No valid published ExitLane release found')
print(max(candidates)[1])
PY
)
printf '✓ Published ExitLane release %s resolved\n' "$version"
[[ $version != *-rc.* ]] || printf '  This is a release candidate.\n'
fetch "$api/contents/installer/create-proxmox-lxc.py?ref=$version" "$bootstrap_dir/helper.json"
fetch "https://raw.githubusercontent.com/kevindraai/exitlane/$version/installer/create-proxmox-lxc.py" "$bootstrap_dir/helper.py"
# Git blob identity detects mismatched/partial payloads. It is not an independent
# signature: metadata and payload both trust this project's GitHub HTTPS origin.
python3 - "$bootstrap_dir/helper.json" "$bootstrap_dir/helper.py" <<'PY'
import hashlib, json, re, sys
metadata = json.load(open(sys.argv[1]))
payload = open(sys.argv[2], 'rb').read()
if (not isinstance(metadata, dict) or metadata.get('type') != 'file'
    or metadata.get('path') != 'installer/create-proxmox-lxc.py'
    or metadata.get('size') != len(payload) or not payload
    or not re.fullmatch(r'[0-9a-f]{40}', str(metadata.get('sha', '')))):
    sys.exit('Invalid tagged helper metadata')
blob = b'blob ' + str(len(payload)).encode() + b'\0' + payload
if hashlib.sha1(blob, usedforsecurity=False).hexdigest() != metadata['sha']:
    sys.exit('Tagged helper integrity mismatch')
PY
printf '\nInstallation mode\n  1. Default settings\n  2. Advanced settings\n  3. Exit\n'
read -r -p 'Choose [1]: ' mode
args=(--ref "$version")
case ${mode:-1} in
  1) ;;
  2)
    # No eval or shell interpolation. Empty optional values use engine defaults.
    fields=(ctid hostname storage template-storage bridge ip gateway dns vlan cores memory disk pool startup)
    labels=('CTID [automatic]' 'Hostname [exitlane]' 'Root storage [automatic]' \
      'Template storage [automatic]' 'Bridge [vmbr0]' 'IPv4/CIDR [dhcp]' \
      'Gateway [none; required for static IPv4]' 'DNS IPv4 [host default]' 'VLAN [none]' \
      'CPU [2]' 'Memory MiB [2048]' 'Disk GiB [16]' 'Pool [none]' 'Startup order [default]')
    for index in "${!fields[@]}"; do
      read -r -p "${labels[$index]}: " value
      [[ -z $value ]] || args+=("--${fields[$index]}" "$value")
    done
    ;;
  3) printf 'Cancelled; no container created.\n'; exit 0 ;;
  *) fail 'Invalid mode; no container created.' ;;
esac
printf '\nThe tagged engine will validate and display the exact plan.\n'
printf 'Creation requires its explicit confirmation; cancelling makes no changes.\n\n'
# One engine invocation computes, confirms and executes one canonical plan.
# rc.3 asks for CREATE; newer engines may use y/N. Never pass --yes here.
# Keep bootstrap downloads private without leaking that policy into pct's guest
# configuration writers (0644 masked by 077 becomes unreadable to APT's _apt).
(umask 022; python3 "$bootstrap_dir/helper.py" "${args[@]}")
