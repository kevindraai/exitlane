#!/usr/bin/env bash
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; TARGET=/opt/exitlane
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ -e /dev/net/tun ]] || { echo "/dev/net/tun is missing"; exit 1; }
apt-get update
apt-get install -y python3 python3-venv python3-pip wireguard-tools iptables curl iproute2 rsync
install -d -m 0755 "$TARGET"; install -d -m 0700 /etc/exitlane
rsync -a --delete --exclude .git "$SRC/" "$TARGET/"
python3 -m venv "$TARGET/venv"
"$TARGET/venv/bin/pip" install --upgrade pip
"$TARGET/venv/bin/pip" install "$TARGET/backend"
install -m 0644 "$TARGET/systemd/exitlane.service" /etc/systemd/system/exitlane.service
[[ -f /etc/default/exitlane ]] || install -m 0600 "$TARGET/installer/exitlane.default" /etc/default/exitlane
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-exitlane.conf; sysctl --system >/dev/null
systemctl daemon-reload; systemctl enable --now exitlane
IP="$(ip -4 -o addr show scope global | awk '$2!="lo"{split($4,a,"/");print a[1];exit}')"
echo "Open http://${IP}:8787"
