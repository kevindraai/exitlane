#!/usr/bin/env bash
# Reviewed upstream release digests freeze artifact integrity, not vendor authenticity.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: install_security_cli.sh syft|trivy|gitleaks' >&2
  exit 2
fi
case "$1" in
  syft)
    project=anchore/syft
    version=1.42.2
    archive=syft_1.42.2_linux_amd64.tar.gz
    digest=1d3cc98b13ce3dfb6083ef42f64f1033e40d7dea292e8ea85ed1cf88efb2f542
    ;;
  trivy)
    project=aquasecurity/trivy
    version=0.69.3
    archive=trivy_0.69.3_Linux-64bit.tar.gz
    digest=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
    ;;
  gitleaks)
    project=gitleaks/gitleaks
    version=8.30.1
    archive=gitleaks_8.30.1_linux_x64.tar.gz
    digest=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    ;;
  *)
    echo 'security_cli_unknown' >&2
    exit 2
    ;;
esac
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'security_cli_platform_unsupported' >&2
  exit 1
}
tool=$1
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
curl --fail --silent --show-error --location --retry 3 \
  --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 \
  "https://github.com/${project}/releases/download/v${version}/${archive}" \
  -o "$scratch/$archive"
printf '%s  %s\n' "$digest" "$scratch/$archive" | sha256sum --check --status
# Select only the required binary after the archive has passed its recorded hash.
tar -xzf "$scratch/$archive" -C "$scratch" "$tool"
sudo install -m 0755 "$scratch/$tool" "/usr/local/bin/$tool"
"/usr/local/bin/$tool" version
