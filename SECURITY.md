# Security policy

## Supported versions

ExitLane remains pre-release software. Security fixes target the most recent published release or
release candidate. This policy accompanies `v0.3.0-rc.1` and takes effect when that candidate is
published; a preparation branch or draft release does not supersede the current published version.

| Version | Supported |
| --- | --- |
| v0.3.0-rc.1 | Yes, upon publication |
| v0.2.0 | Superseded upon publication of v0.3.0-rc.1 |
| Earlier prereleases and v0.1.x | No |

See the [published releases](https://github.com/kevindraai/exitlane/releases) for availability.
The historical `v0.2.0` tag reports application version `0.2.0-rc.1` and Python package version
`0.2.0rc1`; include both the tag and reported runtime version in reports about that release.

## Reporting a vulnerability

Do not report vulnerabilities through public GitHub Issues, discussions, or pull requests.
Use GitHub private vulnerability reporting when it is available for the repository. Otherwise,
use a private maintainer-contact method listed in the repository or maintainer profile. Include a
clear description, affected version, reproduction steps, impact, and any suggested mitigation. Do
not include credentials, private keys, or personal data that are not required to reproduce the
issue.

Please allow the maintainers time to acknowledge, investigate, and coordinate a fix before public
disclosure. Good-faith research and responsible disclosure are appreciated.

Reports are triaged by exploitability, required privilege, exposure and impact on credentials,
routing and host control. No fixed response time is promised. Fixes are coordinated privately and
published through an advisory when operators need to act; request a CVE only when ecosystem impact
warrants one. Rotate any session, provider credential or WireGuard key that may have been exposed.
Pre-release fixes normally ship forward, with backports considered only for materially deployed
older candidates.

TOTP MFA reduces the impact of a stolen password but is not phishing-resistant. Keep recovery
codes offline. The SQLite database and `/etc/exitlane/secret.key` are jointly sensitive and must
be preserved together for operator-managed disaster recovery. The same master key protects
ExitLane-owned Mullvad account and WireGuard device state. Encrypted backups therefore contain
provider credentials as well as administrator and MFA data.

## Scope

In scope are vulnerabilities in the Exitlane backend, browser application, authentication and
session handling, installer and service configuration, provider integration, WireGuard ingress,
and project-owned deployment artifacts.

Third-party services and software—including NordVPN, Mullvad, router firmware, Proxmox, operating-system
packages, and infrastructure not operated by the project—are outside project scope. Reports that
only describe missing hardening on an intentionally trusted management network may be treated as
deployment guidance rather than a product vulnerability.

## Deployment baseline

Keep the management interface on a trusted network, restrict access to Exitlane data and
configuration directories, and rotate any credentials or keys exposed in logs or screenshots.
Exitlane does not currently claim to be safe for direct exposure to the public internet.

The supported OS and architecture are Debian 13 on `amd64`; the qualified Proxmox baseline is a
privileged LXC. ExitLane needs root-level network administration to operate its gateway interfaces.
Use a dedicated appliance and keep local console recovery available. Docker, unprivileged LXC,
other Debian releases and other architectures are not supported release targets.

Mullvad egress currently supports IPv4. Its mandatory routing guard protects active and interrupted
connections, while the optional ExitLane killswitch controls whether routed clients may use direct
egress after an explicit disconnect. See the [Mullvad operator guide](docs/mullvad.md).
