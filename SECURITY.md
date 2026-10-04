# Security policy

## Supported versions

ExitLane remains pre-release software. Security fixes target the most recent published release or
release candidate. This policy accompanies `v1.0.0-rc.1` and takes effect when that candidate is
published; a preparation branch or draft release does not supersede the current published version.

| Version | Supported |
| --- | --- |
| v1.0.0-rc.1 | Yes, upon publication |
| v0.3.0-rc.3 and earlier | Superseded upon publication of v1.0.0-rc.1 |
| v0.2.0 | No |
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
Use a dedicated appliance and keep local console recovery available. Unprivileged LXC, other Debian releases and other architectures are outside native support.
The Docker v1 target is rootful Linux amd64, Engine >=28 and Compose v2, NET_ADMIN/TUN,
read-only root and a private durable state volume; see the [Docker deployment guide](docs/docker-deployment.md).
Final stable-image qualification/publication and anonymous pull remain required before announcing availability.

Mullvad egress currently supports IPv4. Its mandatory routing guard protects active and interrupted
connections, while the optional ExitLane killswitch controls whether routed clients may use direct
egress after an explicit disconnect. See the [Mullvad operator guide](docs/mullvad.md).

## v1 release vulnerability decisions

The Product Owner's 2026-10-04 release policy applies to native Debian and the Docker
image. Preserve complete scanner results and original severities. Secrets, materially
applicable application/shared dependency vulnerabilities, supported fixes not consumed,
concrete exploitable conditions we can remediate, and security/isolation regressions block
release. Application/Python HIGH/CRITICAL findings remain conservatively blocking in the
Docker automated gate; they cannot borrow an OS risk disposition.

An upstream Debian vulnerability with no supported fix can be a documented residual platform
risk after exact CVE/package/version/severity review, applicability assessment and available
mitigations. It does not indefinitely prevent publication. Unsupported-suite substitution,
manual replacement of distribution libraries, severity changes and scanner ignores are forbidden.
The [native disposition](docs/qualification/native-os-advisories-2026-10-03.json) retains the
native inventory; the [Docker residual manifest](docs/security/docker-residual-risks.json)
records exactly reviewed Debian image identities and prerequisite/mitigation evidence.
These historical inventories must be reconciled against each new release scan.

The Docker workflow retains full Trivy JSON and a separate decision report bound to its SHA-256.
`scripts/check_release_scan.py` blocks every secret, every HIGH/CRITICAL application finding,
every HIGH/CRITICAL finding with a supported scanner fix, and every unreviewed HIGH/CRITICAL
OS identity. Only unfixed, exact reviewed Debian identities receive residual status. A changed
package version, CVE, severity or distribution requires fresh review. Scan errors or missing OS/
Python coverage fail closed. Review new scanner findings through a normal independently reviewed
PR, rather than adding ignores. Runtime/security qualification remains mandatory independently
of scanner disposition. Maintainers monitor Debian updates and consume supported fixes in the
next applicable release; operators keep their Docker host and native appliance maintained.
