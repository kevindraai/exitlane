# Security policy

## Supported versions

Exitlane is pre-release software. Security fixes are provided only for the most recent published
alpha release.

| Version | Supported |
| --- | --- |
| v0.2.0-alpha.1 | Yes |
| v0.1.x | No |

## Reporting a vulnerability

Do not report vulnerabilities through public GitHub Issues, discussions, or pull requests.
Use GitHub private vulnerability reporting when it is available for the repository. Otherwise,
use a private maintainer-contact method listed in the repository or maintainer profile. Include a
clear description, affected version, reproduction steps, impact, and any suggested mitigation. Do
not include credentials, private keys, or personal data that are not required to reproduce the
issue.

Please allow the maintainers time to acknowledge, investigate, and coordinate a fix before public
disclosure. Good-faith research and responsible disclosure are appreciated.

## Scope

In scope are vulnerabilities in the Exitlane backend, browser application, authentication and
session handling, installer and service configuration, provider integration, WireGuard ingress,
and project-owned deployment artifacts.

Third-party services and software—including NordVPN, router firmware, Proxmox, operating-system
packages, and infrastructure not operated by the project—are outside project scope. Reports that
only describe missing hardening on an intentionally trusted management network may be treated as
deployment guidance rather than a product vulnerability.

## Deployment baseline

Keep the management interface on a trusted network, restrict access to Exitlane data and
configuration directories, and rotate any credentials or keys exposed in logs or screenshots.
Exitlane does not currently claim to be safe for direct exposure to the public internet.
