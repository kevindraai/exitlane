# ADR-001: Managed Ookla Speedtest installation

- Status: Accepted
- Date: 2026-08-23
- Release: `0.2.0-beta.3`

## Context

Diagnostics can run the official Ookla `speedtest` CLI only as an explicit administrator action.
When the executable is absent, the current release can report only that the tool is unavailable.
Installing it introduces a proprietary binary, package mutation, license and privacy terms, and a
new authenticated path to a privileged host operation.

Ookla publishes Speedtest CLI for personal, non-commercial use. ExitLane cannot broaden those
terms. Commercial or general use therefore remains unsupported until the operator has separate
permission or suitable terms from Ookla.

Ookla's Debian instructions use a remotely downloaded Packagecloud repository script. Running a
mutable remote script as root or retaining a third-party APT repository and signing key would
create a broader and longer-lived trust boundary than this beta feature requires.

## Decision

ExitLane beta.3 supports managed installation only when all of these conditions are met:

- the appliance runs Debian 13 on `amd64`;
- an authenticated administrator explicitly confirms that the use is personal and
  non-commercial;
- that administrator explicitly accepts the applicable Ookla license and privacy/GDPR terms for
  the appliance;
- the administrator confirms the Debian package mutation;
- the installer downloads only the official Packagecloud artifact
  `speedtest_1.2.0.84-1.ea6b6773cf_amd64.deb` and verifies SHA-256
  `35e084567a6388631fb10cf01e5e0d6b57a67d34ede2b72ba111b3d9164c8b94` before installation.

The implementation must not execute Packagecloud's repository script, add an APT source, import
or retain a signing key, or substitute Debian's unrelated `speedtest-cli` package. Other operating
systems and architectures return an honest unsupported capability.

A dedicated, fixed-purpose root helper and oneshot systemd unit own the installation. They use
fixed argument lists, an exclusive package-operation lock, bounded downloads and package commands,
root-only temporary files, allowlisted phases and stable error codes. Browser responses never
contain package output, repository details or arbitrary subprocess text. The operation can be
reconciled and resumed after a page reload through authenticated status polling.

Installation and measurement remain separate operations. A successful install never starts a
Speedtest. The administrator must deliberately select Speedtest again, and terms acceptance must
be visible before an installed CLI is invoked with `--accept-license` and `--accept-gdpr`.

## Consequences

- The package is reproducible and reviewable, but does not receive automatic updates. Every future
  version or architecture requires a new artifact and digest review.
- The pinned proprietary release is old and has no transparent source or dependable public release
  cadence. Operators must treat that as residual supply-chain risk.
- No repository or signing-key rollback is necessary because neither is added. Failed downloads or
  checksum checks leave no durable package trust. A partial dpkg failure is reported with a stable
  recovery code and can be retried after local operator diagnosis.
- A pre-existing administrator-owned CLI is not silently removed. An incompatible or unknown tool
  is reported honestly instead of being treated as the official CLI.
- Commercial or general use remains blocked unless Ookla grants permission or appropriate terms.

## Sources

- Ookla Speedtest CLI and Debian installation options: <https://www.speedtest.net/apps/cli>
- Pinned Debian 13 amd64 package and checksum:
  <https://packagecloud.io/ookla/speedtest-cli/packages/debian/trixie/speedtest_1.2.0.84-1.ea6b6773cf_amd64.deb/download.deb?distro_version_id=221>
- Ookla EULA: <https://www.speedtest.net/about/eula>
- Ookla Terms of Use: <https://www.speedtest.net/about/terms>
- Ookla Privacy Policy: <https://www.speedtest.net/about/privacy>
