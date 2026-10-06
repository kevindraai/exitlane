# Read-only native package and advisory qualification

`scripts/qualification/native_security.py` collects evidence for a maintainer's
security decision on a **native Debian 13 amd64 ExitLane appliance**. It is a
post-v1 collector, separate from the mutating disposable lifecycle runners and
from Docker image qualification. It does not waive findings, approve a release,
apply maintenance or describe the appliance as secure.

## Plan and execution

Run from an exact committed checkout. The supplied application checkout must
match the installed public package content; the collector independently binds
its own four modules to its committed source. Content equivalence does **not**
recover the historical build commit when the installer did not retain it.

The default command prints the intended observations without reading target
metadata, invoking tools or creating an output directory:

```bash
python3 -I -S -B /root/exitlane-candidate/scripts/qualification/native_security.py \
  --application-source /root/exitlane-candidate \
  --output /root/native-security-2026-10-06
```

Add `--execute` to perform that read-only plan. Select pre-existing tools and a
pre-populated Trivy database when they are outside the defaults:

```bash
python3 -I -S -B /root/exitlane-candidate/scripts/qualification/native_security.py \
  --application-source /root/exitlane-candidate \
  --output /root/native-security-2026-10-06 \
  --trivy /root/qualification-tools/trivy \
  --trivy-cache /root/qualification-tools/trivy-cache \
  --pip-audit /root/qualification-tools/bin/pip-audit \
  --allow-network --debian-tracker /root/debian-security-tracker.json \
  --simulate-apt --service exitlane.service --library libssl.so.3 \
  --execute
```

The output must be a **new absolute directory**, outside the source and installed
venv. Directory mode is `0700`; receipt/report files are `0600`. Only that output
is written. The collector never installs tools or updates vulnerability databases.
`--allow-network` permits PyPI advisory requests for exact observed versions using
pip-audit with dependency resolution and pip execution disabled. It does not
permit package downloads, APT network operations or maintenance. Without it,
nonempty Python audit layers explicitly remain incomplete.

Supply an operator-obtained primary Debian security tracker JSON snapshot with
`--debian-tracker` when classifying Debian fixes. Its hash is retained; its origin
is an **operator assertion**, not authenticated by the collector. Obtain it from
[Debian's security tracker](https://security-tracker.debian.org/tracker/data/json)
through a separately trusted workflow. No live mirror/API access is required by
the fixture tests. A scanner's `FixedVersion` alone is never proof of an eligible
native fix.

## Receipt and worksheet

One observation set produces `receipt.json` and `worksheet.txt`. Schema version
`1` contains UTC observation bounds, per-section status/data/reason, native and
Python findings, applicability classifications and hashes/sizes of retained public
inputs and reports. SHA-256 uses canonical sorted JSON for structural inputs;
valid scanner reports retain their original bytes. A malformed or non-allowlisted
report is **not** written: only its hash, size and failure reason remain. Its
findings are unavailable, never replaced by a zero count.
This intentionally also rejects an advisory description containing a literal
userinfo URL such as `https://user@example.com`, even when it is a public example.
Scanner execution can therefore succeed while report export fails. No advisory
is removed or rewritten to obtain a complete receipt.

Statuses mean:

- `complete`: the declared evidence collection succeeded within its stated scope;
  it does not mean no vulnerabilities, proven exploitability or release approval.
- `incomplete`: missing identity, coverage, permission, source/trust or observation;
  inspect the section reason and limitations.
- `error`: invalid inputs, failed query/scanner, missing/malformed result or another
  failed required observation. Findings from a failed invocation are still retained
  when the report is structurally valid and public.
- `skipped`: justified optional observation, such as no requested library or no
  supplied primary advisory snapshot. Required skipped observations cannot make
  collection complete.

The command exits `0` for complete collection and `2` for incomplete/error.
There is no blanket vulnerability PASS/FAIL. The worksheet summarizes identities,
coverage, unresolved/skipped work, scanner/database metadata, candidate categories,
APT projection and library observations; the raw reports remain authoritative.
Database timestamps and hashes are recorded. Maintainers assess database freshness;
an offline scan is not proof that all currently published advisories were known.

Native binding includes OS/release/suite/architecture, dpkg tool identity, a hash
of machine identity, installed ExitLane metadata/RECORD and public content hashes,
application source commit/tree and collector commit/tree/module hashes. dpkg
records retain installed, residual/config-only and other states separately.
Residual records are not counted as installed software. Scanner coverage is
reconciled against exact installed binary/architecture/version/source tuples.
The Trivy target is a private **native package-metadata projection**, not a full
filesystem or loaded-code scan, Docker inventory or the Python venv. Package
inventory is queried again at the end; changes make the receipt incomplete.

Python evidence separates OS interpreter/stdlib identity and distributions,
current ensurepip/bootstrap wheels, bundled dependencies by parent and layer,
and actual final ExitLane venv third-party distributions. Interpreter binary hashes
are retained. Probes use `-I -S -B`: no application import, `.pth`, sitecustomize or
bootstrap execution. Different embedded versions are audited separately. Missing
vendor manifests and unauditable packages are explicit gaps/skips. Current wheels
cannot establish what executed historically during installation; a clean final
venv cannot qualify that bootstrap history.

## APT candidates and simulation

The collector inspects a private, controlled copy of existing public package
metadata. It uses an early private `APT_CONFIG`, disables host configuration and
hooks, redirects state/cache/log paths, supplies a refusing acquisition-method
implementation and never downloads or modifies host packages. It does **not**
preserve arbitrary host source-list/pinning configuration: the receipt explicitly
calls this a **controlled captured-cache projection**, not the host's configured
transaction or authorization to apply an update.

Candidate authentication checks Debian archive signatures with `gpgv`, signed
Release-to-Packages hashes and exact package/source identity. Missing, expired or
unverified archive evidence remains incomplete/unresolved; Origin labels alone
are not authentication. Classification compares the actual source version and
primary trixie advisory fixed version, including epochs and binary rebuilds.
Categories distinguish a supported fix in the captured cache, a primary fix absent
from that cache, distribution unfixed/not-affected, residual not-installed and
unresolved. They are evidence organization, not application exploitability decisions.

`--simulate-apt` adds `apt-get --simulate --no-download` in the private projection.
Every selected upgrade/addition is bound to its own source/version and eligible
signed index; removals, holds, unbound changes and indirect provider-client changes
make the projection ineligible. NordVPN packages remain a separate qualification
boundary. A simulation is neither an applied update nor post-update validation.
Actual updates, repository changes, provider updates and restart/reboot require
separate operator authorization and subsequent qualification.

## Selected loaded-library evidence

`--service` selects `exitlane.service` or `nordvpnd.service`; `--library` selects
one system-library basename. Only that service's MainPID and selected public
library mappings are examined. Observations include PID/start ticks, boot hash,
path, deleted flag, mapped device/inode and current path device/inode. Process
identity is checked again afterwards. Permissions, process changes and absent
selected mappings remain incomplete; absence is not proof that stale code cleared.
Installed dpkg version alone never establishes the loaded library version.

For a post-maintenance comparison, also pass `--maintenance-receipt` pointing to a
previous native collector receipt. It must name the same machine/service/library,
precede the new observation and contain valid public identities. Fresh process/boot
and mapping observations show whether a process restart/boot change occurred and
whether previously stale mappings cleared. Previous application/package hashes and
receipt hash bind the comparison. The supplied receipt is not authenticated, and
this does not prove who performed or authorized maintenance. The collector never
restarts a service or reboots the appliance.

## Privacy and boundaries

Evidence is allowlisted before retention. No environment, process arguments,
process memory, `/proc/*/environ`, application configuration, SQLite contents,
backups, sessions, private keys, provider responses or credentials are collected.
Public metadata reads reject unsafe symlinks/ancestors and are bounded; the
standard Debian os-release/keyring aliases resolve only to their explicit public
canonical paths; child tools
receive a minimal environment, not the operator's credentials. Arbitrary stderr is
hashed rather than exported. Unknown/private scanner fields and credential-bearing
source URLs are rejected. Do not publish receipts automatically: package inventory,
public advisory descriptions and stable machine hashes can still be operationally
sensitive. Review artifacts before sharing.

Docker's qualified image/release path is unchanged. Native package receipts do not
substitute for Docker scans, dataplane tests, lifecycle evidence or maintainer
applicability review. v1.0.0 and its completed #87/#90/#97 gates and historical
receipts remain immutable; this collector delivers post-v1 issue #125.
