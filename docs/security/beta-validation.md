# Beta candidate validation record

Candidate validation date: 2026-07-25 UTC. Target scope was exclusively
`172.16.130.81` (`test-exitlane`, Debian 13). The previously configured
`exitlane-test` SSH alias resolved to `172.16.130.129` and was not touched.
The correct existing alias was `exitlane-reference`. The deployment helper now
defaults to that alias and verifies the exact target IP before copying files.

## Completed evidence

- Installed exact alpha baseline
  `11bc3bf4ab4314d9812e67fdfff0c609ca783751` on the initially clean LXC.
- Alpha health returned `0.2.0-alpha.1`; database, master key, and WireGuard
  files were root-owned with mode `0600`.
- Created representative Dutch/Amsterdam/dark/dashboard settings, a local
  administrator, TOTP MFA, ten one-time recovery codes, one session, trusted
  proxy data, and WireGuard server/client configuration. No real provider token
  was stored.
- Upgraded alpha to beta with a root-only pre-upgrade recovery snapshot.
  Version `0.2.0-beta.1`, schema 1, settings, MFA, recovery codes, session,
  master key, and WireGuard configuration survived.
- Re-ran the beta installer successfully and idempotently.
- Created, inspected, and verified an encrypted four-component `.elb` backup.
- Changed persisted data, restored the backup, observed the previous data,
  retained MFA/WireGuard, revoked all sessions, and received healthy beta HTTP
  status before the restore command returned.
- Wrong passphrase and modified ciphertext both failed with the same safe
  `authentication_failed` code while active data and health remained intact.

## Findings produced by appliance testing

| Severity | Finding | Resolution / regression | Status |
| --- | --- | --- | --- |
| High | PEP 440 alpha `0.2.0a1` was misclassified as newer than the human beta string by `dpkg` | Compare installed PEP 440 version with explicit target `0.2.0b1`; installer regression | Resolved |
| High | Restore returned before HTTP health was established | Bounded local health wait; unhealthy restore triggers data rollback; regression simulates failed health | Resolved |
| High | Explicit installer `fail()` bypassed the `ERR` trap and rollback | `fail()` now invokes rollback directly; regression verifies the callback | Resolved |
| High | Rollback copied the recovery staging directory itself onto `/`, applying its `0700` mode to the root directory | Restore only each saved top-level directory's contents; regression prohibits the unsafe copy | Code resolved; appliance recovery required |
| Medium | Repository deploy alias pointed at `.129`, not the authorized `.81` target | Default to `exitlane-reference` and fail closed unless remote IP is exactly `.81` | Resolved |

## Open release blocker

The final rollback finding changed `/` on the test LXC to mode `0700`. ExitLane
itself remains reachable and healthy at `172.16.130.81:8787`, with beta health
confirmed after the incident, but the non-root SSH account can no longer execute
`sudo`. The existing key does not permit direct root SSH. An authorized host
administrator must run:

```bash
chmod 0755 /
```

from the LXC console or equivalent trusted root channel, then confirm `/dev` and
normal system paths retain their expected modes. Until that recovery is
performed, clean/disaster restore, the corrected rollback re-test, NordVPN,
killswitch appliance checks, and dynamic authenticated scanning remain
incomplete. Pull request #34 must remain draft.

The provider wizard was not completed because no test NordVPN token was supplied.
Setup completion was set locally only to create migration evidence; this is not
claimed as a successful end-to-end wizard/provider test.
