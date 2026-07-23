# Multifactor authentication

ExitLane supports RFC 6238 TOTP with SHA-1, six digits and a 30-second step. Enable it under
**Settings → Authentication**. Re-enter the current password, scan the locally generated QR code
(or enter the setup key), and confirm a current code. MFA is not enabled until confirmation.

Ten high-entropy recovery codes are shown exactly once. Store them offline. Each code is
case-insensitive, accepted once, and stored only as a keyed SHA-256 digest. Regeneration requires
the password and a current authenticator code and invalidates every old code and other session.

The TOTP secret and pending enrollments are encrypted with AES-256-GCM using
`/etc/exitlane/secret.key`. Pending enrollment expires after ten minutes. Successfully accepted
TOTP counters are updated transactionally so a code cannot be replayed.

Disabling MFA in the UI requires the password and current TOTP and ends every session. If the
authenticator and all recovery codes are lost, run locally as root:

```bash
sudo exitlane-cli disable-mfa
```

There is no remote bypass. If the masterkey is lost or cannot decrypt the secret, login does not
fall back to password-only; use the same local command. Preserve the database and masterkey
together in any operator-managed backup. ExitLane has no built-in backup/restore feature.

TOTP is not phishing-resistant. Verify the ExitLane origin before entering a code.
