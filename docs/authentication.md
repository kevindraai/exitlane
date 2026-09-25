# Authentication

Exitlane uses local administrator authentication because the appliance must remain manageable
without an external identity service. The first-run wizard creates the initial account; after
setup, application API access requires an authenticated session.

## Session model

Sessions are server-side and have idle and absolute expiry. The browser receives an opaque
cookie while the stored representation does not contain the reusable token. This allows logout,
expiry, password changes, and account removal to invalidate access centrally.

Cookies are inaccessible to browser scripts and use a same-site policy. Browser write requests
also require a trusted origin. These controls reduce session theft and cross-site request risks,
but they do not replace transport security or correct network isolation.

## Setup boundary

Before setup is complete, only the endpoints needed by the setup flow are available without an
administrator session. Once setup completes, that exception closes. The health endpoint and
session discovery remain public so service monitoring and login routing can work.

## Operational assumptions

Exitlane has one local administrator rather than roles, federation, WebAuthn or API tokens.
Optional TOTP MFA and recovery codes are described in [MFA](security/mfa.md).

Security concerns should follow the private process in [SECURITY.md](../SECURITY.md).

## Password management and recovery

An authenticated administrator can change the password under **Settings → Authentication**.
The current password is verified with the same scrypt implementation and password policy used by
the first-run wizard. A successful change revokes every server-side session, including the
current browser session, so the administrator must sign in again with the new password.

If web login is no longer possible, run the host-only recovery command as root:

```bash
sudo exitlane-cli reset-password
```

The command prompts twice without echo, applies the same password policy, revokes all sessions,
and records a secret-free Activity event. It intentionally has no password argument, HTTP
endpoint, reset token, or remote flow.

## NordVPN token subprocess boundary

NordVPN Linux 5.2 supports a masked interactive token prompt when
`nordvpn login --token` is invoked without a token argument. Exitlane attaches a
private pseudo-terminal, waits until the provider has disabled terminal echo,
then writes the validated token to that terminal. The process argument list
contains only `nordvpn login --token`; the token is never placed in argv, the
environment, stdout or stderr.

Exitlane uses a short timeout and restricted non-secret environment, discards
all provider terminal output for this operation, and never logs, persists,
reflects or adds the token to Activity metadata. This PTY adapter is specific to
the verified NordVPN interface. If NordVPN presents its first-run analytics
consent before the token prompt, Exitlane explicitly answers no. Every provider
must define and test its own secret-input boundary.

The CLI also offers no supported, non-destructive way to validate a replacement token while an
account session is active. Exitlane therefore never logs out automatically or claims that it
validated a replacement. An administrator can instead use this deliberate Settings flow:

1. choose **End current session** and confirm the destructive action;
2. enter the new token after the client reports `signed_out`;
3. sign in again.

NordVPN authentication sign-out and VPN disconnect are different operations. Disconnect ends only
the tunnel, while sign-out runs the supported `nordvpn logout` action, ends the authentication
session, and consequently ends any active tunnel. Normal NordVPN logout also invalidates the
access token used for that session, including a non-expiring token. Generate a new token in Nord
Account before signing in again; reusing the old token is not a renewal test. The separate native
`--persist-token` option is not used by ExitLane
([NordVPN token login and logout documentation](https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-log-in-to-NordVPN-without-a-GUI-using-a-token)).
Activity events record only the provider identifier and a safe failure code.

## Mullvad account and device boundary

The browser uses a masked numeric field and removes its value immediately after starting the
request. The backend normalizes the 16-digit value and submits it only in the HTTPS request body to
Mullvad's fixed authentication origin. It never appears in argv, Activity metadata or responses.

ExitLane encrypts the account number, its generated WireGuard private key and the exact bound device
record with the appliance master key. A pending key record is durable before remote registration,
so an uncertain result can be reconciled by public key without creating another device. Short-lived
access tokens remain in memory only. Safe errors expose no response body or secret value.
See the [Mullvad provider guide](mullvad.md) for operational details.
