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

## NordVPN token subprocess exception

The supported upstream NordVPN CLI requires headless token login as
`nordvpn login --token <token>` and documents no stdin- or file-based alternative. Only for this
provider operation, Exitlane therefore supplies the token temporarily as a local subprocess
argument. Local accounts with sufficient process-inspection privileges may be able to observe it
during that short operation.

Exitlane invokes a fixed argument array without a shell, uses a short timeout and restricted
non-secret environment, and never logs, stores in its own configuration, reflects, or adds the
token to Activity metadata. This is an upstream provider-interface limitation. Future providers
must not inherit this exception automatically.

The CLI also offers no supported, non-destructive way to validate a replacement token while an
account session is active. Exitlane therefore never logs out automatically or claims that it
validated a replacement. An administrator can instead use this deliberate Settings flow:

1. choose **End current session** and confirm the destructive action;
2. enter the new token after the client reports `signed_out`;
3. sign in again.

NordVPN authentication sign-out and VPN disconnect are different operations. Disconnect ends only
the tunnel, while sign-out runs the supported `nordvpn logout` action, ends the authentication
session, and consequently ends any active tunnel. A valid token is required to sign in again.
Activity events record only the provider identifier and a safe failure code.
