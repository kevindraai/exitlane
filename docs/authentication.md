# Authentication

Exitlane uses local administrator authentication because the appliance must remain manageable
without an external identity service. The first-run wizard creates the initial account; after
setup, application API access requires an authenticated session.

## Session model

Sessions are server-side and expire after a configured lifetime. The browser receives an opaque
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

Exitlane currently has a local administrator model rather than roles, federation, multi-factor
authentication, or API tokens. Keep the interface on a trusted management network. Where HTTPS is
terminated by a reverse proxy, configure secure cookies and preserve same-origin access.

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
