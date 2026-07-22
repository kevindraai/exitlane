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
