# HTTPS reverse proxy

ExitLane does not terminate TLS. It trusts `X-Forwarded-For` and `X-Forwarded-Proto` only when the
direct TCP peer is explicitly trusted. Configure it after signing in under
**Settings → Network → Reverse-proxy configuration**, or use `EXITLANE_TRUSTED_PROXIES`.
Environment values are comma-separated IPv4/IPv6 addresses or CIDRs; hostnames and wildcards are
unsupported. Without a trusted peer forwarding headers are
ignored. `X-Forwarded-*` is primary; RFC `Forwarded` is not combined with it.

Addresses are processed right-to-left, removing trusted proxy hops and stopping at the first
untrusted address. Malformed, oversized or overlong chains are ignored. `X-Forwarded-Host` is
never trusted; configure the external origin:

```ini
EXITLANE_TRUSTED_PROXIES=127.0.0.1
EXITLANE_PUBLIC_URL=https://exitlane.example.internal
EXITLANE_SECURE_COOKIES=auto
```

Restart ExitLane after changing environment. Values saved in Settings apply on the next request
without a restart. Serve ExitLane at `/`, not a subpath. Verify status under
**Settings → Network**. Direct HTTP remains available for trusted local networks and warns.
`always` forces Secure cookies; `never` is only for explicit local development. HSTS is emitted
only when HTTPS is reliably detected.

## Configuration precedence and safety

The effective runtime configuration has one defined precedence:

1. `EXITLANE_PUBLIC_URL`, `EXITLANE_TRUSTED_PROXIES`, and
   `EXITLANE_SECURE_COOKIES` when the relevant variable is present;
2. the corresponding value saved under Settings → Network;
3. direct-access defaults: no public URL, no trusted proxy, and automatic cookies.

An environment-controlled field is read-only in the web interface and is marked as managed
through environment configuration. Saving requires the current administrator password and,
when MFA is enabled, a fresh TOTP code. Universal proxy ranges are rejected. Broad private ranges
and changes that may invalidate the current browser origin or trusted peer require an explicit
extra confirmation.

## Caddy

```caddy
exitlane.example.internal {
    reverse_proxy 127.0.0.1:8787 {
        header_up Host {host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto https
        header_up -Forwarded
    }
}
```

## Nginx

```nginx
server {
    listen 443 ssl;
    server_name exitlane.example.internal;
    client_max_body_size 1m;
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Forwarded "";
        proxy_read_timeout 60s;
    }
}
```

## Traefik

Use an HTTP service URL such as `http://127.0.0.1:8787`, attach a TLS router, and configure
Traefik's forwarded-header trusted IPs so client-supplied headers are discarded. Trust only the
exact Traefik peer in ExitLane. Do not enable Traefik's insecure forwarded-header mode.

If the public URL is HTTPS but Settings reports HTTP, check the proxy peer CIDR and that the proxy
overwrites `X-Forwarded-Proto`. Forwarding headers on a direct request are intentionally ignored.

## Nginx Proxy Manager

Create a Proxy Host with these **Details**:

- Domain Name: the public ExitLane hostname, for example `exitlane.example.internal`
- Scheme: `http`
- Forward Hostname / IP: the private ExitLane address
- Forward Port: `8787`
- Websockets Support: off; ExitLane does not currently require it
- Block Common Exploits: enable only after testing that login and API requests still work

Under **SSL**, select a valid certificate and enable Force SSL. HTTP/2 is optional. Enable HSTS
only after the HTTPS deployment works reliably and you have deliberately accepted its persistence.

Nginx Proxy Manager normally supplies `Host`, `X-Real-IP`, `X-Forwarded-For`, and
`X-Forwarded-Proto`; do not add duplicate headers. If an Advanced snippet is necessary because
the local NPM configuration does not overwrite client-supplied values, use only:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

`X-Forwarded-Protocol` is not used by ExitLane. Determine NPM's direct peer as seen by ExitLane
from the host/container network (it may be the NPM container address, Docker gateway, or proxy
host address). Configure exactly that address or the smallest stable CIDR, never an entire broad
RFC1918 range:

```ini
EXITLANE_TRUSTED_PROXIES=<exact-npm-peer-ip-or-small-cidr>
EXITLANE_PUBLIC_URL=https://exitlane.example.internal
EXITLANE_SECURE_COOKIES=auto
```

Restart ExitLane after editing its environment. Then use **Settings → Network** to verify HTTPS,
reverse proxy detection, trusted direct peer, Secure cookies, and the public URL.

When using the Settings flow, the **Direct peer** value is the address that should normally be
trusted for NPM. After saving, sign out and verify a new login through NPM. The status card should
then show HTTPS, reverse proxy, direct peer trusted, and secure cookie as active. ExitLane never
shows the raw forwarding-header chain.

Origin and other deployment-security rejections happen before credentials are evaluated. They
do not create the misleading `auth.login_failed` Activity event. ExitLane emits only a bounded,
reason-code-only warning in the service security log (`invalid_origin` or
`deployment_origin_mismatch`); it never logs raw origins, proxy headers, usernames, request
bodies, or credentials for these rejections.

## Local recovery

If a saved value blocks browser access, use the local appliance console:

```console
sudo exitlane-cli network-status
sudo exitlane-cli reset-network-security
```

The reset command requires typing `RESET NETWORK SECURITY`, restores the database values to
direct-access defaults, revokes every session, and records a safe Activity event. Environment
overrides remain active; change those in the service or container configuration and restart
ExitLane when an override caused the lockout.
