# Startup lifecycle

Startup is treated as a mode decision followed by mode-specific loading. This ordering prevents
the browser from requesting protected data before it knows whether setup is complete and whether
the user has an authenticated session.

## Cold start

A cold start first establishes basic application availability and session state. Session state
provides the two facts needed for routing: whether first-run setup is complete and whether the
current browser is authenticated. Exitlane then selects exactly one application mode before it
loads data for that mode.

If session discovery fails, startup does not guess a mode or continue with protected loading. This
favors a visible startup failure over an inconsistent or partially authorized interface.

Backend startup also reconciles the appliance timezone before serving normal operations. When an
explicit valid ExitLane timezone exists, it is authoritative and Debian is converged to that IANA
timezone. A match is a no-op. An invalid stored value, unreadable system timezone, or failed native
change is recorded as a stable Activity error and surfaced in Settings; the service remains
available for an administrator to recover the configuration.

## Wizard

An incomplete setup selects wizard mode. Only setup data and public configuration needed for the
guided flow are loaded. The wizard owns the progression through system checks, administrator
creation, provider choice, WireGuard setup, and completion. Provider choice is an independent
multi-select: none, NordVPN, Mullvad VPN, or both. Selected providers can be installed,
authenticated, or individually skipped. One ready provider becomes active automatically; multiple
ready providers require an explicit active choice. Deferred mode keeps the normal host route as
egress for WireGuard clients and leaves provider installation/authentication available in the
authenticated VPN management view after setup.

Completing setup causes the application to reassess its session and mode rather than layering the
dashboard over wizard state. This creates a clean boundary between initial provisioning and normal
operation.

## Login

Completed setup without an authenticated session selects login mode. Protected operational data
is not loaded and no operational poller runs. A successful login starts a fresh application
evaluation so server-confirmed session state determines entry to the dashboard.

## Dashboard

An authenticated session selects dashboard mode before dashboard data is requested. Public
configuration and the data needed by the active view are then loaded. Establishing the mode first
ensures that any later loading failure remains a dashboard-local error instead of producing an
ambiguous transition.

Polling starts only after authenticated dashboard startup. It follows the active view: dashboard,
provider, and WireGuard polling are lifecycle responsibilities rather than permanent background
tasks. View changes synchronize which poller is active, and preference changes restart polling
with the confirmed interval.

## Mode transitions and logout

Wizard, login, and dashboard are mutually exclusive application modes. Transitions re-render the
application shell and synchronize the lifecycle; data loading does not choose or implicitly alter
the mode.

Logout invalidates the server session, stops polling, clears authenticated status, and selects
login mode. An HTTP 401 follows the same client-side boundary even when it occurs during a refresh.
This prevents stale operational data or background work from surviving loss of authentication.
