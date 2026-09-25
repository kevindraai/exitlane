# Optional provider onboarding

Status: implemented; extended by multi-provider onboarding on 2026-08-28

Branch: `feat/optional-provider-onboarding`

Baseline: `0c5c9d1` (`origin/main`, fetched 2026-08-22)

## Problem

The first-run wizard currently treats successful authentication to the selected commercial VPN
provider as mandatory. This prevents a valid deployment in which ExitLane terminates WireGuard
for remote clients and sends their traffic through the appliance's normal internet route. Provider
installation and authentication already remain available in the authenticated management UI, so
the wizard requirement is stricter than the runtime architecture.

## Scope and decisions

1. Add an explicit, provider-neutral `deferred` onboarding choice. It means no commercial egress
   provider is configured yet; it does not pretend that the provider is authenticated or healthy.
2. Persist the choice as `setup_provider_deferred`. The provider wizard step is complete when the
   selected provider is authenticated or onboarding has been deferred. The setup-state response
   exposes both `provider_authenticated` and `provider_deferred` so clients do not have to infer the
   distinction from one boolean.
3. Add `POST /api/setup/provider/defer`. It is available only during incomplete setup, requires the
   authenticated local administrator created in step 2, requires completed system/admin
   prerequisites, sets the current step to WireGuard, and contains no provider-specific behavior.
4. Successful provider authentication clears the deferred choice. Installing a provider alone does
   not: the existing wizard still requires either authentication or an explicit defer decision.
5. Present a clear secondary action in step 3. Explain that WireGuard clients will use ExitLane's
   normal internet connection until a provider is configured, that provider setup remains available
   later under VPN management, and that a provider VPN/killswitch is not active in this mode.
6. Completion renders the provider item as `Deferred`, not `Ready`. The next button and step marker
   accept the deliberate deferred state while provider installation/authentication controls remain
   usable when the user navigates back.
7. WireGuard ingress uses the appliance's main default-route interface. Provider clients change
   that route when connected; provider-specific interface names do not belong in generated
   WireGuard rules. The installer includes the iptables compatibility frontend used by `wg-quick`;
   on current Debian it applies these rules through the nftables backend.

## Acceptance and regression coverage

- Setup cannot be completed while provider onboarding is neither authenticated nor deferred.
- Anonymous, pre-admin, post-completion and invalid-state defer attempts are rejected.
- A valid administrator can defer, advance to WireGuard and complete setup after WireGuard exists.
- Authentication after deferral clears the deferred state.
- Setup state distinguishes authenticated, deferred and required provider states.
- Frontend tests cover the explicit action, honest completion label, translated copy and the fact
  that deferral does not invoke provider installation, authentication, speed tests or VPN changes.
- Run the full backend/frontend, lint, security, i18n, syntax and package suites, followed by the
  Debian 13 test-appliance wizard/API smoke path.

## Multi-provider extension

The provider catalog now includes NordVPN and Mullvad VPN. The wizard stores independently selected
and skipped provider IDs, configures them deterministically, activates one ready provider
automatically, and requires an explicit active choice when both are ready. Multiple providers may
be installed and authenticated, but simultaneous commercial egress remains prohibited.
