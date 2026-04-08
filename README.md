# OIDC Auth Layer for Istio Gateway

Production-oriented OIDC authentication layer for an existing Istio ingress gateway using:

- Go
- Envoy `ext_authz` over gRPC
- opaque browser session cookie only
- Redis for login state, sessions, refresh locks and Keycloak session index
- Kubernetes Gateway API + Istio

The design target is a near-invisible hot path for ordinary requests:

- no call to Keycloak on the normal request path
- only Redis on the normal request path
- gRPC `ext_authz` instead of HTTP
- refresh only inside the configured refresh window
- Redis distributed lock to suppress refresh stampede

## Architecture

There are three separate operational layers:

1. `auth-service` application.
   It owns OIDC login/callback/logout/backchannel-logout, Redis session state and the gRPC `ext_authz` decision path.
2. namespace-scoped application chart.
   It deploys `auth-service`, Redis and namespaced Gateway API/Istio resources such as `HTTPRoute`, `PeerAuthentication`, `NetworkPolicy`.
3. existing Istio control plane integration.
   `meshConfig.extensionProviders` belongs to the existing Istio installation and should not be silently mutated by the application release.

The repository therefore ships:

- a main chart: [deployments/charts/oidc-auth](/Users/colz/gitrepos/envs/pkce_istio_external/deployments/charts/oidc-auth)
- a gateway integration chart: [deployments/charts/oidc-auth-integration](/Users/colz/gitrepos/envs/pkce_istio_external/deployments/charts/oidc-auth-integration)
- explicit Istio control-plane snippets: [deployments/istio](/Users/colz/gitrepos/envs/pkce_istio_external/deployments/istio)
- GitHub Actions workflows for CI and GHCR publishing in [.github/workflows](/Users/colz/gitrepos/envs/pkce_istio_external/.github/workflows)

More detail is in [docs/architecture.md](/Users/colz/gitrepos/envs/pkce_istio_external/docs/architecture.md) and [docs/istio-integration.md](/Users/colz/gitrepos/envs/pkce_istio_external/docs/istio-integration.md).

## Repo Layout

```text
cmd/authservice/                    binary entrypoint
internal/app/                       process wiring and graceful shutdown
internal/config/                    env-driven runtime config
internal/extauth/                   Envoy gRPC ext_authz server
internal/httpserver/                login/callback/logout/backchannel endpoints
internal/model/                     login/session domain models
internal/oidc/                      OIDC discovery, token exchange, refresh, logout token verification
internal/session/                   session manager and refresh coordination
internal/store/                     Redis-backed state/session store
deployments/charts/oidc-auth/       auth-service + Redis + namespaced resources
deployments/charts/oidc-auth-integration/  gateway AuthorizationPolicy chart
deployments/istio/                  meshConfig extension provider overlays/snippets
docs/                               architecture and integration notes
```

## Installation Order

1. Install the main chart into the auth namespace.
2. Merge the extension provider snippet into the existing Istio release.
3. Install the integration chart into the gateway namespace to attach `AuthorizationPolicy` with `action: CUSTOM`.

This split is intentional. A single chart that directly mutates a separately managed `istiod` release is not production-friendly because it couples app lifecycle and control-plane lifecycle, and `meshConfig.extensionProviders` is a list that must be merged carefully with existing providers.

## Build And Publish

- CI runs `go test ./...`, `helm dependency build`, `helm lint` and `helm template`.
- Image publish workflow builds `linux/amd64` and `linux/arm64` and pushes to `ghcr.io/colzphml/pkce_istio_external`.
- Build metadata is embedded into the binary and exposed via `/versionz`.
- Example runtime environment is in [.env.example](/Users/colz/gitrepos/envs/pkce_istio_external/.env.example).

## Current Status

The repo contains:

- service implementation for login/callback/logout/backchannel logout
- Redis-backed sessions and refresh locks
- gRPC `ext_authz` server that injects `Authorization: Bearer <access_token>` and identity headers
- Helm packaging for app-side resources and separate gateway integration
- Istio control-plane snippets
- unit tests, Redis-backed integration tests and a hot-path benchmark

Remaining hardening items are listed in [docs/architecture.md](/Users/colz/gitrepos/envs/pkce_istio_external/docs/architecture.md).
