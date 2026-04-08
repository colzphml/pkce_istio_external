# Architecture

## Final Shape

The solution is intentionally split into three artifacts:

1. `auth-service` binary.
   One process exposes gRPC `ext_authz` and HTTP auth endpoints.
2. namespace-scoped Helm chart.
   It deploys `auth-service`, Redis and namespaced Kubernetes/Istio/Gateway API resources.
3. separate gateway/control-plane integration.
   It attaches `AuthorizationPolicy` to the existing Gateway and adds `meshConfig.extensionProviders` to the existing Istio control plane.

This separation matters because `meshConfig.extensionProviders` is part of the existing `istiod` installation, not part of the application namespace lifecycle.

## Request Flow

### Normal authenticated request

1. Browser sends opaque session cookie to the existing Istio gateway.
2. Gateway triggers `CUSTOM` auth on the protected host/path and calls `auth-service` over gRPC `ext_authz`.
3. `auth-service` loads the session from Redis.
4. If the access token is outside the refresh window, the request is allowed immediately.
5. If the token is in the refresh window, only one request refreshes under a Redis lock. Parallel requests reuse the fresh session or temporarily reuse the still-valid token.
6. On allow, the service injects:
   - `Authorization: Bearer <access_token>`
   - identity headers such as `x-auth-request-user`, `x-auth-request-email`, `x-auth-request-sub`
7. Backend remains unaware of OIDC and receives a normal bearer token.

### First unauthenticated request

1. Gateway triggers gRPC `ext_authz`.
2. `auth-service` sees no valid session and returns `302 Location: /_auth/login?...`.
3. The separate `HTTPRoute` for `/_auth/*` sends login/callback/logout traffic to `auth-service`.
4. `/_auth/login` creates `state`, `nonce`, `code_verifier`, stores them in Redis and redirects to Keycloak with PKCE S256.
5. `/_auth/callback` validates state, exchanges the code, verifies ID token nonce and validates the JWT access token, then creates a server-side session in Redis and an opaque cookie in the browser.
6. Browser is redirected back to the original path.

### Logout

- `/_auth/logout`
  Deletes local session state, clears the cookie and redirects to the Keycloak RP-Initiated Logout endpoint.
- `/_auth/backchannel-logout`
  Verifies the logout token JWT and deletes all local sessions indexed by `kc_session_id`.

## Redis Keys

- `oidc:state:{state}`
- `oidc:session:{session_id}`
- `oidc:kc-session:{kc_session_id}`
- `oidc:lock:refresh:{session_id}`

## What Belongs Where

### Application-owned

- Go binary
- Redis-backed session model
- login/callback/logout/backchannel logic
- gRPC `ext_authz`
- metrics, probes, graceful shutdown

### Main chart, namespace-scoped

- Deployment / Service / ServiceAccount / PDB
- Redis dependency
- `HTTPRoute` for `/_auth/*`
- `PeerAuthentication`
- optional `ServiceEntry` for external Keycloak when mesh egress is `REGISTRY_ONLY`
- namespace-scoped `NetworkPolicy`

### Separate gateway/control-plane integration

- `AuthorizationPolicy` with `action: CUSTOM`
- `meshConfig.extensionProviders` on the existing Istio control plane

## Why Not One Chart

It is a bad operational boundary to let an application release silently rewrite a separately managed shared `istiod` release.

Problems with a single chart:

- shared control plane may be owned by another team/release pipeline
- Helm list merge semantics for `meshConfig.extensionProviders` are easy to get wrong
- rollback coupling between app and control plane is undesirable
- unrelated workloads on the same gateway can be affected by an accidental provider/policy change

The production-friendly model is:

- keep `auth-service` lifecycle independent
- make the `meshConfig.extensionProviders` change explicit
- keep gateway attachment explicit in the gateway namespace

## Hot Path

Hot path on a valid session:

1. gateway -> gRPC `ext_authz`
2. Redis `GET`
3. optional refresh lock `SETNX` + `GET`/`SET` only when inside refresh window
4. allow with upstream header mutation

No Keycloak call is made on the normal request path.

## Optimization Decisions

- gRPC `ext_authz`, not HTTP
- Redis is the only external dependency on the normal path
- no local L1 cache yet, to keep logout and backchannel invalidation exact
- refresh only inside a short refresh window
- distributed Redis lock prevents parallel refresh storms
- still-valid token can be reused briefly when a concurrent refresh is in progress, except for `invalid_grant`
- keep-alive and connection pooling are delegated to the gRPC and Redis clients

## Security Decisions

- Authorization Code Flow only
- PKCE S256 only
- state verification
- nonce verification
- ID token verification via JWKS
- access token JWT validation via JWKS plus `iss`, `aud`/`azp`, `exp`
- opaque cookie only
- no tokens in cookies
- `HttpOnly`, `Secure`, `SameSite=Lax` by default
- backchannel logout token verification before local session deletion

## Still To Harden

- add explicit rate limiting on `/_auth/*` endpoints
- add optional circuit breaking and retries for Keycloak HTTP client with tighter error taxonomy
- add mTLS client auth to Redis if required by policy
- add stricter egress `NetworkPolicy`/`ServiceEntry` generation for known Keycloak endpoints
- add chaos and load tests against a real Keycloak and real Redis Sentinel cluster
- add explicit secret rotation playbooks
- decide whether auth cookie stripping before backend is needed in your gateway policy model
