# Istio Integration

## Important Boundary

`AuthorizationPolicy` with `action: CUSTOM` references a provider name that must exist in `meshConfig.extensionProviders`.

That means the full integration is split across two places:

- namespace-scoped app resources
- existing Istio control plane configuration

This repository keeps those two concerns separate on purpose.

## Install Sequence

1. Install [deployments/charts/oidc-auth](/Users/colz/gitrepos/envs/pkce_istio_external/deployments/charts/oidc-auth) into the auth namespace.
2. Merge [deployments/istio/meshconfig-extension-provider.snippet.yaml](/Users/colz/gitrepos/envs/pkce_istio_external/deployments/istio/meshconfig-extension-provider.snippet.yaml) into the values or `IstioOperator` spec for the existing Istio release.
3. Install [deployments/charts/oidc-auth-integration](/Users/colz/gitrepos/envs/pkce_istio_external/deployments/charts/oidc-auth-integration) into the gateway namespace.

## Why The Provider Patch Is Separate

- `meshConfig.extensionProviders` is owned by the `istiod` release
- it is a list, so careless Helm merging can drop existing providers
- the app chart should not surprise operators by mutating the control plane

When using Helm for Istio, merge the new provider into the existing `meshConfig.extensionProviders` list instead of replacing the list blindly.

## Gateway Namespace Attachment

The integration chart creates `AuthorizationPolicy` in the gateway namespace. That is deliberate.

For shared gateways, gateway-attached policy usually belongs in the gateway namespace, not in the app namespace.

Use `targetRefs` when possible. If the gateway deployment is managed manually or older compatibility is needed, the chart can fall back to workload selector labels.

## Gateway API Notes

- `HTTPRoute` for `/_auth/*` may live in the auth namespace and attach to the shared Gateway through `parentRefs`, but the Gateway must permit those cross-namespace routes with `allowedRoutes`.
- If the gateway is manually deployed and you want to use policy attachment through `targetRefs`, ensure gateway pods carry `gateway.networking.k8s.io/gateway-name: <gateway-name>`.
- The integration chart limits auth enforcement by `hosts` and excludes `/_auth/*`, so unrelated hosts on the same gateway are not unintentionally protected.

## gRPC Provider Notes

Current Istio API for `envoyExtAuthzGrpc` exposes provider settings such as `service`, `port`, `timeout`, `failOpen`, `clearRouteCache`, `statusOnError` and request-body buffering.

It does not expose the HTTP-provider-only header allowlist knobs such as:

- `includeRequestHeadersInCheck`
- `headersToUpstreamOnAllow`
- `headersToDownstreamOnDeny`

For gRPC this is acceptable:

- Envoy already sends the request headers in the gRPC check request
- upstream/downstream header mutations are returned directly in the gRPC `CheckResponse`

That is why the meshConfig snippet here stays minimal and relies on the gRPC response for `Authorization` and redirect headers.
