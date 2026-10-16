# AEM CUG Edge Function

An AEM Edge Functions gateway for an Edge Delivery Services site. Migrated from
the Cloudflare CUG template at upstream commit `409a7ba`.

The gateway reads `x-aem-cug-required: true` and `x-aem-cug-groups` from the EDS
origin, verifies a visitor's session and group membership, and strips those
headers before delivery. It includes configurable OIDC authorization code +
PKCE login. Authentication defaults to `deny` until configured.

```text
Browser → Adobe-managed CDN (skipCache) → CUG function → authenticated EDS origin
                                               ↘ OIDC provider
```

Both the outer CDN cache and the function's fetch cache are bypassed. All
responses are private/no-store, including public pages and login errors. This
deliberate first-release policy prevents a cache hit from bypassing the gate.

## Prerequisites

- A Cloud Manager program with an onboarded EDS site, custom domain and EDS
  configuration pipeline. AEM sandbox programs cannot provision the required
  config/secret stores.
- Node.js 22+, the Adobe CLI and `@adobe/aio-cli-plugin-aem-edge-functions`.
- EDS site authentication enabled on the live origin, with a site token stored
  in Cloud Manager. Review preview, branch and author access separately.
- For login, an OIDC provider issuing RS256 ID tokens with a string-array group
  claim. Provider-specific group lookup, Entra group-overage resolution and
  Adobe IMS product-profile lookup are not implemented.

## Configure

1. Edit `config/edgeFunctions.yaml`: set the EDS backend domain and matching
   `ORIGIN_HOSTNAME`, and the canonical HTTPS `PUBLIC_ORIGIN`. Requests to other
   hosts, including diagnostic function hosts, return 421.
2. Create the Cloud Manager secret `CUG_ORIGIN_TOKEN`. It must be an EDS site
   token, not an Admin API token. The gateway never fetches content without it.
3. Review `PROTECTED_PATH_PREFIXES`. Its default `["/"]` requires explicit CUG
   metadata for every content path. Public pages outside the listed prefixes
   may omit the headers. For example, `["/members", "/downloads"]` requires
   metadata on those paths, their descendants and root representations such as
   `/members.json`. Use `[]` only if you deliberately rely entirely on the
   origin's metadata. Missing metadata on a required path returns 502; an empty
   protected group list authorizes nobody.
4. For OIDC, set `AUTH_MODE: oidc`, uncomment/fill the OIDC values and secret
   references, and set the `oidc-token` and `oidc-jwks` backend domains to the
   corresponding endpoint hosts. Copy endpoint values from your provider's
   trusted configuration. The issuer value is compared exactly, including its
   trailing slash. The scopes must request the required group claim.
5. Register `${PUBLIC_ORIGIN}/auth/callback` with the provider. Supported token
   endpoint client authentication methods are `client_secret_post`,
   `client_secret_basic`, and `none` for a public PKCE client. For confidential
   clients, store the secret as `CUG_OIDC_CLIENT_SECRET` in Cloud Manager.
6. Generate a session signing key using `openssl rand -hex 32`; store it as
   `CUG_SESSION_SIGNING_KEY` in Cloud Manager. Never put it in Git or a frontend
   script. Changing this key invalidates all sessions and in-progress logins.

The runtime uses `config_default` and `secret_default`. Cloud secrets are loaded
through Adobe's bundled `secrets` JSON entry; individual entries are supported
for local development. These stores are shared across functions in the same
environment. Separate environments are needed for separate secret trust
boundaries. No KV store is required.

## Authentication behavior

- `GET /auth/login?returnTo=/members/page` starts login with random state/nonce,
  PKCE S256 and a signed, five-minute HttpOnly flow cookie.
- `GET /auth/callback` validates the flow, exchanges the one-time authorization
  code, verifies the ID token's signature, issuer, audience, authorized party,
  timestamps and nonce, and issues an HttpOnly/Secure/SameSite=Lax host cookie.
- Protected HTML requests without a session redirect to login. Other anonymous
  requests receive 401. Authenticated visitors in the wrong group receive 403.
- `POST /auth/logout` requires a matching Origin header and clears the cookies.
  A same-origin HTML form or fetch can invoke it. It does not end the IdP's SSO
  session and does not revoke an already copied session token.
- Sessions last at most five minutes, or until the ID token expires if sooner.
  Group claims are a snapshot at login; group removal/user disablement can take
  up to that interval to affect access. Immediate revocation requires an
  authoritative introspection/session service and is not claimed here.
- Group identifiers are exact, case-sensitive strings in the configured top-level
  ID-token claim. Missing, malformed, oversized or overage claims fail login.
  Keep groups small enough to fit the signed session cookie (3800-byte limit).
- The token endpoint's single-use authorization-code enforcement is part of
  replay protection. The gateway has no strongly consistent replay database.
- All IdP requests use explicit named backends and bypass fetch caching. The
  application does not follow IdP redirects or use JWT-supplied key URLs.

## Build and test

```sh
npm install
npm test
npm run build:wasm
```

The regression suite verifies the proxy policy and real JWT/PKCE operations.
GitHub Actions also compiles a separate test entry point and exercises RSA
verification, HMAC sessions, PKCE and the gate in Fastly's Viceroy runtime. It
restores the production Wasm before uploading the artifact. Test fixtures contain
only synthetic identities and a public RSA key. Never deploy the smoke entry point.

`fastly.toml` contains local backend/config examples and no credentials. For local
runtime work, configure private secret files using Fastly's local secret-store
support. The application requires the configured canonical HTTPS URL; ordinary
requests to `http://127.0.0.1:7676` intentionally fail the host/scheme check. Unit
tests and the Viceroy smoke test construct canonical requests internally. Use a
configured HTTPS staging domain to test the complete browser login/CDN path.

## Deploy to staging, then production

```sh
npm install -g @adobe/aio-cli
aio plugins install @adobe/aio-cli-plugin-aem-edge-functions
aio login
aio aem edge-functions setup
```

1. Select the intended EDS environment. Add secrets and deploy
   `config/edgeFunctions.yaml` through its Cloud Manager configuration pipeline to
   register the function/backends/stores. If `cdn.yaml` would activate routing at
   the same time, stage registration separately so an empty function never
   receives production traffic.
2. Build and deploy the package:

   ```sh
   aio aem edge-functions build
   aio aem edge-functions deploy cug-gateway
   ```

3. Merge `config/cdn.yaml` into the site's existing CDN configuration and deploy
   it through the pipeline. The catch-all origin selector must cover every
   potentially protected route before any rule that could bypass the function.
   Keep `skipCache: true`, including for requests with no cookies. Verify that
   request cookies and all Set-Cookie responses survive the actual CDN path.
4. Complete the deployed acceptance checks in `docs/security-and-rollout.md`.
5. Configure the production certificate, callback URL and domain, purge existing
   cached responses, and perform DNS/routing cutover. Keep the previous deployed
   Cloudflare version and DNS rollback procedure until validation is complete.

This repository does not deploy automatically. The CI workflow needs no Adobe
credentials and cannot change production routing.

## Behavior changes from the Worker

- Cloudflare `env`/Wrangler/`cf.cacheEverything` are replaced by AEM stores,
  configuration pipelines and Fastly cache pass mode.
- The EDS-facing CDN header uses `fastly`; the site's production CDN
  configuration must use type `managed`. `X-Push-Invalidation` is intentionally
  absent because long origin TTLs are inappropriate until invalidation is proven.
- Origin cookies, browser credentials and user-supplied internal headers are not
  forwarded. Only a small content-request header allowlist crosses the boundary.
- Content permits GET/HEAD. RUM/Optel permits GET/POST/OPTIONS. Draft paths remain
  blocked. Unknown query parameters are removed without skipping adjacent keys.
- HEAD fetches a full GET representation to inspect its policy and returns no
  body. Range and conditional headers are removed, so clients receive a complete
  response rather than a partial or 304 response missing CUG metadata. This
  trades bandwidth/range-download support for a reliable policy check.
- CUG headers, origin Set-Cookie and conflicting CDN cache directives are
  stripped. Origin CSP and robots directives are preserved. Same-site content
  redirects retain query strings; external redirects do not inherit them.

Before enabling caching, implement and verify managed-CDN invalidation plus
separate fetch-cache invalidation. A public-to-protected transition must not leave
a stale public response. A page's CUG does not automatically protect its media,
JSON, search indexes or downloads: audit each representation and origin policy.

See [AEM Edge Functions](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/developing/edge-functions),
[cache architecture](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/developing/edge-functions-caching),
[site authentication](https://www.aem.live/docs/authentication-setup-site), and
[managed push invalidation](https://www.aem.live/docs/setup-byo-cdn-push-invalidation-for-managed).
