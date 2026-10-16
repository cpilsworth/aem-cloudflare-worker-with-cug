# Deployment acceptance and rollback

Run these checks on the actual staging custom domain before production cutover.
Local mocks and Viceroy cannot establish the behavior of the managed CDN, real
EDS metadata, IdP configuration or Cloudflare account controls.

## Required inputs

- Cloud Manager program/EDS site, configuration pipeline and store-capable environment.
- Custom production/staging domains and matching certificates.
- EDS origin with site authentication enabled and its site-token secret.
- IdP issuer, client, endpoints, callback registration and group mapping.
- Deliberate required-policy prefixes and an inventory of all content representations.
- Inventory of existing Cloudflare zone protections and Adobe replacements.

## Security gates

1. Anonymous direct requests to the EDS live origin fail. Review preview/branch
   origins and intended Sidekick author access independently. The origin token
   must not appear in browser responses, logs or source.
2. The canonical custom domain reaches the gate for HTML, `.plain.html`, JSON,
   fragments, downloads, indexes and media. Other diagnostic/alternate hosts
   receive 421 from this application. Existing CDN routes must not bypass it.
3. The origin supplies accurate CUG headers on every protected representation.
   Required-policy paths without those headers fail closed. Empty group lists
   deny everyone. Check redirect targets and error responses too.
4. Warm a URL as group A, then request anonymously and as group B, including at
   another edge location. No unauthorized response may contain protected bytes.
   Verify outer-cache bypass and that the function executes every time.
5. Publish a formerly public page as protected. Remove group access and disable a
   user. Verify the five-minute session bound and current origin policy; document
   that already delivered browser copies cannot be recalled. Strict immediate
   revocation requires additional infrastructure.
6. Verify code/state survive callback routing, cookies survive the CDN, two
   Set-Cookie headers are delivered separately, and callback failures remain
   uncached. Replay the same callback code with its original flow cookie; the IdP
   must reject the consumed authorization code.
7. Try forged forwarding/internal/CUG headers, encoded paths, conditional and
   range requests, HEAD, draft paths and disallowed methods. No fallback may
   return content without policy evaluation.
8. Simulate origin, IdP and secret failures. Responses must deny access or report
   unavailability, never return a stale successful response. Inspect logs to
   ensure codes, cookies, tokens and request query strings are not recorded.
9. Measure origin load and authentication latency with caches disabled. Validate
   performance under AEM execution/fetch limits. HEAD and range handling can
   increase origin bandwidth. Add appropriate rate limits to the login/token
   flow in the site's CDN configuration.
10. Inventory Cloudflare WAF, bot controls, rate limits, Access and TLS settings.
    The repository cannot discover or migrate zone-level settings. Configure and
    validate replacements; advanced Adobe WAF requires entitlement and activation.

## Cutover

Deploy function/backends/secrets first, code second, routing last. Purge old CDN
entries before routing changes. Validate the production callback and cookie
domain, then switch DNS/routing while monitoring status/latency and redacted
authorization events. Keep the old Cloudflare deployment operational through the
rollback window. After acceptance, remove obsolete Cloudflare routes and purge
credentials using the account's normal change process.

## Rollback

Keep the prior Cloudflare deployment version, DNS records, route configuration
and origin-token compatibility. Restore those routing/DNS values and validate
the original gate before removing AEM routing. If session formats differ, users
must log in again. Do not disable origin authentication to recover availability.

## Caching is a separate follow-up

This release intentionally has no shared cache. Before enabling it, classify
resources, preserve fresh CUG metadata, implement managed outer-CDN and function
fetch-cache purges, and test public-to-protected transitions. Never use cookie
presence, client IP or an unverified group header as authorization. Do not use
soft purge or stale response fallback for access revocation.
