/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */

import { mayRead, readPolicy } from './cug.js';
import { isTelemetry, originRequest, outgoingHeaders } from './proxy.js';
import { privateResponse, redirect, safeReturnTo } from './lib/http.js';

export function createApp({ settings, auth, getSecret, fetchOrigin, log = () => {} }) {
  return async function handle(request) {
    try {
      const url = new URL(request.url);
      // Diagnostic and alternate domains cannot become additional public gateways.
      if (url.origin !== settings.publicOrigin) return privateResponse('Misdirected Request', 421);
      const path = decodeURIComponent(url.pathname);
      if (/[\\%\u0000-\u001f\u007f]/.test(path) || path.includes('//')) {
        return privateResponse('Bad Request', 400);
      }
      // Use one path interpretation for routing, policy, and the origin request.
      url.pathname = path;
      request = new Request(url, request);
      if (path === '/drafts' || path.startsWith('/drafts/')) return privateResponse('Not Found', 404);
      const authResponse = await auth.route(request);
      if (authResponse) return authResponse;
      const telemetry = isTelemetry(path);
      const methods = telemetry ? ['GET', 'POST', 'OPTIONS'] : ['GET', 'HEAD'];
      if (!methods.includes(request.method)) return privateResponse('Method Not Allowed', 405, { Allow: methods.join(', ') });
      const upstream = await fetchOrigin(originRequest(request, settings, await getSecret('ORIGIN_AUTHENTICATION')));
      if (upstream.status === 304 || upstream.status === 206 || upstream.status >= 500) {
        await upstream.body?.cancel();
        return privateResponse('Origin unavailable', 502);
      }
      let policy;
      try {
        policy = readPolicy(upstream.headers, path, telemetry ? [] : settings.protectedPrefixes);
      } catch {
        await upstream.body?.cancel();
        return privateResponse('Content policy unavailable', 502);
      }
      if (policy.protected) {
        const identity = await auth.identity(request);
        if (!mayRead(identity, policy)) {
          await upstream.body?.cancel();
          if (!identity && settings.mode === 'oidc' && request.method === 'GET'
              && request.headers.get('accept')?.includes('text/html')) {
            const returnTo = safeReturnTo(url.pathname + url.search, settings.publicOrigin);
            return redirect(`/auth/login?${new URLSearchParams({ returnTo })}`);
          }
          return privateResponse(identity ? 'Forbidden' : 'Unauthorized', identity ? 403 : 401);
        }
      }
      const headers = outgoingHeaders(upstream, request, settings);
      if (request.method === 'HEAD') await upstream.body?.cancel();
      return privateResponse(request.method === 'HEAD' ? null : upstream.body, upstream.status, headers);
    } catch {
      log({ event: 'gateway_failure' });
      return privateResponse('Service unavailable', 503);
    }
  };
}
