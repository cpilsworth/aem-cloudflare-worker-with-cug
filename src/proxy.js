/* Copyright 2022 Adobe. Licensed under the Apache License, Version 2.0. */

const MEDIA = /\/media_[0-9a-f]{40,}[/a-zA-Z0-9_-]*\.[0-9a-z]+$/;
export const isTelemetry = (path) => /^\/\.(rum|optel)\//.test(path);

export function normalizedOriginUrl(input, hostname) {
  const url = new URL(input);
  const allowed = MEDIA.test(url.pathname) ? ['format', 'height', 'optimize', 'width']
    : url.pathname.endsWith('.json') ? ['limit', 'offset', 'sheet'] : [];
  for (const key of [...url.searchParams.keys()]) {
    if (!allowed.includes(key)) url.searchParams.delete(key);
  }
  url.searchParams.sort();
  url.hostname = hostname;
  url.protocol = 'https:';
  url.port = '';
  return url;
}

export function originRequest(request, settings, token) {
  if (!token) throw new Error('Origin authentication is required');
  const url = normalizedOriginUrl(request.url, settings.originHostname);
  const headers = new Headers();
  for (const name of ['accept', 'accept-language', 'content-type', 'user-agent']) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set('Authorization', `token ${token}`);
  headers.set('X-Forwarded-Host', new URL(settings.publicOrigin).host);
  headers.set('X-BYO-CDN-Type', 'fastly');
  // No long-TTL push-invalidation opt-in until a purge path is verified.
  const method = request.method === 'HEAD' ? 'GET' : request.method;
  const init = { method, headers, redirect: 'manual' };
  if (!['GET', 'HEAD'].includes(method)) {
    init.body = request.body;
    init.duplex = 'half'; // Node tests; ignored by Fastly.
  }
  // Never forward cookies, caller authorization, conditional, range, or routing
  // headers. Fetch a complete representation with its authorization metadata.
  return new Request(url, init);
}

export function outgoingHeaders(response, request, settings) {
  const headers = new Headers(response.headers);
  for (const name of ['x-aem-cug-required', 'x-aem-cug-groups', 'age', 'set-cookie',
    'surrogate-key', 'cdn-cache-control', 'cloudflare-cdn-cache-control', 'expires']) headers.delete(name);
  headers.set('Cache-Control', 'private, no-store');
  headers.set('Surrogate-Control', 'no-store');
  headers.set('Pragma', 'no-cache');
  const location = headers.get('location');
  if (location && response.status >= 300 && response.status < 400) {
    const target = new URL(location, `https://${settings.originHostname}${new URL(request.url).pathname}`);
    if (target.hostname === settings.originHostname) {
      target.host = new URL(settings.publicOrigin).host;
      target.protocol = 'https:';
    }
    if (response.status === 301 && target.origin === settings.publicOrigin
        && !target.pathname.startsWith('/auth/') && !target.search) {
      target.search = new URL(request.url).search;
    }
    headers.set('location', target.href);
  }
  return headers;
}
