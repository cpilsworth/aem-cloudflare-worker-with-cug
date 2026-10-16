/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */

export function privateResponse(body, status = 200, headers = {}) {
  const output = new Headers(headers);
  output.set('Cache-Control', 'private, no-store');
  output.set('Surrogate-Control', 'no-store');
  output.set('Pragma', 'no-cache');
  output.set('X-Content-Type-Options', 'nosniff');
  output.set('Referrer-Policy', 'no-referrer');
  return new Response(body, { status, headers: output });
}

export function redirect(location, headers = {}) {
  return privateResponse(null, 303, { ...headers, Location: location });
}

export function cookieValue(request, name) {
  const values = (request.headers.get('cookie') || '').split(';')
    .map((part) => part.trim()).filter((part) => part.startsWith(`${name}=`));
  return values.length === 1 ? values[0].slice(name.length + 1) : null;
}

export function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function safeReturnTo(value, publicOrigin) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')
      || /[\\\u0000-\u0020\u007f]/.test(value) || value.length > 2048) return '/';
  const target = new URL(value, publicOrigin);
  if (target.origin !== publicOrigin || target.pathname.startsWith('/auth/')) return '/';
  return target.pathname + target.search;
}
