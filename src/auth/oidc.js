/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */

import { SignJWT, jwtVerify, createLocalJWKSet, base64url } from 'jose';
import { cookie, cookieValue, privateResponse, redirect, safeReturnTo } from '../lib/http.js';

export const SESSION_COOKIE = '__Host-cug-session';
export const FLOW_COOKIE = '__Host-cug-flow';
const FLOW_SECONDS = 300;
const encoder = new TextEncoder();
const random = () => base64url.encode(crypto.getRandomValues(new Uint8Array(32)));

async function jsonResponse(response) {
  if (!response.ok) throw new Error('Identity provider request failed');
  const raw = await response.text();
  if (raw.length > 131072) throw new Error('Identity provider response too large');
  return JSON.parse(raw);
}

export function createAuth(settings, { getSecret, fetchIdp, now = () => Math.floor(Date.now() / 1000) }) {
  async function signingKey() {
    const value = await getSecret('SESSION_SIGNING_KEY');
    // Generate with openssl rand -hex 32; the decoded key must be 256 bits.
    if (!/^[0-9a-f]{64}$/i.test(value || '')) throw new Error('Invalid session signing key');
    return Uint8Array.from(value.match(/../g).map((byte) => parseInt(byte, 16)));
  }

  async function sign(payload, type, lifetime, subject) {
    let jwt = new SignJWT(payload).setProtectedHeader({ alg: 'HS256', typ: type })
      .setIssuer(settings.publicOrigin).setAudience(settings.clientId)
      .setIssuedAt(now()).setExpirationTime(now() + lifetime);
    if (subject) jwt = jwt.setSubject(subject);
    return jwt.sign(await signingKey());
  }

  async function verify(value, type, maxAge) {
    if (!value || value.length > 3800) throw new Error('Invalid cookie');
    return (await jwtVerify(value, await signingKey(), {
      algorithms: ['HS256'], typ: type, issuer: settings.publicOrigin,
      audience: settings.clientId, requiredClaims: ['iat', 'exp'],
      maxTokenAge: maxAge, currentDate: new Date(now() * 1000),
    })).payload;
  }

  async function identity(request) {
    if (settings.mode !== 'oidc') return null;
    try {
      const payload = await verify(cookieValue(request, SESSION_COOKIE), 'cug-session+jwt', settings.sessionSeconds);
      if (typeof payload.sub !== 'string' || !Array.isArray(payload.groups)
          || payload.groups.some((group) => typeof group !== 'string')) return null;
      return { sub: payload.sub, groups: payload.groups };
    } catch {
      return null;
    }
  }

  async function login(request) {
    if (settings.mode !== 'oidc') return privateResponse('Authentication is not configured', 503);
    const input = new URL(request.url);
    const state = random();
    const nonce = random();
    const verifier = random();
    const returnTo = safeReturnTo(input.searchParams.get('returnTo'), settings.publicOrigin);
    const flow = await sign({ state, nonce, verifier, returnTo }, 'cug-flow+jwt', FLOW_SECONDS);
    const target = new URL(settings.authorizationEndpoint);
    const params = {
      response_type: 'code', client_id: settings.clientId,
      redirect_uri: `${settings.publicOrigin}/auth/callback`, scope: settings.scope,
      state, nonce, code_challenge_method: 'S256',
      code_challenge: base64url.encode(await crypto.subtle.digest('SHA-256', encoder.encode(verifier))),
    };
    for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
    return redirect(target.href, { 'Set-Cookie': cookie(FLOW_COOKIE, flow, FLOW_SECONDS) });
  }

  async function callback(request) {
    const cleared = cookie(FLOW_COOKIE, '', 0);
    try {
      const params = new URL(request.url).searchParams;
      if (params.has('error') || params.getAll('code').length !== 1
          || params.getAll('state').length !== 1) throw new Error('Invalid callback');
      const flow = await verify(cookieValue(request, FLOW_COOKIE), 'cug-flow+jwt', FLOW_SECONDS);
      if (!params.get('code') || params.get('state') !== flow.state
          || (params.has('iss') && params.get('iss') !== settings.issuer)) throw new Error('Invalid state');
      const body = new URLSearchParams({
        grant_type: 'authorization_code', code: params.get('code'),
        redirect_uri: `${settings.publicOrigin}/auth/callback`,
        client_id: settings.clientId, code_verifier: flow.verifier,
      });
      const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      if (settings.tokenAuthMethod !== 'none') {
        const secret = await getSecret('OIDC_CLIENT_SECRET');
        if (!secret) throw new Error('Missing client secret');
        if (settings.tokenAuthMethod === 'client_secret_basic') {
          const formEncode = (value) => new URLSearchParams({ v: value }).toString().slice(2);
          headers.Authorization = `Basic ${btoa(`${formEncode(settings.clientId)}:${formEncode(secret)}`)}`;
        } else body.set('client_secret', secret);
      }
      const tokens = await jsonResponse(await fetchIdp(new Request(settings.tokenEndpoint, {
        method: 'POST', body, headers, redirect: 'manual',
      }), 'oidc-token'));
      if (typeof tokens.id_token !== 'string' || tokens.id_token.length > 16384) throw new Error('Missing ID token');
      const jwks = await jsonResponse(await fetchIdp(new Request(settings.jwksUri, {
        redirect: 'manual', headers: { Accept: 'application/json' },
      }), 'oidc-jwks'));
      // Local JWKS prevents library-initiated fetches bypassing our cache/backend policy.
      const { payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
        algorithms: ['RS256'], issuer: settings.issuer, audience: settings.clientId,
        requiredClaims: ['sub', 'iat', 'exp', 'nonce'],
        maxTokenAge: FLOW_SECONDS, clockTolerance: 5, currentDate: new Date(now() * 1000),
      });
      if (payload.nonce !== flow.nonce || typeof payload.sub !== 'string' || !payload.sub
          || (payload.azp !== undefined && payload.azp !== settings.clientId)
          || (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== settings.clientId)) {
        throw new Error('Invalid identity claims');
      }
      const groups = payload[settings.groupsClaim];
      if (!Array.isArray(groups) || groups.length > 100
          || groups.some((group) => typeof group !== 'string' || !group || group.length > 256)) {
        throw new Error('Missing or invalid group claims');
      }
      const lifetime = Math.min(settings.sessionSeconds, payload.exp - now());
      if (lifetime < 1) throw new Error('Expired identity');
      const session = await sign({ groups: [...new Set(groups)] }, 'cug-session+jwt', lifetime, payload.sub);
      if (session.length > 3800) throw new Error('Group claims exceed cookie capacity');
      const response = redirect(safeReturnTo(flow.returnTo, settings.publicOrigin));
      response.headers.append('Set-Cookie', cleared);
      response.headers.append('Set-Cookie', cookie(SESSION_COOKIE, session, lifetime));
      return response;
    } catch {
      // Never log codes, provider responses, tokens, or session cookies.
      return privateResponse('Login failed', 401, { 'Set-Cookie': cleared });
    }
  }

  async function route(request) {
    const path = new URL(request.url).pathname;
    if (!path.startsWith('/auth/')) return null;
    if (path === '/auth/logout') {
      if (request.method !== 'POST') return privateResponse('Method Not Allowed', 405, { Allow: 'POST' });
      if (request.headers.get('origin') !== settings.publicOrigin) return privateResponse('Forbidden', 403);
      const response = redirect('/');
      response.headers.append('Set-Cookie', cookie(SESSION_COOKIE, '', 0));
      response.headers.append('Set-Cookie', cookie(FLOW_COOKIE, '', 0));
      return response;
    }
    if (request.method !== 'GET') return privateResponse('Method Not Allowed', 405, { Allow: 'GET' });
    if (path === '/auth/login') return login(request);
    if (path === '/auth/callback' && settings.mode === 'oidc') return callback(request);
    return privateResponse('Not Found', 404);
  }

  return { identity, route };
}
