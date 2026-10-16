import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT, decodeJwt, base64url } from 'jose';
import { createAuth, FLOW_COOKIE, SESSION_COOKIE } from '../src/auth/oidc.js';
import { safeReturnTo } from '../src/lib/http.js';

const keys = await generateKeyPair('RS256');
const publicJwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
const settings = {
  mode: 'oidc', publicOrigin: 'https://portal.example.com', issuer: 'https://idp.example.com',
  clientId: 'portal-client', authorizationEndpoint: 'https://idp.example.com/authorize',
  tokenEndpoint: 'https://idp.example.com/token', jwksUri: 'https://idp.example.com/keys',
  groupsClaim: 'groups', scope: 'openid profile groups', tokenAuthMethod: 'client_secret_post', sessionSeconds: 300,
};
const signingSecret = 'ab'.repeat(32);
const keyBytes = Uint8Array.from({ length: 32 }, () => 0xab);
const fixedTime = 1800000000;
const req = (path, init) => new Request(settings.publicOrigin + path, init);

function fixture({ claims = {}, tokenIssuer = settings.issuer, tokenAudience = settings.clientId,
  jwks = { keys: [publicJwk] }, providerStatus = 200, config = {}, secret = signingSecret,
  providerToken, } = {}) {
  let clock = fixedTime;
  let flow;
  const calls = [];
  const auth = createAuth({ ...settings, ...config }, {
    now: () => clock,
    getSecret: async (name) => name === 'SESSION_SIGNING_KEY' ? secret : 'client-secret',
    fetchIdp: async (request, backend) => {
      calls.push({ backend, request });
      if (backend === 'oidc-token') {
        const token = providerToken || await new SignJWT({ nonce: flow.nonce, groups: ['team-a'], ...claims })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(tokenIssuer)
          .setAudience(tokenAudience).setSubject('user-1').setIssuedAt(clock)
          .setExpirationTime(clock + 600).sign(keys.privateKey);
        return new Response(JSON.stringify({ id_token: token }), { status: providerStatus });
      }
      return new Response(JSON.stringify(jwks));
    },
  });
  async function begin(returnTo = '/members/page') {
    const response = await auth.route(req(`/auth/login?${new URLSearchParams({ returnTo })}`));
    const flowCookie = response.headers.getSetCookie()[0].split(';')[0];
    flow = decodeJwt(flowCookie.slice(flowCookie.indexOf('=') + 1));
    return { response, flowCookie, flow };
  }
  async function finish(start, query = '') {
    return auth.route(req(`/auth/callback?code=one-time-code&state=${start.flow.state}${query}`, {
      headers: { Cookie: start.flowCookie },
    }));
  }
  return { auth, begin, finish, calls, setTime: (time) => { clock = time; } };
}

function sessionFrom(response) {
  return response.headers.getSetCookie().find((value) => value.startsWith(`${SESSION_COOKIE}=`))?.split(';')[0];
}

test('OIDC login uses PKCE S256, state, nonce and an HttpOnly host cookie', async () => {
  const f = fixture();
  const { response, flow } = await f.begin();
  assert.equal(response.status, 303);
  const target = new URL(response.headers.get('location'));
  assert.equal(target.origin, 'https://idp.example.com');
  assert.equal(target.searchParams.get('response_type'), 'code');
  assert.equal(target.searchParams.get('state'), flow.state);
  assert.equal(target.searchParams.get('nonce'), flow.nonce);
  assert.equal(target.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(target.searchParams.get('redirect_uri'), `${settings.publicOrigin}/auth/callback`);
  assert.equal(target.searchParams.get('code_challenge'), base64url.encode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(flow.verifier))));
  assert.match(response.headers.getSetCookie()[0], /Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=300/);
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
});

test('valid callback verifies identity, exchanges PKCE and issues a five-minute group session', async () => {
  const f = fixture();
  const start = await f.begin('/members/page?tab=2');
  const response = await f.finish(start);
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/members/page?tab=2');
  assert.equal(response.headers.getSetCookie().length, 2);
  assert.match(response.headers.getSetCookie()[0], new RegExp(`${FLOW_COOKIE}=;.*Max-Age=0`));
  const identity = await f.auth.identity(req('/members/page', { headers: { Cookie: sessionFrom(response) } }));
  assert.deepEqual(identity, { sub: 'user-1', groups: ['team-a'] });
  const body = new URLSearchParams(await f.calls[0].request.text());
  assert.equal(body.get('code_verifier'), start.flow.verifier);
  assert.equal(body.get('client_secret'), 'client-secret');
  assert.deepEqual(f.calls.map((call) => call.backend), ['oidc-token', 'oidc-jwks']);
  assert.equal(f.calls[0].request.redirect, 'manual');
  assert.equal(f.calls[1].request.redirect, 'manual');
  f.setTime(fixedTime + 301);
  assert.equal(await f.auth.identity(req('/', { headers: { Cookie: sessionFrom(response) } })), null);
});

for (const [name, options] of [
  ['wrong nonce', { claims: { nonce: 'attacker' } }],
  ['wrong issuer', { tokenIssuer: 'https://attacker.example.com' }],
  ['wrong audience', { tokenAudience: 'another-client' }],
  ['wrong authorized party', { claims: { azp: 'another-client' } }],
  ['multiple audiences without azp', { tokenAudience: [settings.clientId, 'another-client'] }],
  ['missing groups', { claims: { groups: undefined } }],
  ['string groups', { claims: { groups: 'team-a' } }],
  ['non-string group', { claims: { groups: [true] } }],
  ['provider outage', { providerStatus: 503 }],
  ['unknown signing key', { jwks: { keys: [] } }],
  ['malformed token', { providerToken: 'not.a.jwt' }],
]) {
  test(`${name} does not issue a session`, async () => {
    const f = fixture(options);
    const response = await f.finish(await f.begin());
    assert.equal(response.status, 401);
    assert.equal(sessionFrom(response), undefined);
    assert.equal(await response.text(), 'Login failed');
  });
}

test('wrong state, duplicate callback fields and missing cookies fail before the token endpoint', async () => {
  const f = fixture();
  const start = await f.begin();
  for (const query of ['code=c&state=wrong', `code=c&code=d&state=${start.flow.state}`,
    `code=c&state=${start.flow.state}&state=wrong`, `error=denied&state=${start.flow.state}`,
    `code=c&state=${start.flow.state}&iss=https://attacker.example.com`]) {
    assert.equal((await f.auth.route(req(`/auth/callback?${query}`, { headers: { Cookie: start.flowCookie } }))).status, 401);
  }
  assert.equal((await f.auth.route(req(`/auth/callback?code=c&state=${start.flow.state}`))).status, 401);
  assert.equal(f.calls.length, 0);
});

test('expired or duplicate flow cookies fail without identity provider calls', async () => {
  const f = fixture();
  const start = await f.begin();
  const duplicate = { ...start, flowCookie: `${start.flowCookie}; ${start.flowCookie}` };
  assert.equal((await f.finish(duplicate)).status, 401);
  f.setTime(fixedTime + 301);
  assert.equal((await f.finish(start)).status, 401);
  assert.equal(f.calls.length, 0);
});

test('tampered sessions, duplicate cookies and flow-token substitution are rejected', async () => {
  const f = fixture();
  const start = await f.begin();
  const response = await f.finish(start);
  const session = sessionFrom(response);
  const token = session.split('=')[1];
  const parts = token.split('.');
  const claims = { ...decodeJwt(token), groups: ['admin'] };
  parts[1] = base64url.encode(JSON.stringify(claims));
  for (const value of [`${SESSION_COOKIE}=${parts.join('.')}`, `${session}; ${session}`,
    `${SESSION_COOKIE}=${start.flowCookie.split('=')[1]}`]) {
    assert.equal(await f.auth.identity(req('/', { headers: { Cookie: value } })), null);
  }
});

test('session validation binds issuer, audience, algorithm, issued-at and expiry', async () => {
  const f = fixture();
  for (const overrides of [{ iss: 'https://elsewhere.example.com' }, { aud: 'other-client' },
    { exp: fixedTime - 1 }, { iat: fixedTime + 100 }, { iat: fixedTime - 1000 }]) {
    const token = await new SignJWT({ sub: 'user', groups: ['team-a'], iss: settings.publicOrigin,
      aud: settings.clientId, iat: fixedTime, exp: fixedTime + 300, ...overrides })
      .setProtectedHeader({ alg: 'HS256', typ: 'cug-session+jwt' }).sign(keyBytes);
    assert.equal(await f.auth.identity(req('/', { headers: { Cookie: `${SESSION_COOKIE}=${token}` } })), null);
  }
  const rsaToken = await new SignJWT({ sub: 'user', groups: ['team-a'], iss: settings.publicOrigin,
    aud: settings.clientId, iat: fixedTime, exp: fixedTime + 300 })
    .setProtectedHeader({ alg: 'RS256', typ: 'cug-session+jwt' }).sign(keys.privateKey);
  assert.equal(await f.auth.identity(req('/', { headers: { Cookie: `${SESSION_COOKIE}=${rsaToken}` } })), null);
});

test('logout requires a same-origin POST and clears both cookies', async () => {
  const f = fixture();
  assert.equal((await f.auth.route(req('/auth/logout'))).status, 405);
  assert.equal((await f.auth.route(req('/auth/logout', { method: 'POST' }))).status, 403);
  assert.equal((await f.auth.route(req('/auth/logout', { method: 'POST', headers: { Origin: 'https://attacker.example.com' } }))).status, 403);
  const response = await f.auth.route(req('/auth/logout', { method: 'POST', headers: { Origin: settings.publicOrigin } }));
  assert.equal(response.status, 303);
  assert.equal(response.headers.getSetCookie().length, 2);
  assert.ok(response.headers.getSetCookie().every((value) => value.includes('Max-Age=0')));
});

test('return destinations cannot cause open redirects or authentication loops', () => {
  for (const value of ['https://attacker.example.com', '//attacker.example.com', '/\\attacker.example.com',
    '/auth/callback', '/hello\nworld', null]) assert.equal(safeReturnTo(value, settings.publicOrigin), '/');
  assert.equal(safeReturnTo('/members?tab=2', settings.publicOrigin), '/members?tab=2');
});

test('deny mode has no usable login or session', async () => {
  const f = fixture({ config: { mode: 'deny' } });
  assert.equal((await f.auth.route(req('/auth/login'))).status, 503);
  assert.equal(await f.auth.identity(req('/')), null);
  assert.equal(f.calls.length, 0);
});

test('weak or unavailable signing secrets cannot initiate login', async () => {
  await assert.rejects(() => fixture({ secret: 'short' }).begin());
});

test('client_secret_basic and public PKCE clients are explicitly supported', async () => {
  for (const method of ['client_secret_basic', 'none']) {
    const f = fixture({ config: { tokenAuthMethod: method } });
    assert.equal((await f.finish(await f.begin())).status, 303);
    const tokenRequest = f.calls[0].request;
    const body = new URLSearchParams(await tokenRequest.text());
    assert.equal(body.has('client_secret'), false);
    assert.equal(tokenRequest.headers.get('authorization'), method === 'none' ? null : `Basic ${btoa('portal-client:client-secret')}`);
  }
});
