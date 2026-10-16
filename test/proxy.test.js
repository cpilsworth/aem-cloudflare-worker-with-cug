import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { readSettings } from '../src/settings.js';
import { normalizedOriginUrl } from '../src/proxy.js';
import { readPolicy } from '../src/cug.js';

const settings = {
  publicOrigin: 'https://portal.example.com', originHostname: 'main--site--org.aem.live',
  mode: 'oidc', protectedPrefixes: ['/members'],
};
const request = (path = '/members/page', init) => new Request(settings.publicOrigin + path, init);
const protectedHeaders = { 'x-aem-cug-required': 'true', 'x-aem-cug-groups': 'team-a, team-b' };
function gateway({ identity = null, upstream, secret = 'origin-token', mode = 'oidc' } = {}) {
  const seen = [];
  const app = createApp({ settings: { ...settings, mode },
    auth: { route: async () => null, identity: async () => identity },
    getSecret: async () => secret,
    fetchOrigin: async (req) => {
      seen.push(req);
      return upstream ? upstream(req) : new Response('restricted-content', { headers: protectedHeaders });
    },
  });
  return { app, seen };
}

test('authorized group receives content, with no internal policy or cache directives', async () => {
  const { app } = gateway({ identity: { groups: ['team-b'] }, upstream: () => new Response('private', {
    headers: { ...protectedHeaders, 'Cache-Control': 'public, max-age=999',
      'Surrogate-Control': 'max-age=999', 'Cloudflare-CDN-Cache-Control': 'max-age=999',
      'CDN-Cache-Control': 'max-age=999', 'Set-Cookie': 'origin-cookie=secret',
      'Surrogate-Key': 'page-1', Age: '100', Expires: 'tomorrow' },
  }) });
  const response = await app(request());
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'private');
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  assert.equal(response.headers.get('surrogate-control'), 'no-store');
  for (const name of ['x-aem-cug-required', 'x-aem-cug-groups', 'set-cookie', 'age',
    'cdn-cache-control', 'cloudflare-cdn-cache-control', 'surrogate-key', 'expires']) {
    assert.equal(response.headers.get(name), null, name);
  }
});

for (const [name, identity, expected] of [['anonymous', null, 401], ['wrong group', { groups: ['team-c'] }, 403]]) {
  test(`${name} cannot obtain protected content`, async () => {
    const response = await gateway({ identity }).app(request());
    assert.equal(response.status, expected);
    assert.equal(response.headers.get('cache-control'), 'private, no-store');
    assert.doesNotMatch(await response.text(), /restricted-content/);
  });
}

test('an authorized response never authorizes the next request', async () => {
  let currentIdentity = { groups: ['team-a'] };
  let fetches = 0;
  const app = createApp({ settings, auth: { route: async () => null, identity: async () => currentIdentity },
    getSecret: async () => 'token', fetchOrigin: async () => {
      fetches += 1;
      return new Response('secret', { headers: protectedHeaders });
    },
  });
  assert.equal((await app(request())).status, 200);
  currentIdentity = null;
  assert.equal((await app(request())).status, 401);
  currentIdentity = { groups: ['other'] };
  assert.equal((await app(request())).status, 403);
  assert.equal(fetches, 3);
});

test('missing, malformed, or contradictory policy never releases a protected path', async () => {
  for (const headers of [{}, { 'x-aem-cug-required': 'false' },
    { 'x-aem-cug-required': 'TRUE' }, { 'x-aem-cug-groups': 'team-a' }]) {
    const response = await gateway({ identity: { groups: ['team-a'] },
      upstream: () => new Response('secret', { headers }),
    }).app(request());
    assert.equal(response.status, 502);
    assert.doesNotMatch(await response.text(), /secret/);
  }
});

test('empty groups deny every authenticated user', async () => {
  const response = await gateway({ identity: { groups: ['team-a'] },
    upstream: () => new Response('secret', { headers: { 'x-aem-cug-required': 'true' } }),
  }).app(request());
  assert.equal(response.status, 403);
});

test('public content is served only outside required-policy paths', async () => {
  const response = await gateway({ upstream: () => new Response('public') }).app(request('/about'));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'public');
});

test('public content becoming protected is re-evaluated on the next request', async () => {
  let headers = {};
  const { app } = gateway({ upstream: () => new Response('content', { headers }) });
  assert.equal((await app(request('/about'))).status, 200);
  headers = protectedHeaders;
  assert.equal((await app(request('/about'))).status, 401);
});

test('origin requests discard spoofed identity, routing, range and condition headers', async () => {
  const { app, seen } = gateway({ identity: { groups: ['team-a'] } });
  const response = await app(request('/members/page', { headers: {
    Authorization: 'Bearer browser-token', Cookie: 'session=secret',
    'X-Forwarded-Host': 'attacker.example', 'X-Edgefunction-Request': 'true',
    'X-AEM-CUG-Required': 'false', 'X-AEM-CUG-Groups': 'team-a',
    'If-None-Match': 'etag', 'If-Modified-Since': 'yesterday', Range: 'bytes=0-3',
  } }));
  assert.equal(response.status, 200);
  assert.equal(seen[0].headers.get('authorization'), 'token origin-token');
  assert.equal(seen[0].headers.get('x-forwarded-host'), 'portal.example.com');
  for (const name of ['cookie', 'x-edgefunction-request', 'x-aem-cug-required',
    'x-aem-cug-groups', 'if-none-match', 'if-modified-since', 'range', 'x-push-invalidation']) {
    assert.equal(seen[0].headers.get(name), null, name);
  }
  assert.equal(seen[0].redirect, 'manual');
});

test('missing origin token never makes an unauthenticated origin fetch', async () => {
  const { app, seen } = gateway({ secret: '' });
  assert.equal((await app(request())).status, 503);
  assert.equal(seen.length, 0);
});

test('HEAD fetches complete policy and returns no body after authorization', async () => {
  const { app, seen } = gateway({ identity: { groups: ['team-a'] } });
  const response = await app(request('/members/page', { method: 'HEAD' }));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '');
  assert.equal(seen[0].method, 'GET');
  assert.equal((await gateway().app(request('/members/page', { method: 'HEAD' }))).status, 401);
});

for (const status of [206, 304, 500, 503]) {
  test(`unexpected origin ${status} cannot bypass policy`, async () => {
    const response = await gateway({ upstream: () => new Response(status === 304 ? null : 'secret', { status }) }).app(request());
    assert.equal(response.status, 502);
  });
}

test('drafts and alternate hosts never reach the origin', async () => {
  const { app, seen } = gateway();
  for (const path of ['/drafts', '/drafts/page', '/%64rafts/page']) assert.equal((await app(request(path))).status, 404);
  assert.equal((await app(new Request('https://edgefunction-example.adobeaemcloud.com/members/page'))).status, 421);
  assert.equal(seen.length, 0);
});

test('ambiguous paths are rejected and encoded paths use the same policy', async () => {
  const { app } = gateway({ upstream: () => new Response('secret') });
  for (const path of ['/members%252fpage', '/members%5cpage', '/members//page']) {
    assert.equal((await app(request(path))).status, 400);
  }
  assert.equal((await app(request('/%6dembers/page'))).status, 502);
});

test('browser login redirect preserves only a same-site return URL', async () => {
  const response = await gateway().app(request('/members/page?campaign=x', { headers: { Accept: 'text/html' } }));
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/auth/login?returnTo=%2Fmembers%2Fpage%3Fcampaign%3Dx');
  assert.equal((await gateway({ mode: 'deny' }).app(request('/', { headers: { Accept: 'text/html' } }))).status, 401);
});

test('method restrictions preserve telemetry POST and reject content mutations', async () => {
  const { app, seen } = gateway({ upstream: () => new Response(null, { status: 204 }) });
  assert.equal((await app(request('/page', { method: 'POST', body: 'x' }))).status, 405);
  assert.equal((await app(request('/.rum/1', { method: 'DELETE' }))).status, 405);
  assert.equal((await app(request('/.rum/1', { method: 'POST', body: 'telemetry' }))).status, 204);
  assert.equal(await seen[0].text(), 'telemetry');
});

test('query allowlists remove every unknown parameter and sort remaining values', () => {
  assert.equal(normalizedOriginUrl('https://example.com/data.json?bad=1&evil=2&sheet=one&limit=3', settings.originHostname).search, '?limit=3&sheet=one');
  assert.equal(normalizedOriginUrl(`https://example.com/media_${'a'.repeat(40)}.png?bad=1&evil=2&width=500`, settings.originHostname).search, '?width=500');
  assert.equal(normalizedOriginUrl('https://example.com/page?code=x&foo=bar', settings.originHostname).search, '');
});

test('origin redirects use the public hostname and keep same-site query parameters', async () => {
  const { app } = gateway({ upstream: () => new Response(null, { status: 301, headers: { Location: `https://${settings.originHostname}/new` } }) });
  const response = await app(request('/old?campaign=x'));
  assert.equal(response.headers.get('location'), 'https://portal.example.com/new?campaign=x');
  const external = await gateway({ upstream: () => new Response(null, { status: 301, headers: { Location: 'https://other.example/' } }) }).app(request('/old?secret=x'));
  assert.equal(external.headers.get('location'), 'https://other.example/');
});

test('configuration rejects credential-bearing destinations and invalid modes', () => {
  const values = { ORIGIN_HOSTNAME: settings.originHostname, PUBLIC_ORIGIN: settings.publicOrigin };
  assert.equal(readSettings((key) => values[key]).mode, 'deny');
  assert.deepEqual(readSettings((key) => values[key]).protectedPrefixes, ['/']);
  for (const override of [{ ORIGIN_HOSTNAME: 'main--site--org.aem.live.attacker.com' },
    { PUBLIC_ORIGIN: 'http://portal.example.com' }, { PUBLIC_ORIGIN: 'https://user:pass@portal.example.com' },
    { AUTH_MODE: 'allow' }, { PROTECTED_PATH_PREFIXES: '"/members"' }]) {
    assert.throws(() => readSettings((key) => ({ ...values, ...override })[key]));
  }
});

test('metadata policy uses path boundaries', () => {
  assert.throws(() => readPolicy(new Headers(), '/members/page', ['/members']));
  assert.throws(() => readPolicy(new Headers(), '/members.plain.html', ['/members']));
  assert.throws(() => readPolicy(new Headers(), '/members.json', ['/members']));
  assert.equal(readPolicy(new Headers(), '/membership', ['/members']).protected, false);
});
