// Compiled separately for Viceroy; this entry point is never deployed.
import { jwtVerify, createLocalJWKSet, SignJWT } from 'jose';
import fixture from './fixtures/identity.json';
import { createAuth, SESSION_COOKIE } from '../src/auth/oidc.js';
import { createApp } from '../src/app.js';

addEventListener('fetch', (event) => event.respondWith(smoke()));

async function smoke() {
  try {
    const { payload } = await jwtVerify(fixture.idToken, createLocalJWKSet(fixture.jwks), {
      algorithms: ['RS256'], issuer: 'https://idp.example.com', audience: 'smoke-client',
      currentDate: new Date(fixture.now * 1000), maxTokenAge: 300,
    });
    const settings = { publicOrigin: 'https://portal.example.com', clientId: 'smoke-client',
      originHostname: 'main--site--org.aem.live', mode: 'oidc', sessionSeconds: 300,
      protectedPrefixes: ['/'], authorizationEndpoint: 'https://idp.example.com/authorize',
      scope: 'openid groups',
    };
    const auth = createAuth(settings, { getSecret: async () => 'ab'.repeat(32), now: () => fixture.now });
    const session = await new SignJWT({ groups: payload.groups }).setProtectedHeader({ alg: 'HS256', typ: 'cug-session+jwt' })
      .setSubject(payload.sub).setIssuer(settings.publicOrigin).setAudience(settings.clientId)
      .setIssuedAt(fixture.now).setExpirationTime(fixture.now + 300)
      .sign(new Uint8Array(32).fill(0xab));
    const app = createApp({ settings, auth, getSecret: async () => 'test-only-origin-token',
      fetchOrigin: async () => new Response('private', { headers: {
        'x-aem-cug-required': 'true', 'x-aem-cug-groups': 'team-a',
      } }),
    });
    const allowed = await app(new Request(`${settings.publicOrigin}/members`, {
      headers: { Cookie: `${SESSION_COOKIE}=${session}` },
    }));
    const denied = await app(new Request(`${settings.publicOrigin}/members`));
    const login = await app(new Request(`${settings.publicOrigin}/auth/login`));
    if (allowed.status !== 200 || await allowed.text() !== 'private' || denied.status !== 401
        || login.status !== 303 || !login.headers.get('location').includes('code_challenge=')) {
      throw new Error('Runtime authentication smoke failed');
    }
    return new Response(JSON.stringify({ ok: true, rsa: true, hmac: true, pkce: true, gate: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(String(error.stack || error), { status: 500 });
  }
}
