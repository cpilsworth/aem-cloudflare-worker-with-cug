/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */

function httpsUrl(value, name) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port) {
    throw new Error(`Invalid ${name}`);
  }
  return url;
}

export function readSettings(get) {
  const origin = get('ORIGIN_HOSTNAME');
  if (!/^main--[a-z0-9-]+--[a-z0-9-]+\.(?:aem|hlx)\.live$/.test(origin || '')) {
    throw new Error('Invalid ORIGIN_HOSTNAME');
  }
  const publicUrl = httpsUrl(get('PUBLIC_ORIGIN'), 'PUBLIC_ORIGIN');
  if (publicUrl.pathname !== '/' || publicUrl.search) throw new Error('Invalid PUBLIC_ORIGIN');
  const mode = get('AUTH_MODE') || 'deny';
  if (!['deny', 'oidc'].includes(mode)) throw new Error('Invalid AUTH_MODE');
  const prefixes = JSON.parse(get('PROTECTED_PATH_PREFIXES') || '["/"]');
  if (!Array.isArray(prefixes) || prefixes.some((p) => typeof p !== 'string'
      || !p.startsWith('/') || /[?%#\\\s]/.test(p))) throw new Error('Invalid protected paths');
  const settings = {
    originHostname: origin, publicOrigin: publicUrl.origin, mode,
    protectedPrefixes: prefixes, sessionSeconds: 300,
  };
  if (mode === 'oidc') {
    httpsUrl(get('OIDC_ISSUER'), 'OIDC_ISSUER');
    settings.issuer = get('OIDC_ISSUER');
    settings.clientId = get('OIDC_CLIENT_ID');
    settings.authorizationEndpoint = httpsUrl(get('OIDC_AUTHORIZATION_ENDPOINT'), 'authorization endpoint').href;
    settings.tokenEndpoint = httpsUrl(get('OIDC_TOKEN_ENDPOINT'), 'token endpoint').href;
    settings.jwksUri = httpsUrl(get('OIDC_JWKS_URI'), 'JWKS URI').href;
    settings.groupsClaim = get('OIDC_GROUPS_CLAIM') || 'groups';
    settings.scope = get('OIDC_SCOPE') || 'openid profile groups';
    settings.tokenAuthMethod = get('OIDC_TOKEN_AUTH_METHOD') || 'client_secret_post';
    if (!settings.clientId || !settings.scope.split(' ').includes('openid')
        || !['client_secret_post', 'client_secret_basic', 'none'].includes(settings.tokenAuthMethod)) {
      throw new Error('Invalid OIDC configuration');
    }
  }
  return settings;
}
