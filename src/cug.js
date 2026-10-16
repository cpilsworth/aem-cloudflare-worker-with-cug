/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */

export function requiresMetadata(path, prefixes) {
  return prefixes.some((prefix) => prefix === '/' || path === prefix.replace(/\/$/, '')
    || path.startsWith(`${prefix.replace(/\/$/, '')}/`)
    || path.startsWith(`${prefix.replace(/\/$/, '')}.`));
}

export function readPolicy(headers, path, prefixes) {
  const flag = headers.get('x-aem-cug-required');
  const groups = headers.get('x-aem-cug-groups');
  if (flag !== null && flag !== 'true' && flag !== 'false') throw new Error('Invalid CUG flag');
  if (flag !== 'true') {
    if (groups !== null || requiresMetadata(path, prefixes)) throw new Error('Missing CUG policy');
    return { protected: false, groups: [] };
  }
  const allowed = [...new Set((groups || '').split(',').map((g) => g.trim()).filter(Boolean))];
  if (allowed.length > 100 || allowed.some((g) => g.length > 256)) throw new Error('Invalid CUG groups');
  return { protected: true, groups: allowed };
}

export function mayRead(identity, policy) {
  return Boolean(identity && Array.isArray(identity.groups)
    && policy.groups.some((group) => identity.groups.includes(group)));
}
