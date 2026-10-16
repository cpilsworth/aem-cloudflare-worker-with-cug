/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */

import { ConfigStore } from 'fastly:config-store';
import { SecretStore } from 'fastly:secret-store';
import { CacheOverride } from 'fastly:cache-override';
import { readSettings } from './settings.js';

export function runtime() {
  const config = new ConfigStore('config_default');
  const settings = readSettings((name) => config.get(name));
  const secrets = new SecretStore('secret_default');
  let bundled;
  async function getSecret(name) {
    if (!bundled) bundled = secrets.get('secrets').then((entry) => entry ? JSON.parse(entry.plaintext()) : null);
    const values = await bundled;
    const value = values ? values[name] : (await secrets.get(name))?.plaintext();
    if (typeof value !== 'string' || !value) throw new Error('Required secret unavailable');
    return value;
  }
  const pass = (request, backend) => fetch(request, {
    backend, cacheOverride: new CacheOverride('pass'),
  });
  return { settings, getSecret, fetchOrigin: (request) => pass(request, 'eds'), fetchIdp: pass };
}
