/* Copyright 2026 Adobe. Licensed under the Apache License, Version 2.0. */
/// <reference types="@fastly/js-compute" />

import { createApp } from './app.js';
import { createAuth } from './auth/oidc.js';
import { privateResponse } from './lib/http.js';
import { runtime } from './runtime.js';

addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  try {
    // Store access and crypto occur at request time, not during Wasm snapshotting.
    const services = runtime();
    return await createApp({ ...services, auth: createAuth(services.settings, services),
      log: (record) => console.log(JSON.stringify(record)),
    })(request);
  } catch {
    console.log(JSON.stringify({ event: 'configuration_unavailable' }));
    return privateResponse('Service unavailable', 503);
  }
}
