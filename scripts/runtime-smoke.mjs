import { spawn } from 'node:child_process';
import { copyFile } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';
import fastly from '@fastly/cli';

await copyFile('bin/main.wasm', 'bin/production.wasm');
await copyFile('bin/smoke.wasm', 'bin/main.wasm');
const server = spawn(fastly, ['compute', 'serve', '--skip-build', '--addr', '127.0.0.1:7676'], { stdio: 'inherit' });
let spawnError;
server.on('error', (error) => { spawnError = error; });
try {
  let response;
  for (let attempt = 0; attempt < 45; attempt += 1) {
    if (spawnError) throw spawnError;
    if (server.exitCode !== null) throw new Error(`Viceroy exited: ${server.exitCode}`);
    try {
      response = await fetch('http://127.0.0.1:7676/', { signal: AbortSignal.timeout(5000) });
      break;
    } catch {
      await setTimeout(1000);
    }
  }
  if (!response) throw new Error('Viceroy did not start');
  const body = await response.text();
  if (!response.ok || !JSON.parse(body).ok) throw new Error(`Runtime smoke failed: ${body}`);
  console.log(body);
} finally {
  server.kill('SIGTERM');
  await copyFile('bin/production.wasm', 'bin/main.wasm');
}
