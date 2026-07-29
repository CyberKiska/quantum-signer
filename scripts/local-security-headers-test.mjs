import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const port = 41_873;
const deploymentUrl = `http://127.0.0.1:${port}/`;
let output = '';

const preview = spawn(process.execPath, ['scripts/dev.mjs', '--preview'], {
  cwd: root,
  env: {
    ...process.env,
    PORT: String(port),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

for (const stream of [preview.stdout, preview.stderr]) {
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    output += chunk;
  });
}

try {
  process.env.DEPLOYMENT_URL = deploymentUrl;
  await import('./live-security-headers-test.mjs');
} catch (error) {
  const detail = output.trim();
  if (detail) error.message = `${error.message}\nLocal preview output:\n${detail}`;
  throw error;
} finally {
  preview.kill('SIGTERM');
  await new Promise((resolve) => {
    if (preview.exitCode !== null) resolve();
    else preview.once('exit', resolve);
  });
}
