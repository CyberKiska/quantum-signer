import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject } from './build.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const distDir = path.join(root, 'dist');

async function listFiles(directory, prefix = '') {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) files.push(...(await listFiles(path.join(directory, entry.name), relative)));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}

async function digestBuild() {
  const hash = createHash('sha256');
  for (const relative of await listFiles(distDir)) {
    const bytes = await readFile(path.join(distDir, relative));
    hash.update(relative, 'utf8');
    hash.update(Uint8Array.of(0));
    hash.update(bytes);
    hash.update(Uint8Array.of(0xff));
  }
  return hash.digest('hex');
}

await buildProject();
const first = await digestBuild();
await buildProject();
const second = await digestBuild();

if (first !== second) throw new Error(`Non-reproducible build: ${first} != ${second}`);
console.log(`Reproducible build: ${first}`);
