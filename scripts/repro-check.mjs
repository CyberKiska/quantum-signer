import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject } from './build.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const distDir = path.join(root, 'dist');
const expectedDigestPath = path.join(__dirname, 'expected-build-digests.json');

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
  const manifest = JSON.parse(await readFile(path.join(distDir, 'build-manifest.json'), 'utf8'));
  const sourceCommit = manifest.sourceCommit;
  if (typeof sourceCommit !== 'string' || sourceCommit.length === 0) {
    throw new Error('Build manifest is missing sourceCommit');
  }
  const indexText = await readFile(path.join(distDir, 'index.html'), 'utf8');
  const normalizedIndexText = indexText
    .replace(
      /(<meta name="build-commit" content=")[^"]+(" \/>)/u,
      '$1%SOURCE_COMMIT%$2'
    )
    .replace(
      /(<span class="build-id" title=")[^"]+(">)[^<]+(<\/span>)/u,
      '$1%SOURCE_COMMIT%$2%SOURCE_COMMIT_SHORT%$3'
    );
  const normalizedIndex = Buffer.from(
    normalizedIndexText,
    'utf8'
  );
  const normalizedIndexSha256 = createHash('sha256').update(normalizedIndex).digest('hex');
  const normalizedManifest = {
    ...manifest,
    sourceCommit: '%SOURCE_COMMIT%',
    artifacts: manifest.artifacts.map((artifact) =>
      artifact.path === 'index.html'
        ? { ...artifact, bytes: normalizedIndex.length, sha256: normalizedIndexSha256 }
        : artifact
    ),
  };
  const hash = createHash('sha256');
  for (const relative of await listFiles(distDir)) {
    let bytes = await readFile(path.join(distDir, relative));
    if (relative === 'index.html') bytes = normalizedIndex;
    if (relative === 'build-manifest.json') {
      bytes = Buffer.from(`${JSON.stringify(normalizedManifest, null, 2)}\n`, 'utf8');
    }
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
const expectedDigests = JSON.parse(await readFile(expectedDigestPath, 'utf8'));
const builtManifest = JSON.parse(await readFile(path.join(distDir, 'build-manifest.json'), 'utf8'));
const configurationKey = `${builtManifest.basePath}|${builtManifest.privateKeyOperations}`;
const expected = expectedDigests[configurationKey];
if (!/^[0-9a-f]{64}$/u.test(expected)) throw new Error('Expected build digest is not canonical SHA-256 hex');
if (first !== expected) {
  throw new Error(`Build digest changed: expected ${expected}, got ${first}`);
}
console.log(`Reproducible build matches pinned digest (${configurationKey}): ${first}`);
