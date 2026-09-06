// Run this from a separately trusted source checkout, after authenticating the
// manifest with GitHub provenance. Never execute an unverified downloaded CLI.
import { readFile, readdir, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
const directory = process.argv[2];
if (!directory || process.argv.length !== 3) throw new Error('Usage: node scripts/verify-release.mjs RELEASE_DIRECTORY');
const root = await realpath(directory);
const manifest = JSON.parse(await readFile(path.join(root, 'release-manifest.json'), 'utf8'));
if (manifest.schema !== 'quantum-signer-release/v1' || !Array.isArray(manifest.artifacts) || !manifest.artifacts.length) {
  throw new Error('Invalid release manifest');
}
const expected = new Set(['release-manifest.json']);
for (const item of manifest.artifacts) {
  if (typeof item.path !== 'string' || !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/u.test(item.path) ||
      item.path.split('/').some(part => part === '.' || part === '..') || expected.has(item.path) ||
      !Number.isSafeInteger(item.bytes) || item.bytes < 0 || !/^[a-f0-9]{64}$/u.test(item.sha256)) throw new Error('Invalid manifest entry');
  expected.add(item.path);
}
const actual = new Set();
async function inventory(dir, prefix = '') {
  for (const entry of await readdir(dir)) {
    const relative = `${prefix}${entry}`;
    const full = path.join(dir, entry);
    const info = await lstat(full);
    if (info.isSymbolicLink()) throw new Error('Release contains a symlink');
    if (info.isDirectory()) await inventory(full, `${relative}/`);
    else if (info.isFile()) actual.add(relative);
    else throw new Error('Release contains a non-regular file');
  }
}
await inventory(root);
if (actual.size !== expected.size || [...actual].some(file => !expected.has(file))) throw new Error('Release file inventory differs from manifest');
for (const item of manifest.artifacts) {
  const bytes = await readFile(path.join(root, item.path));
  if (bytes.length !== item.bytes || createHash('sha256').update(bytes).digest('hex') !== item.sha256) {
    throw new Error(`Release integrity failed: ${item.path}`);
  }
}
console.log('Release inventory integrity: PASS. This check alone does not authenticate the manifest or establish trust.');
