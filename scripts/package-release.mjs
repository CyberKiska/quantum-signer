import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdir, rm, readFile, writeFile, cp, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProject } from './build.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'release');
await buildProject();
await rm(output, { recursive: true, force: true });
await mkdir(output);
const native = await build({ entryPoints: [path.join(root, 'src/native/cli.mjs')], bundle: true,
  platform: 'node', target: 'node26', format: 'esm', write: false, metafile: true, logLevel: 'silent' });
if (Object.keys(native.metafile.inputs).some(file => file.includes('node_modules/'))) {
  throw new Error('Release signing CLI contains third-party runtime code');
}
await writeFile(path.join(output, 'quantum-signer.mjs'), native.outputFiles[0].contents);
await cp(path.join(root, 'dist'), path.join(output, 'browser'), { recursive: true });
await cp(path.join(root, 'LICENSE'), path.join(output, 'LICENSE'));
const notices = [];
for (const name of ['hashes', 'post-quantum']) {
  notices.push(`@noble/${name}\n\n${await readFile(path.join(root, 'node_modules/@noble', name, 'LICENSE'), 'utf8')}`);
}
await writeFile(path.join(output, 'THIRD-PARTY.txt'), notices.join('\n\n'));
await cp(path.join(root, 'spec/qsig-v2.txt'), path.join(output, 'qsig-v2.txt'));
await cp(path.join(root, 'docs/RELEASE.md'), path.join(output, 'RELEASE.md'));
// esbuild's legal-comment sidecar (if any) is part of the authenticated inventory.
for (const file of native.outputFiles.slice(1)) await writeFile(path.join(output, path.basename(file.path)), file.contents);
const entries = [];
async function inventory(directory, prefix = '') {
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const relative = `${prefix}${entry.name}`;
    if (entry.isDirectory()) await inventory(path.join(directory, entry.name), `${relative}/`);
    else {
      const bytes = await readFile(path.join(directory, entry.name));
      entries.push({ path: relative, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
    }
  }
}
await inventory(output);
const browserManifest = JSON.parse(await readFile(path.join(root, 'dist/build-manifest.json'), 'utf8'));
await writeFile(path.join(output, 'release-manifest.json'), `${JSON.stringify({
  schema: 'quantum-signer-release/v1', version: browserManifest.applicationVersion,
  sourceCommit: browserManifest.sourceCommit, artifacts: entries,
}, null, 2)}\n`);
console.log('Release directory created. Its hashes are an inventory, not authentication; verify CI provenance before use.');
