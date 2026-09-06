import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, writeFile, unlink, symlink, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

function run(file, args = [], expected = 0, options = {}) {
  const result = spawnSync(process.execPath, [file, ...args], { encoding: 'utf8', timeout: 120000, ...options });
  assert.equal(result.status, expected, `${file}: ${result.stderr}`);
  return result.stdout;
}
run('scripts/package-release.mjs');
const first = await readFile('release/release-manifest.json');
run('scripts/package-release.mjs');
assert.deepEqual(await readFile('release/release-manifest.json'), first, 'Release artifacts are not reproducible');
run('scripts/verify-release.mjs', ['release']);
const doctor = JSON.parse(run('release/quantum-signer.mjs', ['doctor']));
assert.equal(doctor.signingProvider, 'node:crypto');
assert.equal(doctor.moduleValidationEstablished, false);
// Exercise the distributed executable, including encrypted key storage and
// detached verification, without relying on source-tree module resolution.
const sandbox = await mkdtemp(path.join(tmpdir(), 'qsig-release-'));
const executable = path.resolve('release/quantum-signer.mjs');
const options = { cwd: sandbox, input: 'release smoke test password only\n' };
try {
  await writeFile(path.join(sandbox, 'payload'), 'release 2.0.1 smoke test');
  run(executable, ['keygen', '--suite', 'ML-DSA-44', '--secret', 'key.pqse', '--public', 'key.pqpk', '--passphrase-fd', '0'], 0, options);
  const digest = run(executable, ['hash', '--file', 'payload'], 0, options).trim();
  run(executable, ['sign', '--secret', 'key.pqse', '--file', 'payload', '--expect-sha3-512', digest, '--out', 'payload.qsig', '--passphrase-fd', '0'], 0, options);
  run(executable, ['verify', '--file', 'payload', '--signature', 'payload.qsig', '--public', 'key.pqpk'], 0, options);
  run(executable, ['verify', '--file', 'payload', '--signature', 'payload.qsig'], 2, options);
  await writeFile(path.join(sandbox, 'payload'), 'altered payload');
  run(executable, ['verify', '--file', 'payload', '--signature', 'payload.qsig', '--public', 'key.pqpk'], 1, options);
} finally { await rm(sandbox, { recursive: true, force: true }); }
const cli = await readFile('release/quantum-signer.mjs');
try {
  await writeFile('release/quantum-signer.mjs', Buffer.concat([cli, Buffer.from('\n//tampered\n')]));
  run('scripts/verify-release.mjs', ['release'], 1);
} finally { await writeFile('release/quantum-signer.mjs', cli); }
try {
  await writeFile('release/unexpected.js', 'unlisted executable');
  run('scripts/verify-release.mjs', ['release'], 1);
} finally { await unlink('release/unexpected.js'); }
try {
  await symlink('quantum-signer.mjs', 'release/alias');
  run('scripts/verify-release.mjs', ['release'], 1);
} finally { await unlink('release/alias'); }
const manifest = JSON.parse(first);
assert.equal(manifest.version, JSON.parse(await readFile('package.json', 'utf8')).version);
assert(manifest.artifacts.some(item => item.path === 'RELEASE.md'));
assert(!manifest.artifacts.some(item => /audit|internal|release-validation/i.test(item.path)), 'Internal documents leaked into the release');
manifest.artifacts[0].path = '../outside';
try {
  await writeFile('release/release-manifest.json', JSON.stringify(manifest));
  run('scripts/verify-release.mjs', ['release'], 1);
} finally { await writeFile('release/release-manifest.json', first); }
run('scripts/verify-release.mjs', ['release']);
console.log(`Release packaging, reproducibility and tamper tests: PASS (manifest SHA-256 ${createHash('sha256').update(first).digest('hex')})`);
