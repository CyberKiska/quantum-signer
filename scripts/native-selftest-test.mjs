// Fault injection for the native conditional self-tests: a corrupted NIST
// fixture must stop verification and private operations in the shipped CLI.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { build } from 'esbuild';
import { versionAtLeast as versionAtLeastForTest } from '../src/native/crypto.js';

async function bundle(corrupt) {
  const plugins = corrupt ? [{ name: 'corrupt-kat', setup(builder) {
    builder.onLoad({ filter: corrupt.filter }, async ({ path: file }) => {
      const data = JSON.parse(await readFile(file, 'utf8'));
      corrupt.mutate(data);
      return { loader: 'json', contents: JSON.stringify(data) };
    });
  } }] : [];
  const out = await build({ entryPoints: ['src/native/cli.mjs'], bundle: true, platform: 'node', format: 'esm',
    write: false, logLevel: 'silent', plugins });
  return out.outputFiles[0].contents;
}

const dir = await mkdtemp(path.join(tmpdir(), 'qsig-native-selftest-'));
const run = (file, args, input) => spawnSync(process.execPath, [file, ...args], { cwd: dir, input, encoding: 'utf8', timeout: 120000 });
const flip = (hex) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);
try {
  const good = path.join(dir, 'good.mjs');
  await writeFile(good, await bundle(null));
  const doctor = run(good, ['doctor']);
  assert.equal(doctor.status, 0, doctor.stderr);
  assert.equal(JSON.parse(doctor.stdout).selfTest, 'pass');

  const password = 'native self-test fault injection password\n';
  await writeFile(path.join(dir, 'payload'), 'payload');
  assert.equal(run(good, ['keygen', '--suite', 'ML-DSA-44', '--secret', 'k.pqse', '--public', 'k.pqpk', '--passphrase-fd', '0'], password).status, 0);
  const digest = run(good, ['hash', '--file', 'payload']).stdout.trim();
  assert.equal(run(good, ['sign', '--secret', 'k.pqse', '--file', 'payload', '--expect-sha3-512', digest, '--out', 'p.qsig', '--passphrase-fd', '0'], password).status, 0);

  const faults = {
    'ML-DSA KeyGen KAT': { filter: /kat-vectors\.json$/, mutate: (d) => { d.mlDsaKeyGen[0].seedHex = flip(d.mlDsaKeyGen[0].seedHex); } },
    'verification KAT': { filter: /verification-vectors\.json$/, mutate: (d) => {
      const bytes = Buffer.from(d.vectors[0].signatureBase64, 'base64'); bytes[5] ^= 1; d.vectors[0].signatureBase64 = bytes.toString('base64');
    } },
  };
  for (const [label, fault] of Object.entries(faults)) {
    const bad = path.join(dir, 'bad.mjs');
    await writeFile(bad, await bundle(fault));
    for (const args of [
      ['doctor'],
      ['verify', '--file', 'payload', '--signature', 'p.qsig', '--public', 'k.pqpk'],
      ['sign', '--secret', 'k.pqse', '--file', 'payload', '--expect-sha3-512', digest, '--out', `x-${args0(label)}.qsig`, '--passphrase-fd', '0'],
      ['keygen', '--suite', 'ML-DSA-44', '--secret', `x-${args0(label)}.pqse`, '--public', `x-${args0(label)}.pqpk`, '--passphrase-fd', '0'],
    ]) {
      const result = run(bad, args, password);
      assert.equal(result.status, 1, `${label}: ${args[0]} must fail closed`);
      assert.match(result.stderr, /self-test failed/u, `${label}: ${args[0]} must report the self-test failure`);
    }
  }
} finally { await rm(dir, { recursive: true, force: true }); }

function args0(label) { return label.replace(/\W+/gu, '-'); }

assert(versionAtLeastForTest('3.5.0', '3.5.0') && versionAtLeastForTest('3.6.3', '3.5.0') && versionAtLeastForTest('4.0.0', '3.5.0'));
assert(!versionAtLeastForTest('3.4.9', '3.5.0') && !versionAtLeastForTest('3.0.13+quic', '3.5.0') && !versionAtLeastForTest('', '3.5.0'));
console.log('Native self-test fault injection and OpenSSL floor: PASS');
