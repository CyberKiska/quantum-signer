import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey } from 'node:crypto';
import { build } from 'esbuild';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { generateKeypair, signBytes, verifyBytes as verifyJS } from '../src/crypto/algorithms.js';
import { generateNativeKey, importPkcs8, importLegacySecretKey, publicKeyBytes, checkPrivateKey, signBytesNative, verifyBytes } from '../src/native/crypto.js';
import { createDetachedSignature } from '../src/native/signing.js';
import { encryptSecretKeyFile, decryptSecretKeyFile } from '../src/crypto/key-protection.js';
import { packSecretKey, unpackSignatureV2 } from '../src/formats/containers.js';

const message = Buffer.from('Native provider interoperability: \u0000\u00e9\ud83d\udd10');
const contextBytes = Buffer.from('quantum-signer/v2');
const password = 'test-only passphrase for native checks';
for (const suite of listSuites()) {
  const key = generateNativeKey(suite.id);
  const publicKey = publicKeyBytes(suite.id, key);
  const signature = signBytesNative({ suiteId: suite.id, privateKey: key, message, contextBytes });
  assert(verifyJS({ suiteId: suite.id, publicKey, message, contextBytes, signature }));
  assert(!verifyBytes({ suiteId: suite.id, publicKey, message, contextBytes: Buffer.from('wrong'), signature }));
  assert(!verifyBytes({ suiteId: suite.id, publicKey, message: Buffer.from('wrong'), contextBytes, signature }));
  const changed = Buffer.from(signature); changed[changed.length - 1] ^= 1;
  assert(!verifyBytes({ suiteId: suite.id, publicKey, message, contextBytes, signature: changed }));
  const der = key.export({ type: 'pkcs8', format: 'der' });
  const original = Buffer.from(der);
  let decrypted;
  try {
    const encrypting = encryptSecretKeyFile({ suiteId: suite.id, secretKeyFile: der, passphrase: password, keyFormat: 'pkcs8', iterations: 100000 });
    der.fill(0); // Async API must own its plaintext snapshot.
    const encrypted = await encrypting;
    const decrypting = decryptSecretKeyFile(encrypted, password);
    encrypted.fill(0); // Async API must own its ciphertext snapshot.
    decrypted = await decrypting;
    assert.equal(decrypted.keyFormat, 'pkcs8');
    assert.deepEqual(Buffer.from(decrypted.secretKeyFile), original);
    const restored = importPkcs8(suite.id, decrypted.secretKeyFile);
    assert.throws(() => importPkcs8(suite.id, Buffer.concat([decrypted.secretKeyFile, Buffer.from([0])])));
    assert.throws(() => importPkcs8(suite.id, decrypted.secretKeyFile.subarray(0, decrypted.secretKeyFile.length - 1)));
    checkPrivateKey(suite.id, restored);
    assert.deepEqual(publicKeyBytes(suite.id, restored), publicKey);
    assert.throws(() => importPkcs8(suite.id === 1 ? 2 : 1, decrypted.secretKeyFile));
    const digest = createHash('sha3-512').update(message).digest();
    const parsed = unpackSignatureV2(createDetachedSignature(suite.id, restored, digest));
    assert(verifyJS({ suiteId: suite.id, publicKey, message: parsed.tbs, contextBytes: parsed.ctxBytes, signature: parsed.signature }));
  } finally { der.fill(0); original.fill(0); decrypted?.secretKeyFile.fill(0); }

  const legacy = generateKeypair(suite.id);
  try {
    const imported = importLegacySecretKey(suite.id, legacy.secretKey);
    checkPrivateKey(suite.id, imported);
    assert.deepEqual(publicKeyBytes(suite.id, imported), Buffer.from(legacy.publicKey));
    const jsSig = signBytes({ suiteId: suite.id, secretKey: legacy.secretKey, message, contextBytes, hedged: false });
    assert(verifyBytes({ suiteId: suite.id, publicKey: legacy.publicKey, message, contextBytes, signature: jsSig }));
  } finally { legacy.secretKey.fill(0); }
  console.log(`  ${suite.name}: native/JS signatures, contexts, key import and encrypted PKCS#8 PASS`);
}

// Runtime dependency gate: supported CLI must not load third-party cryptography.
const bundle = await build({ entryPoints: ['src/native/cli.mjs'], bundle: true, platform: 'node', format: 'esm', write: false, metafile: true, logLevel: 'silent' });
assert(!Object.keys(bundle.metafile.inputs).some(p => p.includes('node_modules/')));

const directory = await mkdtemp(path.join(tmpdir(), 'qsig-native-'));
const run = (args, expected = 0) => {
  const result = spawnSync(process.execPath, [path.resolve('src/native/cli.mjs'), ...args], {
    cwd: directory, input: `${password}\n`, encoding: 'utf8', timeout: 120000,
  });
  assert.equal(result.status, expected, `${args[0]}: ${result.stderr}`);
  assert(!result.stdout.includes(password) && !result.stderr.includes(password));
  return result.stdout;
};
try {
  await writeFile(path.join(directory, 'payload'), message);
  run(['keygen', '--suite', 'ML-DSA-44', '--secret', 'key.pqse', '--public', 'key.pqpk', '--passphrase-fd', '0']);
  if (process.platform !== 'win32') assert.equal((await stat(path.join(directory, 'key.pqse'))).mode & 0o777, 0o600);
  const saved = await readFile(path.join(directory, 'key.pqse'));
  run(['keygen', '--secret', 'key.pqse', '--public', 'key.pqpk', '--passphrase-fd', '0'], 1);
  assert.deepEqual(await readFile(path.join(directory, 'key.pqse')), saved);
  const digest = run(['hash', '--file', 'payload']).trim();
  run(['sign', '--secret', 'key.pqse', '--file', 'payload', '--out', 'payload.qsig', '--expect-sha3-512', '00'.repeat(64), '--passphrase-fd', '0'], 1);
  run(['sign', '--secret', 'key.pqse', '--file', 'payload', '--out', 'payload.qsig', '--expect-sha3-512', digest, '--passphrase-fd', '0']);
  run(['verify', '--file', 'payload', '--signature', 'payload.qsig', '--public', 'key.pqpk']);
  run(['verify', '--file', 'payload', '--signature', 'payload.qsig'], 2);
  run(['public', '--secret', 'key.pqse', '--out', 'recovered.pqpk', '--passphrase-fd', '0']);
  assert.deepEqual(await readFile(path.join(directory, 'key.pqpk')), await readFile(path.join(directory, 'recovered.pqpk')));
  await writeFile(path.join(directory, 'payload'), 'tampered');
  run(['verify', '--file', 'payload', '--signature', 'payload.qsig', '--public', 'key.pqpk'], 1);
  run(['doctor', '--secret', 'unexpected'], 1);
  run(['hash', '--file', 'payload', '--file', 'payload'], 1);
  const legacy = generateKeypair(1);
  try {
    const pqsk = packSecretKey({ suiteId: 1, keyBytes: legacy.secretKey });
    await writeFile(path.join(directory, 'legacy.pqsk'), pqsk);
    const pqse = await encryptSecretKeyFile({ suiteId: 1, secretKeyFile: pqsk, passphrase: password, iterations: 100000 });
    await writeFile(path.join(directory, 'legacy.pqse'), pqse);
    run(['public', '--secret', 'legacy.pqsk', '--out', 'legacy-raw.pqpk']);
    run(['public', '--secret', 'legacy.pqse', '--out', 'legacy-protected.pqpk', '--passphrase-fd', '0']);
    assert.deepEqual(await readFile(path.join(directory, 'legacy-raw.pqpk')), await readFile(path.join(directory, 'legacy-protected.pqpk')));
    pqsk.fill(0);
  } finally { legacy.secretKey.fill(0); }
} finally { await rm(directory, { recursive: true, force: true }); }
console.log('Native cryptography and CLI regression tests: PASS');
