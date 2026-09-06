import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { importLegacySecretKey, checkPrivateKey, generateNativeKey } from '../src/native/crypto.js';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { encryptSecretKeyFile, decryptSecretKeyFile } from '../src/crypto/key-protection.js';
for (const file of ['nist-acvp-mldsa-siggen-vectors.json', 'nist-acvp-slhdsa-siggen-vectors.json']) {
  const source = JSON.parse(await readFile(new URL(file, import.meta.url), 'utf8'));
  for (const vector of source.vectors) {
    const suite = listSuites().find(s => s.name.toLowerCase() === vector.parameterSet.toLowerCase());
    const secret = Buffer.from(vector.secretKeyBase64, 'base64');
    try {
      checkPrivateKey(suite.id, importLegacySecretKey(suite.id, secret));
      // Break secret/public consistency, not just a container checksum.
      secret[suite.family === 'ML-DSA' ? 128 : 0] ^= 1;
      assert.throws(() => checkPrivateKey(suite.id, importLegacySecretKey(suite.id, secret)), suite.name);
    } finally { secret.fill(0); }
  }
}
const key = generateNativeKey(1);
const der = key.export({ type: 'pkcs8', format: 'der' });
const passphrase = 'test-only key envelope validation';
try {
  const envelope = await encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', passphrase, iterations: 100000 });
  await assert.rejects(decryptSecretKeyFile(envelope, 'wrong password'));
  for (const offset of [4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 18, 22, 38, 50, envelope.length - 1]) {
    const bad = Uint8Array.from(envelope); bad[offset] ^= 1;
    await assert.rejects(decryptSecretKeyFile(bad, passphrase), `PQSE mutation ${offset}`);
  }
  await assert.rejects(decryptSecretKeyFile(envelope.subarray(0, envelope.length - 1), passphrase));
  for (const iterations of [99999, 5000001, NaN]) {
    await assert.rejects(encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', passphrase, iterations }));
  }
} finally { der.fill(0); }
console.log('Native all-suite inconsistent key rejection and PQSE 2 mutation tests: PASS');
