import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { importLegacySecretKey, checkPrivateKey, generateNativeKey } from '../src/native/crypto.js';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { encryptSecretKeyFile, decryptSecretKeyFile, describeProtectedSecretKeyFile } from '../src/crypto/key-protection.js';
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
  const envelope = await encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', kdf: 'pbkdf2', passphrase, iterations: 100000 });
  assert.equal(envelope[4], 2, 'explicit PBKDF2 PKCS#8 envelope must stay PQSE 2');
  await assert.rejects(decryptSecretKeyFile(envelope, 'wrong password'));
  for (const offset of [4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 18, 22, 38, 50, envelope.length - 1]) {
    const bad = Uint8Array.from(envelope); bad[offset] ^= 1;
    await assert.rejects(decryptSecretKeyFile(bad, passphrase), `PQSE mutation ${offset}`);
  }
  await assert.rejects(decryptSecretKeyFile(envelope.subarray(0, envelope.length - 1), passphrase));
  for (const iterations of [99999, 5000001, NaN]) {
    await assert.rejects(encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', kdf: 'pbkdf2', passphrase, iterations }));
  }

  // PQSE 3: Argon2id (RFC 9106) + AES-256-GCM, every header byte authenticated.
  const argon2id = { memoryKiB: 65_536, passes: 1, parallelism: 1 };
  const v3 = await encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', passphrase, argon2id });
  assert.equal(v3[4], 3);
  assert.equal(v3[7], 2);
  assert.equal(describeProtectedSecretKeyFile(v3).legacy, false);
  assert.equal(describeProtectedSecretKeyFile(envelope).legacy, true);
  const opened = await decryptSecretKeyFile(v3, passphrase);
  assert.equal(opened.kdf, 'argon2id');
  assert.deepEqual(Buffer.from(opened.secretKeyFile), Buffer.from(der));
  await assert.rejects(decryptSecretKeyFile(v3, 'wrong password'));
  for (let offset = 4; offset < 54; offset++) {
    const bad = Uint8Array.from(v3); bad[offset] ^= 1;
    await assert.rejects(decryptSecretKeyFile(bad, passphrase), `PQSE 3 mutation ${offset}`);
  }
  for (const offset of [54, v3.length - 1]) {
    const bad = Uint8Array.from(v3); bad[offset] ^= 1;
    await assert.rejects(decryptSecretKeyFile(bad, passphrase), `PQSE 3 ciphertext/tag mutation ${offset}`);
  }
  await assert.rejects(decryptSecretKeyFile(v3.subarray(0, v3.length - 1), passphrase));
  // Attacker-chosen costs are bounded before any derivation (resource limits).
  for (const [offset, value] of [[10, 65_535], [10, 2_097_153], [14, 0], [14, 11], [18, 0], [18, 17]]) {
    const bad = Uint8Array.from(v3);
    if (offset === 18) bad[18] = value; else new DataView(bad.buffer).setUint32(offset, value, true);
    await assert.rejects(decryptSecretKeyFile(bad, passphrase), (err) => err.code === 'E_FORMAT_LENGTH', `PQSE 3 bound ${offset}=${value}`);
  }
  for (const bad of [{ ...argon2id, memoryKiB: 1024 }, { ...argon2id, passes: 0 }, { ...argon2id, parallelism: 64 }]) {
    await assert.rejects(encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', passphrase, argon2id: bad }));
  }
  await assert.rejects(encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pqsk', kdf: 'argon2id', passphrase }));
  await assert.rejects(encryptSecretKeyFile({ suiteId: 1, secretKeyFile: der, keyFormat: 'pkcs8', passphrase: 'fourteen chars', argon2id }),
    (err) => err.code === 'E_KEY_PASSPHRASE_INVALID', 'new passwords need 15 code points');
} finally { der.fill(0); }
console.log('Native all-suite inconsistent key rejection and PQSE 2/3 mutation tests: PASS');
