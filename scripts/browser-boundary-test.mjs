import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { MAX_TEXT_INPUT_BYTES } from '../src/crypto/policy.js';
import { generateNativeKey, importPkcs8, publicKeyBytes } from '../src/native/crypto.js';
import { createDetachedSignature } from '../src/native/signing.js';
import { packPublicKey, packSecretKey, unpackSignatureV2 } from '../src/formats/containers.js';
import { decryptSecretKeyFile, encryptSecretKeyFile } from '../src/crypto/key-protection.js';
import { finalizePayloadVerification } from '../src/crypto/verify-policy.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';

const FAULTS = {
  verification: [/verification-vectors\.json$/, (v) => {
    const bad = Buffer.from(v.vectors[0].signatureBase64, 'base64'); bad[0] ^= 1; v.vectors[0].signatureBase64 = bad.toString('base64');
  }],
  signing: [/kat-vectors\.json$/, (v) => { v.mlDsaKeyGen[0].publicKeySha256 = '0'.repeat(64); }],
};
let rngCalls = 0;
async function worker({ fault } = {}) {
  const built = await build({ entryPoints: ['src/worker.js'], bundle: true, platform: 'browser', format: 'iife',
    write: false, logLevel: 'silent', plugins: fault ? [{ name: 'fault-injection', setup(builder) {
      const [filter, mutate] = FAULTS[fault];
      builder.onLoad({ filter }, async ({ path }) => {
        const vectors = JSON.parse(await readFile(path, 'utf8'));
        mutate(vectors);
        return { loader: 'json', contents: JSON.stringify(vectors) };
      });
    } }] : [] });
  const messages = [];
  const surface = { self: {}, postMessage: m => messages.push(m), TextEncoder, TextDecoder, Blob, setTimeout,
    Uint8Array, Uint16Array, Uint32Array, Int32Array, ArrayBuffer, DataView, BigUint64Array, atob, btoa,
    // Web Crypto only: CSPRNG (counted, so verification can be shown to use none) and SubtleCrypto.
    crypto: { getRandomValues: (array) => { rngCalls++; return crypto.getRandomValues(array); }, subtle: crypto.subtle } };
  // Bind intrinsics as locals: vm global lookups in hot loops (Argon2id, SLH-DSA)
  // are an order of magnitude slower than in a real worker.
  const locals = ['Math', 'Array', 'Object', 'Number', 'String', 'Error', 'TypeError', 'RangeError', 'Promise', 'BigInt',
    'Map', 'Set', 'JSON', 'Symbol', 'Reflect', 'Uint8Array', 'Uint16Array', 'Uint32Array', 'Int32Array', 'BigUint64Array',
    'ArrayBuffer', 'DataView'];
  vm.runInNewContext(`(function (${locals}) {${built.outputFiles[0].text}})(${locals})`, surface);
  let seq = 0;
  return async (type, payload = {}, id = ++seq) => {
    messages.length = 0;
    await surface.self.onmessage({ data: { id, type, payload } });
    return messages.findLast(m => m.type === 'RESULT' || m.type === 'ERROR');
  };
}
const call = await worker();
assert.equal((await call('SELFTEST')).result.ok, true);
for (const type of ['IMPORT_SECRET', 'EXPORT_SECRET', 'AUTHORIZE_SECRET_EXPORT', 'CLEAR_SECRET_SESSION', 'LOCK', 'constructor', 'toString', '__proto__', 'hasOwnProperty']) {
  assert.equal((await call(type)).code, 'E_WORKER_PROTOCOL', `Exposed unsupported worker operation ${type}`);
}
const textDigestHex = (text) => createHash('sha3-512').update(text).digest('hex');
assert.equal((await call('SIGN', { text: 'x', expectedDigestHex: textDigestHex('x'), expectedFingerprintHex: '' })).code, 'E_SESSION_MISSING');
for (const id of [0, -1, Infinity, NaN, {}, '', 'a'.repeat(129)]) assert.equal((await call('HASH_TEXT', { text: 'abc' }, id)).ok, false);
assert.equal((await call('HASH_TEXT', { text: 'a'.repeat(MAX_TEXT_INPUT_BYTES + 1) })).code, 'E_INPUT_TOO_LARGE');
assert.equal((await call('HASH_TEXT', { text: '\ud800' })).code, 'E_TEXT_ENCODING');
const payload = new Uint8Array([0, 1, 255, 128]);
const digest = createHash('sha3-512').update(payload).digest();
for (const suite of listSuites()) {
  rngCalls = 0;
  const key = generateNativeKey(suite.id);
  const sigFile = createDetachedSignature(suite.id, key, digest);
  const publicKeyFile = packPublicKey({ suiteId: suite.id, keyBytes: publicKeyBytes(suite.id, key) });
  const params = { file: new Blob([payload]), sigFile, publicKeyFile };
  const valid = await call('VERIFY_FILE', params);
  assert(valid.ok && valid.result.valid && valid.result.trusted, suite.name);
  const embedded = await call('VERIFY_FILE', { ...params, publicKeyFile: null });
  assert(!embedded.result.valid && embedded.result.integrityValid && !embedded.result.trusted &&
    embedded.result.code === 'E_SIGNER_UNTRUSTED', 'embedded-only must be integrity-only');
  const wrong = await call('VERIFY_FILE', { ...params, file: new Blob(['wrong']) });
  assert(!wrong.result.valid && !wrong.result.integrityValid && !wrong.result.trusted);
  assert.equal((await call('VERIFY_FILE', { ...params, publicKeyFile: {} })).ok, false);
  // Sampled one-bit mutations through the real browser worker (noble verifier).
  const step = Math.max(1, Math.floor(sigFile.length / 48));
  for (let offset = 0; offset < sigFile.length; offset += offset < 160 ? 3 : step) {
    const mutated = Uint8Array.from(sigFile);
    mutated[offset] ^= 1 << (offset % 8);
    for (const keyFile of [publicKeyFile, null]) {
      const response = await call('VERIFY_FILE', { ...params, sigFile: mutated, publicKeyFile: keyFile });
      assert(!response.ok || (!response.result.valid && !response.result.integrityValid),
        `${suite.name}: browser worker accepted a mutation at offset ${offset}`);
    }
  }
  assert.equal(rngCalls, 0, `${suite.name}: verification requested randomness`);
}

// Private operations. The worker must interoperate with CLI (OpenSSL) keys and
// signatures in both directions and sign only the reviewed digest and signer.
const password = 'browser boundary test passphrase';
const fastKdf = { memoryKiB: 65_536, passes: 1, parallelism: 1 };
const nativeVerify = (sigFile, publicKeyFile, text) => finalizePayloadVerification(unpackSignatureV2(sigFile), publicKeyFile,
  { computedHashHex: textDigestHex(text) });
async function signText(text, fingerprintHex, digestHex = textDigestHex(text)) {
  return call('SIGN', { text, expectedDigestHex: digestHex, expectedFingerprintHex: fingerprintHex });
}
// JavaScript SLH-DSA signing takes seconds; quick runs cover one SLH-DSA suite.
for (const suite of listSuites().filter((s) => process.env.FULL_SELFTEST === '1' || s.id === 0x02 || s.id === 0x11)) {
  const key = generateNativeKey(suite.id);
  const publicKeyFile = packPublicKey({ suiteId: suite.id, keyBytes: publicKeyBytes(suite.id, key) });
  const der = key.export({ type: 'pkcs8', format: 'der' });
  const pqse = await encryptSecretKeyFile({ suiteId: suite.id, secretKeyFile: der, passphrase: password, keyFormat: 'pkcs8', argon2id: fastKdf });
  assert.equal((await call('UNLOCK', { secretKeyFile: pqse, passphrase: `${password}!` })).code, 'E_KEY_DECRYPT_FAILED');
  const unlocked = await call('UNLOCK', { secretKeyFile: pqse, passphrase: password });
  assert(unlocked.ok && unlocked.result.suiteId === suite.id && !unlocked.result.legacy, `${suite.name}: ${JSON.stringify(unlocked).slice(0, 300)}`);
  assert.deepEqual(Buffer.from(unlocked.result.publicKeyFile), Buffer.from(publicKeyFile));
  const fp = unlocked.result.fingerprintHex;
  const signed = await signText('reviewed text', fp);
  assert(signed.ok && nativeVerify(signed.result.signatureFile, publicKeyFile, 'reviewed text').valid, `${suite.name}: OpenSSL rejected worker QSIG`);
  assert.equal(signed.result.hashHex, textDigestHex('reviewed text'));
  assert.equal((await signText('changed text', fp, textDigestHex('reviewed text'))).code, 'E_FILE_HASH_MISMATCH');
  assert.equal((await signText('reviewed text', '0'.repeat(64))).code, 'E_SESSION_MISSING');
  console.log(`  ${suite.name}: worker unlock of CLI key and OpenSSL-verified signing PASS`);
}

// Browser key generation: PQSE 3 with default Argon2id, readable by the CLI.
assert.equal((await call('KEYGEN', { suiteId: 0x01, passphrase: 'too short' })).code, 'E_KEY_PASSPHRASE_INVALID');
assert.equal((await call('KEYGEN', { suiteId: 0x04, passphrase: password })).code, 'E_SUITE_UNSUPPORTED');
const generated = await call('KEYGEN', { suiteId: 0x01, passphrase: password });
assert(generated.ok, 'KEYGEN failed');
const opened = await decryptSecretKeyFile(generated.result.secretKeyFile, password);
assert(!opened.legacy && opened.keyFormat === 'pkcs8' && opened.kdf === 'argon2id');
assert.deepEqual(Buffer.from(packPublicKey({ suiteId: 0x01, keyBytes: publicKeyBytes(0x01, importPkcs8(0x01, opened.secretKeyFile)) })),
  Buffer.from(generated.result.publicKeyFile));
const bytes = new Uint8Array([0, 1, 255]);
const fileSigned = await call('SIGN', { file: new Blob([bytes]), expectedDigestHex: textDigestHex(bytes),
  expectedFingerprintHex: generated.result.fingerprintHex });
assert(fileSigned.ok && nativeVerify(fileSigned.result.signatureFile, generated.result.publicKeyFile, bytes).valid);
assert.equal((await call('SIGN', { file: new Blob([bytes]), text: 'x', expectedDigestHex: textDigestHex(bytes),
  expectedFingerprintHex: generated.result.fingerprintHex })).code, 'E_INPUT_REQUIRED');

// Legacy keys the CLI still loads: PQSE 2 (PBKDF2) and plaintext PQSK.
const legacy = ml_dsa44.keygen();
const pqsk = packSecretKey({ suiteId: 0x01, keyBytes: legacy.secretKey });
const pqse1 = await encryptSecretKeyFile({ suiteId: 0x01, secretKeyFile: pqsk, passphrase: password, iterations: 100_000 });
for (const secretKeyFile of [pqsk, pqse1]) {
  const result = await call('UNLOCK', { secretKeyFile, passphrase: password });
  assert(result.ok && result.result.legacy && Buffer.from(result.result.publicKeyFile).includes(Buffer.from(legacy.publicKey)));
}
assert.equal((await call('UNLOCK', { secretKeyFile: pqse1.subarray(0, 60), passphrase: password })).ok, false);

const failed = await worker({ fault: 'verification' });
assert.equal((await failed('SELFTEST')).ok, false);
assert.equal((await failed('HASH_TEXT', { text: 'abc' })).ok, false);
assert.equal((await failed('VERIFY_FILE')).ok, false);
assert.equal((await failed('KEYGEN', { suiteId: 0x01, passphrase: password })).ok, false);
const signingFault = await worker({ fault: 'signing' });
assert.equal((await signingFault('KEYGEN', { suiteId: 0x01, passphrase: password })).code, 'E_INTERNAL');
assert.equal((await signingFault('UNLOCK', { secretKeyFile: pqsk })).code, 'E_INTERNAL', 'signing KAT failure did not latch');
assert((await signingFault('HASH_TEXT', { text: 'abc' })).ok, 'signing KAT failure must not disable verification');
console.log('Browser boundary: worker operations, CLI key/signature interoperability, reviewed-input binding and KAT fault latches PASS');
