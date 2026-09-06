import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { MAX_TEXT_INPUT_BYTES } from '../src/crypto/policy.js';
import { generateNativeKey, publicKeyBytes } from '../src/native/crypto.js';
import { createDetachedSignature } from '../src/native/signing.js';
import { packPublicKey } from '../src/formats/containers.js';

async function worker({ corruptKat = false } = {}) {
  const built = await build({ entryPoints: ['src/worker.js'], bundle: true, platform: 'browser', format: 'iife',
    write: false, logLevel: 'silent', plugins: corruptKat ? [{ name: 'fault-injection', setup(builder) {
      builder.onLoad({ filter: /verification-vectors\.json$/ }, async ({ path }) => {
        const vectors = JSON.parse(await readFile(path, 'utf8'));
        const bad = Buffer.from(vectors.vectors[0].signatureBase64, 'base64'); bad[0] ^= 1;
        vectors.vectors[0].signatureBase64 = bad.toString('base64');
        return { loader: 'json', contents: JSON.stringify(vectors) };
      });
    } }] : [] });
  const messages = [];
  const surface = { self: {}, postMessage: m => messages.push(m), TextEncoder, TextDecoder, Blob,
    Uint8Array, Uint16Array, Uint32Array, Int32Array, ArrayBuffer, DataView, BigUint64Array, atob, btoa,
    // Verification must not request randomness or have access to private sessions.
    crypto: { getRandomValues() { throw new Error('Unexpected browser RNG use'); } } };
  vm.runInNewContext(built.outputFiles[0].text, surface);
  let seq = 0;
  return async (type, payload = {}, id = ++seq) => {
    messages.length = 0;
    await surface.self.onmessage({ data: { id, type, payload } });
    return messages.findLast(m => m.type === 'RESULT' || m.type === 'ERROR');
  };
}
const call = await worker();
assert.equal((await call('SELFTEST')).result.ok, true);
for (const type of ['KEYGEN', 'IMPORT_SECRET', 'SIGN', 'EXPORT_SECRET', 'AUTHORIZE_SECRET_EXPORT', 'CLEAR_SECRET_SESSION', 'constructor', 'toString', '__proto__']) {
  assert.equal((await call(type)).ok, false, `Exposed forbidden worker operation ${type}`);
}
for (const id of [0, -1, Infinity, NaN, {}, '', 'a'.repeat(129)]) assert.equal((await call('HASH_TEXT', { text: 'abc' }, id)).ok, false);
assert.equal((await call('HASH_TEXT', { text: 'a'.repeat(MAX_TEXT_INPUT_BYTES + 1) })).code, 'E_INPUT_TOO_LARGE');
assert.equal((await call('HASH_TEXT', { text: '\ud800' })).code, 'E_TEXT_ENCODING');
const payload = new Uint8Array([0, 1, 255, 128]);
const digest = createHash('sha3-512').update(payload).digest();
for (const suite of listSuites()) {
  const key = generateNativeKey(suite.id);
  const sigFile = createDetachedSignature(suite.id, key, digest);
  const publicKeyFile = packPublicKey({ suiteId: suite.id, keyBytes: publicKeyBytes(suite.id, key) });
  const params = { file: new Blob([payload]), sigFile, publicKeyFile };
  const valid = await call('VERIFY_FILE', params);
  assert(valid.ok && valid.result.valid && valid.result.trusted, suite.name);
  const embedded = await call('VERIFY_FILE', { ...params, publicKeyFile: null });
  assert(embedded.result.valid && !embedded.result.trusted);
  const wrong = await call('VERIFY_FILE', { ...params, file: new Blob(['wrong']) });
  assert(!wrong.result.valid && !wrong.result.trusted);
  assert.equal((await call('VERIFY_FILE', { ...params, publicKeyFile: {} })).ok, false);
}
const failed = await worker({ corruptKat: true });
assert.equal((await failed('SELFTEST')).ok, false);
assert.equal((await failed('HASH_TEXT', { text: 'abc' })).ok, false);
assert.equal((await failed('VERIFY_FILE')).ok, false);
console.log('Browser boundary: public-only operations, all-suite containers, invalid requests and startup fault latch PASS');
