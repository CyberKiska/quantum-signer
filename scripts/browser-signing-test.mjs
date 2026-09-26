// Browser signing adapter and PKCS#8 codec against OpenSSL, for all suites.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { decodePkcs8 } from '../src/crypto/pkcs8.js';
import { generatePrivateKey, importPrivateKey, signMessage } from '../src/crypto/browser-signing.js';
import { createDetachedSignature } from '../src/crypto/detached-signature.js';
import { finalizePayloadVerification } from '../src/crypto/verify-policy.js';
import { generateNativeKey, importLegacySecretKey, importPkcs8, publicKeyBytes, verifyBytes } from '../src/native/crypto.js';
import { packPublicKey, unpackSignatureV2 } from '../src/formats/containers.js';

const rejects = (promise, code) => assert.rejects(promise, (error) => error.code === code, code);
const der = (tag, bytes) => Buffer.concat([Buffer.from(bytes.length < 128 ? [tag, bytes.length]
  : bytes.length < 256 ? [tag, 0x81, bytes.length] : [tag, 0x82, bytes.length >>> 8, bytes.length & 255]), bytes]);
const contextBytes = Buffer.from('quantum-signer/v2');
const message = Buffer.from('browser signing interoperability');
const digest = createHash('sha3-512').update(message).digest();
// JavaScript SLH-DSA signing takes seconds; quick runs cover one SLH-DSA suite.
const suites = listSuites().filter((s) => process.env.FULL_SELFTEST === '1' || s.family === 'ML-DSA' || s.id === 0x11);

for (const suite of suites) {
  const mlDsa = suite.family === 'ML-DSA';
  // OpenSSL-written PKCS#8 -> browser.
  const nativeKey = generateNativeKey(suite.id);
  const nativePkcs8 = nativeKey.export({ type: 'pkcs8', format: 'der' });
  const imported = await importPrivateKey(suite.id, nativePkcs8, 'pkcs8');
  assert.deepEqual(Buffer.from(imported.publicKey), publicKeyBytes(suite.id, nativeKey));

  // Browser-written PKCS#8 -> OpenSSL; shared QSIG core with the browser signer.
  const { key, pkcs8 } = await generatePrivateKey(suite.id);
  assert.deepEqual(publicKeyBytes(suite.id, importPkcs8(suite.id, pkcs8)), Buffer.from(key.publicKey));
  const qsig = createDetachedSignature({ suiteId: suite.id, publicKey: key.publicKey, payloadDigest: digest,
    sign: (tbs, ctx) => signMessage({ ...key, message: tbs, contextBytes: ctx }) });
  const verified = finalizePayloadVerification(unpackSignatureV2(qsig), packPublicKey({ suiteId: suite.id, keyBytes: key.publicKey }),
    { computedHashHex: digest.toString('hex') });
  assert(verified.valid && verified.trusted, `${suite.name}: OpenSSL rejected browser QSIG`);

  // Legacy raw expanded key (PQSK) and, for ML-DSA, the RFC 9881 expandedKey and both forms.
  if (mlDsa) {
    const raw = await importPrivateKey(suite.id, key.secretKey, 'raw');
    assert.deepEqual(raw.publicKey, key.publicKey);
    const signature = signMessage({ ...raw, message, contextBytes });
    assert(verifyBytes({ suiteId: suite.id, publicKey: raw.publicKey, message, contextBytes, signature }));
    const seed = decodePkcs8(suite.id, pkcs8).seed;
    const wrap = (inner) => der(0x30, Buffer.concat([pkcs8.subarray(2, 18), der(0x04, inner)]));
    const expandedForm = wrap(der(0x04, key.secretKey));
    assert.deepEqual(publicKeyBytes(suite.id, importLegacySecretKey(suite.id, key.secretKey)), Buffer.from(key.publicKey));
    assert.deepEqual((await importPrivateKey(suite.id, expandedForm, 'pkcs8')).publicKey, key.publicKey);
    const both = (expanded) => wrap(der(0x30, Buffer.concat([der(0x04, seed), der(0x04, expanded)])));
    assert.deepEqual((await importPrivateKey(suite.id, both(key.secretKey), 'pkcs8')).publicKey, key.publicKey);
    const inconsistent = Buffer.from(key.secretKey); inconsistent[100] ^= 1;
    await rejects(importPrivateKey(suite.id, both(inconsistent), 'pkcs8'), 'E_KEY_CONSISTENCY');
  } else {
    const broken = Uint8Array.from(key.secretKey); broken[broken.length - 1] ^= 1; // PK.root
    await rejects(importPrivateKey(suite.id, broken, 'raw'), 'E_KEY_CONSISTENCY');
  }

  // Strict DER: every structural deviation fails closed.
  const other = listSuites().find((s) => s.family === suite.family && s.id !== suite.id).id;
  const h = pkcs8[1] & 0x80 ? 2 + (pkcs8[1] & 0x7f) : 2; // outer header length
  const body = pkcs8.subarray(h, h + 16); // version || AlgorithmIdentifier
  const inner = pkcs8.subarray(h + 16);
  const malformed = {
    trailing: Buffer.concat([pkcs8, Buffer.of(0)]),
    truncated: pkcs8.subarray(0, pkcs8.length - 1),
    nonMinimalLength: h === 2 ? Buffer.concat([Buffer.of(0x30, 0x81), pkcs8.subarray(1)]) : null,
    version1: Buffer.from(pkcs8).fill(1, h + 2, h + 3),
    parameters: der(0x30, Buffer.concat([Buffer.of(2, 1, 0), der(0x30, Buffer.concat([pkcs8.subarray(h + 5, h + 16), Buffer.of(5, 0)])), inner])),
    attributes: der(0x30, Buffer.concat([body, inner, Buffer.of(0xa0, 0)])),
    publicKeyField: der(0x30, Buffer.concat([body, inner, Buffer.of(0x81, 1, 0)])),
  };
  for (const [name, bytes] of Object.entries(malformed)) {
    if (bytes) await rejects(importPrivateKey(suite.id, bytes, 'pkcs8'), 'E_KEY_FORMAT').catch(() => assert.fail(`${suite.name}: ${name}`));
  }
  await rejects(importPrivateKey(other, pkcs8, 'pkcs8'), 'E_KEY_FORMAT');
  await rejects(importPrivateKey(suite.id, nativePkcs8.subarray(0, 20), 'raw'), 'E_FORMAT_LENGTH');
  console.log(`  ${suite.name}: browser PKCS#8, pairwise checks and OpenSSL interoperability PASS`);
}
console.log('Browser signing adapter: PASS');
