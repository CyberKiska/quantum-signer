import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { getSuiteMetadata, assertKeyLength, listSuites, verificationInputsWellFormed } from '../crypto/suite-metadata.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit } from '../crypto/policy.js';
import { runVerificationSelfTest } from '../crypto/verification-selftest.js';
import { sha3_512 } from '../crypto/native-hashes.js';
import kat from './kat-vectors.json' with { type: 'json' };

// OpenSSL 3.5.0 is the first release implementing FIPS 204 ML-DSA and FIPS 205
// SLH-DSA with the context-string API. The startup self-tests below are the
// actual conformance gate; this floor rejects providers that cannot pass them.
export const MIN_OPENSSL_VERSION = '3.5.0';

export function versionAtLeast(actual, minimum) {
  const parse = (value) => (String(value).match(/^(\d+)\.(\d+)\.(\d+)/u) || []).slice(1).map(Number);
  const a = parse(actual);
  const m = parse(minimum);
  if (a.length !== 3) return false;
  for (let i = 0; i < 3; i++) if (a[i] !== m[i]) return a[i] > m[i];
  return true;
}

export function assertNativeRuntime() {
  if (Number(process.versions.node.split('.')[0]) < 26) {
    throw new Error('Local signing requires Node.js 26 or newer with ML-DSA and SLH-DSA support.');
  }
  if (!versionAtLeast(process.versions.openssl, MIN_OPENSSL_VERSION)) {
    throw new Error(`Local signing requires OpenSSL ${MIN_OPENSSL_VERSION} or newer; Node reports ${process.versions.openssl || 'none'}.`);
  }
}

function nativeName(suiteId) { return getSuiteMetadata(suiteId).name.toLowerCase(); }

export function assertNativeKey(suiteId, key, type) {
  if (key?.type !== type || key.asymmetricKeyType !== nativeName(suiteId)) {
    throw new Error('Native key type does not match the selected suite.');
  }
}

export function publicKeyBytes(suiteId, key) {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  assertNativeKey(suiteId, publicKey, 'public');
  const bytes = publicKey.export({ format: 'raw-public' });
  assertKeyLength(suiteId, bytes, 'public');
  return bytes;
}

export function importPublicKey(suiteId, bytes) {
  assertKeyLength(suiteId, bytes, 'public');
  return createPublicKey({ key: bytes, format: 'raw-public', asymmetricKeyType: nativeName(suiteId) });
}

// DER is used only as the standard OpenSSL import wrapper for legacy expanded
// ML-DSA keys. New keys stay in native KeyObjects and are stored as PKCS#8.
function der(tag, bytes) {
  const n = bytes.length;
  if (n > 65535) throw new Error('DER input too long');
  const length = n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >>> 8, n & 255];
  return Buffer.concat([Buffer.from([tag, ...length]), bytes]);
}

export function importLegacySecretKey(suiteId, bytes) {
  assertKeyLength(suiteId, bytes, 'secret');
  if (getSuiteMetadata(suiteId).family === 'SLH-DSA') {
    return createPrivateKey({ key: bytes, format: 'raw-private', asymmetricKeyType: nativeName(suiteId) });
  }
  // RFC 9881: id-ml-dsa-{44,65,87}, absent AlgorithmIdentifier parameters;
  // expandedKey OCTET STRING inside the PKCS#8 privateKey OCTET STRING.
  const algorithm = der(0x30, der(6, Buffer.from([0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 16 + suiteId])));
  const expanded = der(4, bytes);
  const privateOctets = der(4, expanded);
  const body = Buffer.concat([Buffer.from([2, 1, 0]), algorithm, privateOctets]);
  const encoded = der(0x30, body);
  try { return createPrivateKey({ key: encoded, format: 'der', type: 'pkcs8' }); }
  finally { expanded.fill(0); privateOctets.fill(0); body.fill(0); encoded.fill(0); }
}

// RFC 9881 seed-only ML-DSA private key: PKCS#8 privateKey = [0] IMPLICIT OCTET
// STRING (SIZE (32)). FIPS 204 ML-DSA.KeyGen_internal expands it deterministically.
export function importMlDsaSeed(suiteId, seed) {
  if (getSuiteMetadata(suiteId).family !== 'ML-DSA' || !(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TypeError('ML-DSA seed import requires an ML-DSA suite and a 32-byte seed.');
  }
  const algorithm = der(0x30, der(6, Buffer.from([0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 16 + suiteId])));
  const privateOctets = der(4, der(0x80, seed));
  const encoded = der(0x30, Buffer.concat([Buffer.from([2, 1, 0]), algorithm, privateOctets]));
  try { return importPkcs8(suiteId, encoded); }
  finally { privateOctets.fill(0); encoded.fill(0); }
}

export function importPkcs8(suiteId, bytes) {
  assertBytesLimit(bytes, MAX_KEY_FILE_BYTES, 'PKCS8');
  // OpenSSL may accept a valid DER object followed by ignored bytes. Require
  // one complete, minimally length-encoded outer SEQUENCE before decoding.
  if (bytes[0] !== 0x30 || bytes.length < 2) throw new Error('Invalid PKCS#8 sequence.');
  let offset = 2;
  let length = bytes[1];
  if (length >= 128) {
    const count = length & 127;
    if (count < 1 || count > 2 || bytes.length < 2 + count || bytes[2] === 0) throw new Error('Invalid DER length.');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
    if (length < 128) throw new Error('Noncanonical DER length.');
  }
  if (offset + length !== bytes.length) throw new Error('Truncated or trailing PKCS#8 data.');
  const key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' });
  assertNativeKey(suiteId, key, 'private');
  return key;
}

export function signBytesNative({ suiteId, message, privateKey, contextBytes = new Uint8Array() }) {
  ensureNativeSelfTest(suiteId, { signing: true });
  assertNativeKey(suiteId, privateKey, 'private');
  if (!(message instanceof Uint8Array) || !(contextBytes instanceof Uint8Array) || contextBytes.length > 255) {
    throw new TypeError('Signing requires message bytes and a context of at most 255 bytes.');
  }
  // Pure FIPS 204/205: the provider adds the context prefix exactly once.
  // Default OpenSSL signing uses its CSPRNG; there is no deterministic fallback.
  const signature = sign(null, message, { key: privateKey, context: contextBytes });
  if (!verifyBytes({ suiteId, message, signature, publicKey: publicKeyBytes(suiteId, privateKey), contextBytes })) {
    signature.fill(0);
    throw new Error('Native signature self-verification failed.');
  }
  return signature;
}

function rawVerify({ contextBytes = new Uint8Array(), ...args }) {
  if (!verificationInputsWellFormed({ ...args, contextBytes })) return false;
  const { suiteId, message, signature, publicKey } = args;
  try { return verify(null, message, { key: importPublicKey(suiteId, publicKey), context: contextBytes }, signature); }
  catch { return false; }
}

export function verifyBytes({ contextBytes = new Uint8Array(), ...args }) {
  if (!verificationInputsWellFormed({ ...args, contextBytes })) return false;
  ensureNativeSelfTest(args.suiteId);
  return rawVerify({ ...args, contextBytes });
}

// Conditional self-tests before the first use of each suite in this process
// (FIPS 140-3 IG 10.3.A pattern). Pairwise tests and signature self-checks only
// prove the provider agrees with itself; these compare it with NIST ACVP data:
//  - SHA3-256/512 KATs (FIPS 202 'abc' examples);
//  - pure-interface verification of an ACVP-derived signature, plus wrong
//    context, wrong message and damaged-signature rejections;
//  - ML-DSA: FIPS 204 KeyGen from an ACVP seed must reproduce the ACVP public key;
//  - before private operations, a signature from the ACVP key must verify
//    against the ACVP public key (SLH-DSA: exercises the full hypertree).
// Any failure latches every native operation closed for the process.
const selfTested = new Map();
let selfTestFailed = false;
const SHA3_ABC = {
  'sha3-256': '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
  'sha3-512': 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
};
const SELF_TEST_MESSAGE = Buffer.from('quantum-signer/native-self-test/v1');

function katKey(suiteId) {
  const suite = getSuiteMetadata(suiteId);
  if (suite.family === 'ML-DSA') {
    const vector = kat.mlDsaKeyGen.find((entry) => entry.suiteId === suiteId);
    const key = importMlDsaSeed(suiteId, Buffer.from(vector.seedHex, 'hex'));
    const publicKey = publicKeyBytes(suiteId, key);
    if (createHash('sha256').update(publicKey).digest('hex') !== vector.publicKeySha256) throw new Error('ML-DSA KeyGen KAT');
    return { key, publicKey };
  }
  const secretKey = Buffer.from(kat.slhDsaSecretKeys.find((entry) => entry.suiteId === suiteId).secretKeyHex, 'hex');
  const key = createPrivateKey({ key: secretKey, format: 'raw-private', asymmetricKeyType: nativeName(suiteId) });
  const publicKey = secretKey.subarray(suite.lengths.secretKey / 2);
  if (!Buffer.from(publicKeyBytes(suiteId, key)).equals(publicKey)) throw new Error('SLH-DSA key KAT');
  return { key, publicKey };
}

export function ensureNativeSelfTest(suiteId, { signing = false } = {}) {
  getSuiteMetadata(suiteId);
  if (selfTestFailed) throw new Error('Native cryptographic self-test failed earlier in this process; refusing to operate.');
  const level = selfTested.get(suiteId);
  if (level === 'sign' || (level === 'verify' && !signing)) return;
  try {
    assertNativeRuntime();
    for (const [name, expected] of Object.entries(SHA3_ABC)) {
      if (createHash(name).update('abc').digest('hex') !== expected) throw new Error(`${name} KAT`);
    }
    const report = runVerificationSelfTest({ verifyBytes: rawVerify, sha3_512, suiteIds: [suiteId] });
    if (!report.ok) throw new Error('verification KAT');
    const { key, publicKey } = katKey(suiteId);
    if (signing) {
      const contextBytes = Buffer.from('quantum-signer/v2');
      const signature = sign(null, SELF_TEST_MESSAGE, { key, context: contextBytes });
      if (!rawVerify({ suiteId, message: SELF_TEST_MESSAGE, signature, publicKey, contextBytes })) throw new Error('signing KAT');
    }
    selfTested.set(suiteId, signing ? 'sign' : 'verify');
  } catch (error) {
    selfTestFailed = true;
    throw new Error(`Native cryptographic self-test failed (${error.message}); the OpenSSL provider is unavailable or non-conformant.`);
  }
}

export function runAllNativeSelfTests() {
  for (const { id } of listSuites()) ensureNativeSelfTest(id, { signing: true });
}

export function checkPrivateKey(suiteId, privateKey) {
  // Full pairwise test, including legacy imports whose embedded public component
  // alone does not establish consistency of the secret signing material.
  signBytesNative({ suiteId, privateKey, message: Buffer.from('quantum-signer/key-check/v1') }).fill(0);
}

export function generateNativeKey(suiteId) {
  ensureNativeSelfTest(suiteId, { signing: true });
  const { privateKey } = generateKeyPairSync(nativeName(suiteId));
  checkPrivateKey(suiteId, privateKey);
  return privateKey;
}
