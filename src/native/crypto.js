import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { getSuiteMetadata, assertKeyLength } from '../crypto/suite-metadata.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit } from '../crypto/policy.js';

export function assertNativeRuntime() {
  if (Number(process.versions.node.split('.')[0]) < 26) {
    throw new Error('Local signing requires Node.js 26 or newer with ML-DSA and SLH-DSA support.');
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

export function importPkcs8(suiteId, bytes) {
  assertBytesLimit(bytes, MAX_KEY_FILE_BYTES, 'PKCS8');
  const key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' });
  assertNativeKey(suiteId, key, 'private');
  return key;
}

export function signBytesNative({ suiteId, message, privateKey, contextBytes = new Uint8Array() }) {
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

export function verifyBytes({ suiteId, signatureProfileId = 1, message, signature, publicKey, contextBytes = new Uint8Array() }) {
  const suite = getSuiteMetadata(suiteId);
  if (signatureProfileId !== 1) throw new Error('Unsupported signature profile.');
  if (!(message instanceof Uint8Array)) throw new TypeError('Message must be bytes.');
  if (!(signature instanceof Uint8Array) || signature.length !== suite.lengths.signature ||
      !(publicKey instanceof Uint8Array) || publicKey.length !== suite.lengths.publicKey ||
      !(contextBytes instanceof Uint8Array) || contextBytes.length > 255) return false;
  try { return verify(null, message, { key: importPublicKey(suiteId, publicKey), context: contextBytes }, signature); }
  catch { return false; }
}

export function checkPrivateKey(suiteId, privateKey) {
  // Full pairwise test, including legacy imports whose embedded public component
  // alone does not establish consistency of the secret signing material.
  signBytesNative({ suiteId, privateKey, message: Buffer.from('quantum-signer/key-check/v1') }).fill(0);
}

export function generateNativeKey(suiteId) {
  assertNativeRuntime();
  const { privateKey } = generateKeyPairSync(nativeName(suiteId));
  checkPrivateKey(suiteId, privateKey);
  return privateKey;
}
