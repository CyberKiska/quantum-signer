// RFC 5958 OneAsymmetricKey (version 0) for ML-DSA (RFC 9881) and SLH-DSA
// (RFC 9909), matching what OpenSSL writes and reads. Strict X.690 DER: definite
// minimal lengths, absent AlgorithmIdentifier parameters, no attributes or
// publicKey field, no trailing bytes.
import { ErrorCode, createError } from './errors.js';
import { SuiteId, getSuiteMetadata } from './suite-metadata.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit } from './policy.js';

// id-ml-dsa-* and id-slh-dsa-shake-*s arcs under 2.16.840.1.101.3.4.3.
const OID_ARC = new Map([
  [SuiteId.ML_DSA_44, 17], [SuiteId.ML_DSA_65, 18], [SuiteId.ML_DSA_87, 19],
  [SuiteId.SLH_DSA_SHAKE_128S, 26], [SuiteId.SLH_DSA_SHAKE_192S, 28], [SuiteId.SLH_DSA_SHAKE_256S, 30],
]);
const ML_DSA_SEED_BYTES = 32;

const fail = (reason) => { throw createError(ErrorCode.E_KEY_FORMAT, { reason }); };

function algorithmIdentifier(suiteId) {
  getSuiteMetadata(suiteId);
  return Uint8Array.of(0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, OID_ARC.get(suiteId));
}

function der(tag, ...parts) {
  const n = parts.reduce((sum, part) => sum + part.length, 0);
  if (n > 0xffff) fail('too_long');
  const header = n < 0x80 ? [tag, n] : n < 0x100 ? [tag, 0x81, n] : [tag, 0x82, n >>> 8, n & 0xff];
  const out = new Uint8Array(header.length + n);
  out.set(header);
  let offset = header.length;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function readTlv(bytes, offset, tag) {
  if (bytes[offset] !== tag || offset + 1 >= bytes.length) fail('tag');
  let start = offset + 2;
  let length = bytes[offset + 1];
  if (length >= 0x80) {
    const count = length & 0x7f;
    if (count < 1 || count > 2 || start + count > bytes.length || bytes[start] === 0) fail('length');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[start++];
    if (length < 0x80) fail('length');
  }
  if (start + length > bytes.length) fail('length');
  return { value: bytes.subarray(start, start + length), end: start + length };
}

const sameBytes = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);

// ML-DSA keys are written seed-only (RFC 9881 `seed` choice); SLH-DSA keys as
// the raw 4n-byte private key.
export function encodePkcs8(suiteId, privateKey) {
  const mlDsa = getSuiteMetadata(suiteId).family === 'ML-DSA';
  const inner = mlDsa ? der(0x80, privateKey) : privateKey;
  try { return der(0x30, Uint8Array.of(0x02, 0x01, 0x00), algorithmIdentifier(suiteId), der(0x04, inner)); }
  finally { if (mlDsa) inner.fill(0); }
}

// Returns views into `bytes`: { seed?, expandedKey? } (SLH-DSA: expandedKey only).
export function decodePkcs8(suiteId, bytes) {
  assertBytesLimit(bytes, MAX_KEY_FILE_BYTES, 'pkcs8');
  const { family, lengths } = getSuiteMetadata(suiteId);
  const outer = readTlv(bytes, 0, 0x30);
  if (outer.end !== bytes.length) fail('trailing_data');
  const version = readTlv(bytes, outer.end - outer.value.length, 0x02);
  if (!sameBytes(version.value, [0])) fail('version');
  const algorithm = readTlv(bytes, version.end, 0x30);
  if (!sameBytes(bytes.subarray(version.end, algorithm.end), algorithmIdentifier(suiteId))) fail('algorithm');
  const privateKey = readTlv(bytes, algorithm.end, 0x04);
  if (privateKey.end !== outer.end) fail('attributes');
  const key = privateKey.value;
  if (family === 'SLH-DSA') {
    if (key.length !== lengths.secretKey) fail('private_key_length');
    return { expandedKey: key };
  }
  // ML-DSA-PrivateKey ::= CHOICE { seed [0], expandedKey OCTET STRING, both SEQUENCE }
  let seed;
  let expandedKey;
  let end;
  if (key[0] === 0x80) ({ value: seed, end } = readTlv(key, 0, 0x80));
  else if (key[0] === 0x04) ({ value: expandedKey, end } = readTlv(key, 0, 0x04));
  else {
    const both = readTlv(key, 0, 0x30);
    const seedTlv = readTlv(key, both.end - both.value.length, 0x04);
    ({ value: expandedKey, end } = readTlv(key, seedTlv.end, 0x04));
    if (end !== both.end) fail('private_key');
    seed = seedTlv.value;
    end = both.end;
  }
  if (end !== key.length || (seed && seed.length !== ML_DSA_SEED_BYTES) ||
      (expandedKey && expandedKey.length !== lengths.secretKey)) fail('private_key_length');
  return { seed, expandedKey };
}
