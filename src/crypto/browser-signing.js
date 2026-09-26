// Browser private-key operations; imported only by the signing worker.
// Pure ML-DSA / SLH-DSA (FIPS 204 Alg. 2, FIPS 205 Alg. 22) via the pinned noble
// library, because stable Web Crypto has no ML-DSA or SLH-DSA. Randomness for
// key generation and hedged signing comes from crypto.getRandomValues.
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_shake_128s, slh_dsa_shake_192s, slh_dsa_shake_256s } from '@noble/post-quantum/slh-dsa.js';
import { verifyBytes } from './browser-verification.js';
import { equalsBytes, wipeBytes } from './bytes.js';
import { ErrorCode, createError } from './errors.js';
import { decodePkcs8, encodePkcs8 } from './pkcs8.js';
import { SuiteId, assertKeyLength, getSuiteMetadata } from './suite-metadata.js';
import { utf8ToBytes } from '../formats/encoding.js';
import kat from './kat-vectors.json' with { type: 'json' };

const SIGNERS = new Map([
  [SuiteId.ML_DSA_44, ml_dsa44], [SuiteId.ML_DSA_65, ml_dsa65], [SuiteId.ML_DSA_87, ml_dsa87],
  [SuiteId.SLH_DSA_SHAKE_128S, slh_dsa_shake_128s], [SuiteId.SLH_DSA_SHAKE_192S, slh_dsa_shake_192s],
  [SuiteId.SLH_DSA_SHAKE_256S, slh_dsa_shake_256s],
]);
// Same dedicated contexts as the native signer: never valid as QSIG or X.509/CMS signatures.
const PCT_CONTEXT = utf8ToBytes('quantum-signer/pct/v1');
const PCT_MESSAGE = utf8ToBytes('quantum-signer/key-check/v1');
const KAT_CONTEXT = utf8ToBytes('quantum-signer/v2');
const KAT_MESSAGE = utf8ToBytes('quantum-signer/native-self-test/v1');

function signer(suiteId) {
  getSuiteMetadata(suiteId);
  return SIGNERS.get(suiteId);
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// Conditional self-test before the first private operation per suite (FIPS 140-3
// IG 10.3.A pattern), mirroring the native one: ML-DSA KeyGen from an ACVP seed
// must reproduce the ACVP public key, and a signature from the ACVP key must
// verify. Startup verification KATs run separately. Failure latches closed.
const selfTested = new Set();
let selfTestFailed = false;

export async function ensureSigningSelfTest(suiteId) {
  const impl = signer(suiteId);
  if (selfTestFailed) throw createError(ErrorCode.E_INTERNAL);
  if (selfTested.has(suiteId)) return;
  try {
    let keys;
    if (getSuiteMetadata(suiteId).family === 'ML-DSA') {
      const vector = kat.mlDsaKeyGen.find((entry) => entry.suiteId === suiteId);
      keys = impl.keygen(Uint8Array.from(vector.seedHex.match(/../gu), (b) => parseInt(b, 16)));
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', keys.publicKey));
      if (hex(digest) !== vector.publicKeySha256) throw new Error('keygen');
    } else {
      const secretHex = kat.slhDsaSecretKeys.find((entry) => entry.suiteId === suiteId).secretKeyHex;
      const secretKey = Uint8Array.from(secretHex.match(/../gu), (b) => parseInt(b, 16));
      keys = { secretKey, publicKey: secretKey.slice(secretKey.length / 2) };
    }
    const signature = impl.sign(KAT_MESSAGE, keys.secretKey, { context: KAT_CONTEXT });
    if (!verifyBytes({ suiteId, message: KAT_MESSAGE, signature, publicKey: keys.publicKey, contextBytes: KAT_CONTEXT })) {
      throw new Error('sign');
    }
    selfTested.add(suiteId);
  } catch {
    selfTestFailed = true;
    throw createError(ErrorCode.E_INTERNAL);
  }
}

export function signMessage({ suiteId, secretKey, publicKey, message, contextBytes }) {
  if (!selfTested.has(suiteId) || selfTestFailed) throw createError(ErrorCode.E_INTERNAL);
  // Hedged by default: noble mixes fresh randomness (FIPS 204 rnd / FIPS 205 opt_rand).
  const signature = signer(suiteId).sign(message, secretKey, { context: contextBytes });
  if (!verifyBytes({ suiteId, message, signature, publicKey, contextBytes })) {
    wipeBytes(signature);
    throw createError(ErrorCode.E_SIGN_SELF_VERIFY, { reason: 'primitive' });
  }
  return signature;
}

// Pairwise consistency test (FIPS 140-3 IG 10.3.A) on every generated or imported key.
async function checkedKey(suiteId, keys) {
  await ensureSigningSelfTest(suiteId);
  assertKeyLength(suiteId, keys.secretKey, 'secret');
  assertKeyLength(suiteId, keys.publicKey, 'public');
  try { wipeBytes(signMessage({ suiteId, ...keys, message: PCT_MESSAGE, contextBytes: PCT_CONTEXT })); }
  catch { wipeBytes(keys.secretKey); throw createError(ErrorCode.E_KEY_CONSISTENCY); }
  return { suiteId, secretKey: keys.secretKey, publicKey: keys.publicKey };
}

// Returns the active key plus its PKCS#8 encoding for PQSE 3 wrapping.
export async function generatePrivateKey(suiteId) {
  const impl = signer(suiteId);
  await ensureSigningSelfTest(suiteId);
  const seed = crypto.getRandomValues(new Uint8Array(impl.lengths.seed));
  try {
    const key = await checkedKey(suiteId, impl.keygen(seed));
    const mlDsa = getSuiteMetadata(suiteId).family === 'ML-DSA';
    return { key, pkcs8: encodePkcs8(suiteId, mlDsa ? seed : key.secretKey) };
  } finally { wipeBytes(seed); }
}

// format: 'pkcs8' (PQSE 2/3) or 'raw' (legacy PQSK expanded key).
export async function importPrivateKey(suiteId, bytes, format) {
  const impl = signer(suiteId);
  const { seed, expandedKey } = format === 'pkcs8' ? decodePkcs8(suiteId, bytes) : { expandedKey: bytes };
  let keys;
  if (seed) {
    keys = impl.keygen(seed);
    // RFC 9881 `both`: the expanded key must be the one the seed produces.
    if (expandedKey && !equalsBytes(keys.secretKey, expandedKey)) {
      wipeBytes(keys.secretKey);
      throw createError(ErrorCode.E_KEY_CONSISTENCY);
    }
  } else {
    assertKeyLength(suiteId, expandedKey, 'secret');
    const secretKey = Uint8Array.from(expandedKey);
    keys = { secretKey, publicKey: impl.getPublicKey(secretKey) };
  }
  return checkedKey(suiteId, keys);
}
