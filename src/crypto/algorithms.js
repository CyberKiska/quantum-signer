import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_shake_128s,
  slh_dsa_shake_192s,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import { ErrorCode, createError } from './errors.js';
import { HashAlgId, SuiteId } from '../formats/containers.js';
import {
  assertCondition,
  validateBytes,
  validateHashAlgId,
  validateSuiteId,
} from './validate.js';
import { bytesToHexLower, hexToBytesStrict } from '../formats/encoding.js';

export const DEFAULT_SUITE_ID = SuiteId.ML_DSA_87;
export const DEFAULT_SLH_SUITE_ID = SuiteId.SLH_DSA_SHAKE_128S;
export const DEFAULT_HASH_ALG_ID = HashAlgId.SHA3_512;
export const DEFAULT_CTX = 'quantum-signer/mvp/v1';
export const QSIG_V2_DEFAULT_CTX = 'quantum-signer/v2';

const SUITE_REGISTRY = new Map([
  [
    SuiteId.ML_DSA_44,
    {
      id: SuiteId.ML_DSA_44,
      name: 'ML-DSA-44',
      family: 'ML-DSA',
      signer: ml_dsa44,
      defaultHedged: true,
    },
  ],
  [
    SuiteId.ML_DSA_65,
    {
      id: SuiteId.ML_DSA_65,
      name: 'ML-DSA-65',
      family: 'ML-DSA',
      signer: ml_dsa65,
      defaultHedged: true,
    },
  ],
  [
    SuiteId.ML_DSA_87,
    {
      id: SuiteId.ML_DSA_87,
      name: 'ML-DSA-87',
      family: 'ML-DSA',
      signer: ml_dsa87,
      defaultHedged: true,
    },
  ],
  [
    SuiteId.SLH_DSA_SHAKE_128S,
    {
      id: SuiteId.SLH_DSA_SHAKE_128S,
      name: 'SLH-DSA-SHAKE-128s',
      family: 'SLH-DSA',
      signer: slh_dsa_shake_128s,
      defaultHedged: true,
    },
  ],
  [
    SuiteId.SLH_DSA_SHAKE_192S,
    {
      id: SuiteId.SLH_DSA_SHAKE_192S,
      name: 'SLH-DSA-SHAKE-192s',
      family: 'SLH-DSA',
      signer: slh_dsa_shake_192s,
      defaultHedged: true,
    },
  ],
  [
    SuiteId.SLH_DSA_SHAKE_256S,
    {
      id: SuiteId.SLH_DSA_SHAKE_256S,
      name: 'SLH-DSA-SHAKE-256s',
      family: 'SLH-DSA',
      signer: slh_dsa_shake_256s,
      defaultHedged: true,
    },
  ],
]);

export function listSuites() {
  return Array.from(SUITE_REGISTRY.values()).map((entry) => ({
    id: entry.id,
    name: entry.name,
    family: entry.family,
    defaultHedged: entry.defaultHedged,
    lengths: {
      publicKey: entry.signer.lengths.publicKey,
      secretKey: entry.signer.lengths.secretKey,
      signature: entry.signer.lengths.signature,
    },
  }));
}

export function getSuite(suiteId) {
  validateSuiteId(suiteId);
  const suite = SUITE_REGISTRY.get(suiteId);
  if (!suite) {
    throw createError(ErrorCode.E_SUITE_UNSUPPORTED, { suiteId });
  }
  return suite;
}

export function assertKeyLength(suiteId, keyBytes, kind) {
  const suite = getSuite(suiteId);
  validateBytes(keyBytes, `${kind}Key`);
  const expected = kind === 'public' ? suite.signer.lengths.publicKey : suite.signer.lengths.secretKey;
  if (typeof expected === 'number') {
    assertCondition(keyBytes.length === expected, ErrorCode.E_FORMAT_LENGTH, {
      field: `${kind}KeyLength`,
      expected,
      actual: keyBytes.length,
      suiteId,
    });
  }
}

export function assertSignatureLength(suiteId, signature) {
  const suite = getSuite(suiteId);
  validateBytes(signature, 'signature');
  const expected = suite.signer.lengths.signature;
  if (typeof expected === 'number') {
    assertCondition(signature.length === expected, ErrorCode.E_FORMAT_LENGTH, {
      field: 'signatureLength',
      expected,
      actual: signature.length,
      suiteId,
    });
  }
}

export function generateKeypair(suiteId) {
  const suite = getSuite(suiteId);
  const keys = suite.signer.keygen();
  assertKeyLength(suiteId, keys.publicKey, 'public');
  assertKeyLength(suiteId, keys.secretKey, 'secret');
  return keys;
}

export function getPublicKeyFromSecret(suiteId, secretKey) {
  const suite = getSuite(suiteId);
  assertKeyLength(suiteId, secretKey, 'secret');
  const publicKey = suite.signer.getPublicKey(secretKey);
  assertKeyLength(suiteId, publicKey, 'public');
  return publicKey;
}

function normalizeContextBytes(contextBytes) {
  if (contextBytes === undefined || contextBytes === null) return undefined;
  validateBytes(contextBytes, 'contextBytes', 0);
  assertCondition(contextBytes.length <= 255, ErrorCode.E_FORMAT_LENGTH, {
    field: 'contextBytesLength',
    max: 255,
    actual: contextBytes.length,
  });
  return contextBytes;
}

export function signBytes({ suiteId, message, secretKey, hedged = true, contextBytes }) {
  const suite = getSuite(suiteId);
  validateBytes(message, 'message');
  assertKeyLength(suiteId, secretKey, 'secret');
  const context = normalizeContextBytes(contextBytes);

  const opts = {};
  if (context) opts.context = context;
  if (suite.family === 'ML-DSA' && hedged === false) {
    opts.extraEntropy = false;
  }

  const signature = suite.signer.sign(message, secretKey, opts);
  assertSignatureLength(suiteId, signature);
  return signature;
}

export function verifyBytes({ suiteId, message, signature, publicKey, contextBytes }) {
  const suite = getSuite(suiteId);
  validateBytes(message, 'message');
  assertSignatureLength(suiteId, signature);
  assertKeyLength(suiteId, publicKey, 'public');
  const context = normalizeContextBytes(contextBytes);
  const opts = context ? { context } : {};
  return suite.signer.verify(signature, message, publicKey, opts);
}

export async function hashFileSHA3512(file, { chunkSize = 4 * 1024 * 1024, onProgress } = {}) {
  if (!file || typeof file.size !== 'number' || typeof file.slice !== 'function') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file' });
  }

  const hasher = sha3_512.create();
  const total = file.size;

  if (total === 0) {
    if (typeof onProgress === 'function') onProgress(0, 0);
    return hasher.digest();
  }

  let offset = 0;
  while (offset < total) {
    const end = Math.min(offset + chunkSize, total);
    const chunk = file.slice(offset, end);
    const chunkBytes = new Uint8Array(await chunk.arrayBuffer());
    hasher.update(chunkBytes);
    offset = end;
    if (typeof onProgress === 'function') onProgress(offset, total);
  }

  return hasher.digest();
}

export function hashBytesSHA3512(bytes) {
  validateBytes(bytes, 'bytes', 0);
  return sha3_512(bytes);
}

export function hashHexToBytes(hashHex) {
  return hexToBytesStrict(hashHex);
}

export { bytesToHexLower };

export function computeFingerprintBytes(bytes) {
  validateBytes(bytes, 'bytes');
  return sha3_256(bytes);
}

export function computeFingerprint(bytes, size = 8) {
  validateBytes(bytes, 'bytes');
  const digest = computeFingerprintBytes(bytes);
  const take = Math.max(1, Math.min(size, digest.length));
  return bytesToHexLower(digest.subarray(0, take));
}

export function computeFingerprintHex(bytes) {
  return bytesToHexLower(computeFingerprintBytes(bytes));
}

export function ensureHashAlg(hashAlgId) {
  validateHashAlgId(hashAlgId);
}
