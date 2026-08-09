import { sha3_512 } from '@noble/hashes/sha3.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_shake_128s,
  slh_dsa_shake_192s,
  slh_dsa_shake_256s,
} from '@noble/post-quantum/slh-dsa.js';
import { ErrorCode, createError } from './errors.js';
import { wipeBytes } from './bytes.js';
import {
  DEFAULT_HASH_CHUNK_SIZE,
  MAX_CONTEXT_BYTES,
  MAX_PAYLOAD_FILE_BYTES,
  assertFileSizeLimit,
  normalizeChunkSize,
} from './policy.js';
import {
  HashAlgId,
  QSIG_V2_CONTEXT,
  SignatureProfileId,
  buildSignedMessageV2,
} from '../formats/containers.js';
import {
  assertCondition,
  validateBytes,
  validateHashAlgId,
  validateSuiteId,
} from './validate.js';
import { bytesToHexLower, hexToBytesStrict } from '../formats/encoding.js';
import {
  DEFAULT_SLH_SUITE_ID,
  DEFAULT_SUITE_ID,
  SuiteId,
  assertKeyLength as assertMetadataKeyLength,
  getSuiteWireLengths,
} from './suite-metadata.js';

export { DEFAULT_SLH_SUITE_ID, DEFAULT_SUITE_ID };
export const DEFAULT_HASH_ALG_ID = HashAlgId.SHA3_512;
export const QSIG_DEFAULT_CTX = QSIG_V2_CONTEXT;

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

for (const [suiteId, entry] of SUITE_REGISTRY) {
  const wire = getSuiteWireLengths(suiteId);
  if (
    !wire ||
    entry.signer.lengths.publicKey !== wire.publicKey ||
    entry.signer.lengths.secretKey !== wire.secretKey ||
    entry.signer.lengths.signature !== wire.signature
  ) {
    throw createError(ErrorCode.E_INTERNAL, { reason: 'suite_wire_length_drift', suiteId });
  }
}

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

export function getDefaultSignatureProfileId(suiteId) {
  getSuite(suiteId);
  return SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2;
}

function assertSignatureProfileCompatible(suite, signatureProfileId) {
  const expectedProfileId = SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2;

  assertCondition(signatureProfileId === expectedProfileId, ErrorCode.E_FORMAT_VERSION, {
    field: 'signatureProfileId',
    suiteId: suite.id,
    signatureProfileId,
    expectedProfileId,
  });
}

export function assertKeyLength(suiteId, keyBytes, kind) {
  getSuite(suiteId);
  assertMetadataKeyLength(suiteId, keyBytes, kind);
}

export function assertSignatureLength(suiteId, signature) {
  const suite = getSuite(suiteId);
  validateBytes(signature, 'signature');
  const expected = suite.signer.lengths.signature;
  if (!Number.isInteger(expected) || expected < 0) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, {
      field: 'signatureLengthExpected',
      expected,
      suiteId,
      reason: 'invalid_expected_length',
    });
  }
  assertCondition(signature.length === expected, ErrorCode.E_FORMAT_LENGTH, {
    field: 'signatureLength',
    expected,
    actual: signature.length,
    suiteId,
  });
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
  assertCondition(contextBytes.length <= MAX_CONTEXT_BYTES, ErrorCode.E_FORMAT_LENGTH, {
    field: 'contextBytesLength',
    max: MAX_CONTEXT_BYTES,
    actual: contextBytes.length,
  });
  return contextBytes;
}

export function signBytes({
  suiteId,
  signatureProfileId = getDefaultSignatureProfileId(suiteId),
  message,
  secretKey,
  hedged = true,
  contextBytes,
}) {
  const suite = getSuite(suiteId);
  validateBytes(message, 'message');
  assertKeyLength(suiteId, secretKey, 'secret');
  const context = normalizeContextBytes(contextBytes);
  assertSignatureProfileCompatible(suite, signatureProfileId);
  const signedMessage = buildSignedMessageV2({
    signatureProfileId,
    tbs: message,
    ctxBytes: context,
  });

  const opts = {};
  if (signatureProfileId === SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2 && context) {
    opts.context = context;
  }
  if ((suite.family === 'ML-DSA' || suite.family === 'SLH-DSA') && hedged === false) {
    opts.extraEntropy = false;
  }

  const signature = suite.signer.sign(signedMessage, secretKey, opts);
  assertSignatureLength(suiteId, signature);
  return signature;
}

export function signBytesVerified({ publicKey, ...signOptions }) {
  assertKeyLength(signOptions.suiteId, publicKey, 'public');
  const signature = signBytes(signOptions);
  try {
    const valid = verifyBytes({
      suiteId: signOptions.suiteId,
      signatureProfileId: signOptions.signatureProfileId,
      message: signOptions.message,
      signature,
      publicKey,
      contextBytes: signOptions.contextBytes,
    });
    if (!valid) {
      throw createError(ErrorCode.E_SIGN_SELF_VERIFY, {
        reason: 'post_sign_verification_failed',
        suiteId: signOptions.suiteId,
      });
    }
    return signature;
  } catch (err) {
    wipeBytes(signature);
    throw err;
  }
}

export function verifyBytes({
  suiteId,
  signatureProfileId = getDefaultSignatureProfileId(suiteId),
  message,
  signature,
  publicKey,
  contextBytes,
}) {
  const suite = getSuite(suiteId);
  validateBytes(message, 'message');
  assertSignatureProfileCompatible(suite, signatureProfileId);

  // Signature, public-key, and context bytes are attacker-controlled during
  // verification. Keep the verification surface total for malformed values:
  // invalid encodings and lengths are an invalid signature, not an exceptional
  // application state. Unsupported suites/profiles still fail above.
  if (!(signature instanceof Uint8Array) || signature.length !== suite.signer.lengths.signature) {
    return false;
  }
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== suite.signer.lengths.publicKey) {
    return false;
  }

  let context;
  if (contextBytes !== undefined && contextBytes !== null) {
    if (!(contextBytes instanceof Uint8Array) || contextBytes.length > MAX_CONTEXT_BYTES) {
      return false;
    }
    context = contextBytes;
  }
  const signedMessage = buildSignedMessageV2({
    signatureProfileId,
    tbs: message,
    ctxBytes: context,
  });
  const opts =
    signatureProfileId === SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2 && context
      ? { context }
      : {};
  try {
    return suite.signer.verify(signature, signedMessage, publicKey, opts) === true;
  } catch (err) {
    if (err instanceof RangeError || err instanceof TypeError) return false;
    throw err;
  }
}

export async function hashFileSHA3512(file, { chunkSize = DEFAULT_HASH_CHUNK_SIZE, onProgress } = {}) {
  if (!file || typeof file.size !== 'number' || typeof file.slice !== 'function') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file' });
  }
  assertFileSizeLimit(file, MAX_PAYLOAD_FILE_BYTES);
  const effectiveChunkSize = normalizeChunkSize(chunkSize, DEFAULT_HASH_CHUNK_SIZE);

  const hasher = sha3_512.create();
  const total = file.size;

  if (total === 0) {
    if (typeof onProgress === 'function') onProgress(0, 0);
    return hasher.digest();
  }

  let offset = 0;
  while (offset < total) {
    const end = Math.min(offset + effectiveChunkSize, total);
    const chunk = file.slice(offset, end);
    const chunkBytes = new Uint8Array(await chunk.arrayBuffer());
    try {
      hasher.update(chunkBytes);
    } finally {
      // Best-effort privacy hygiene for transient file copies. This cannot
      // erase browser/OS caches or copies retained by the JS engine.
      wipeBytes(chunkBytes);
    }
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


export function ensureHashAlg(hashAlgId) {
  validateHashAlgId(hashAlgId);
}
