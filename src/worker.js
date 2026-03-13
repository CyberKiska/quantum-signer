import {
  DEFAULT_SUITE_ID,
  QSIG_V2_DEFAULT_CTX,
  assertSignatureLength,
  bytesToHexLower,
  computeFingerprint,
  computeFingerprintBytes,
  computeFingerprintHex,
  generateKeypair,
  getPublicKeyFromSecret,
  getSuite,
  hashBytesSHA3512,
  hashFileSHA3512,
  signBytes,
  verifyBytes,
} from './crypto/algorithms.js';
import { ErrorCode, createError, normalizeError } from './crypto/errors.js';
import {
  AuthDigestAlgId,
  FingerprintAlgId,
  HashAlgId,
  SignatureProfileId,
  buildTBSV2,
  computeAuthMetaDigestV2,
  getHashName,
  packPublicKeyV1,
  packSecretKeyV1,
  packAuthenticatedMetadataV2,
  packSignatureV2,
  packSignerFingerprint,
  unpackPublicKeyV1,
  unpackSecretKeyV1,
  unpackSignatureV2,
  unpackSignerFingerprint,
} from './formats/containers.js';
import {
  normalizeMetadata,
  validateRequired,
  validateSignatureAndKeySuites,
} from './crypto/validate.js';
import { runSelfTest } from './crypto/selftest.js';
import { equalsBytes, wipeBytes } from './crypto/bytes.js';

export const WorkerMessageType = Object.freeze({
  HASH_FILE: 'HASH_FILE',
  KEYGEN: 'KEYGEN',
  SIGN: 'SIGN',
  VERIFY_FILE: 'VERIFY_FILE',
  VERIFY_TEXT: 'VERIFY_TEXT',
  HASH_TEXT: 'HASH_TEXT',
  SELFTEST: 'SELFTEST',
});

const Handlers = {
  [WorkerMessageType.HASH_FILE]: handleHashFile,
  [WorkerMessageType.HASH_TEXT]: handleHashText,
  [WorkerMessageType.KEYGEN]: handleKeygen,
  [WorkerMessageType.SIGN]: handleSign,
  [WorkerMessageType.VERIFY_FILE]: handleVerifyFile,
  [WorkerMessageType.VERIFY_TEXT]: handleVerifyText,
  [WorkerMessageType.SELFTEST]: handleSelfTest,
};

self.onmessage = async (event) => {
  const request = event.data;
  const id = request?.id;
  const type = request?.type;
  try {
    if (!request || typeof request !== 'object') {
      throw createError(ErrorCode.E_WORKER_PROTOCOL, { reason: 'request_not_object' });
    }
    if (!id || (typeof id !== 'string' && typeof id !== 'number')) {
      throw createError(ErrorCode.E_WORKER_PROTOCOL, { reason: 'missing_id' });
    }
    if (typeof type !== 'string' || !Handlers[type]) {
      throw createError(ErrorCode.E_WORKER_PROTOCOL, { reason: 'unsupported_type', type });
    }

    const result = await Handlers[type](id, request.payload || {});
    postMessage({ id, type: 'RESULT', op: type, ok: true, result });
  } catch (err) {
    const normalized = normalizeError(err);
    postMessage({
      id: id || null,
      type: 'ERROR',
      op: type || null,
      ok: false,
      code: normalized.code,
      message: normalized.message,
      details: normalized.details,
    });
  }
};

function sendProgress(id, op, loaded, total, extra = null) {
  const percent = total > 0 ? Math.round((loaded / total) * 100) : 100;
  postMessage({ id, type: 'PROGRESS', op, loaded, total, percent, ...(extra || {}) });
}

function nowIso() {
  return new Date().toISOString();
}

function defaultMetadataFromFile(file) {
  return {
    filename: file.name || undefined,
    filesize: BigInt(file.size || 0),
    createdAt: nowIso(),
  };
}

function defaultMetadataFromText(textBytes) {
  return {
    filesize: BigInt(textBytes.length),
    createdAt: nowIso(),
  };
}

function metadataFingerprintHex(parsedSig) {
  if (!(parsedSig.metadata?.signerFingerprint instanceof Uint8Array)) return null;
  try {
    const parsed = unpackSignerFingerprint(parsedSig.metadata.signerFingerprint);
    return bytesToHexLower(parsed.digest);
  } catch (_err) {
    return null;
  }
}

function resolveVerificationCandidates(parsedSig, publicKeyFile) {
  const embeddedKey =
    parsedSig.metadata?.signerPublicKey instanceof Uint8Array && parsedSig.metadata.signerPublicKey.length > 0
      ? parsedSig.metadata.signerPublicKey
      : null;

  let loaded = null;
  if (publicKeyFile instanceof Uint8Array) {
    const parsedPublic = unpackPublicKeyV1(publicKeyFile);
    validateSignatureAndKeySuites(parsedSig.suiteId, parsedPublic.suiteId);
    loaded = {
      keySource: 'keys',
      publicKey: parsedPublic.keyBytes,
      signerFingerprintHex: computeFingerprintHex(parsedPublic.keyBytes),
    };
  }

  const embedded = embeddedKey
    ? {
        keySource: 'signature',
        publicKey: embeddedKey,
        signerFingerprintHex: computeFingerprintHex(embeddedKey),
      }
    : null;

  return {
    loaded,
    embedded,
    embeddedKeyMatchesLoaded: loaded && embedded ? equalsBytes(loaded.publicKey, embedded.publicKey) : null,
    signatureMetadataFingerprintHex: metadataFingerprintHex(parsedSig),
  };
}

function verifyWithCandidate(parsedSig, candidate) {
  const valid = verifyBytes({
    suiteId: parsedSig.suiteId,
    message: parsedSig.tbs,
    signature: parsedSig.signature,
    publicKey: candidate.publicKey,
    contextBytes: parsedSig.ctxBytes,
  });
  return {
    keySource: candidate.keySource,
    signerFingerprintHex: candidate.signerFingerprintHex,
    valid,
  };
}

function mismatchWarning(loadedValid, embeddedValid) {
  if (loadedValid && embeddedValid) {
    return 'Loaded public key differs from embedded key, but both verify. Use trusted key identity for final trust decision.';
  }
  if (loadedValid && !embeddedValid) {
    return 'Loaded public key verifies, embedded key does not. Signature metadata key may be stale or modified.';
  }
  if (!loadedValid && embeddedValid) {
    return 'Loaded public key fails, embedded key verifies. You may have loaded the wrong public key.';
  }
  return 'Loaded and embedded keys both fail verification.';
}

function finalizeVerification(parsedSig, publicKeyFile, hashDetails) {
  const candidates = resolveVerificationCandidates(parsedSig, publicKeyFile);

  if (!candidates.loaded && !candidates.embedded) {
    return {
      valid: false,
      code: ErrorCode.E_INPUT_REQUIRED,
      warning: 'No verification key available. Load a public key in Keys, or use a .qsig that embeds signer public key.',
      ...hashDetails,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
    };
  }

  if (candidates.loaded && candidates.embedded && candidates.embeddedKeyMatchesLoaded === false) {
    const loadedResult = verifyWithCandidate(parsedSig, candidates.loaded);
    const embeddedResult = verifyWithCandidate(parsedSig, candidates.embedded);
    return {
      valid: loadedResult.valid,
      code: loadedResult.valid ? null : ErrorCode.E_SIGNATURE_INVALID,
      ...hashDetails,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      keySource: loadedResult.keySource,
      signerFingerprintHex: loadedResult.signerFingerprintHex,
      signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
      embeddedKeyMatchesLoaded: false,
      keyMismatch: true,
      loadedKeyValid: loadedResult.valid,
      embeddedKeyValid: embeddedResult.valid,
      loadedKeyFingerprintHex: loadedResult.signerFingerprintHex,
      embeddedKeyFingerprintHex: embeddedResult.signerFingerprintHex,
      warning: mismatchWarning(loadedResult.valid, embeddedResult.valid),
    };
  }

  const activeCandidate = candidates.loaded || candidates.embedded;
  const result = verifyWithCandidate(parsedSig, activeCandidate);

  if (!result.valid) {
    return {
      valid: false,
      code: ErrorCode.E_SIGNATURE_INVALID,
      ...hashDetails,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      keySource: result.keySource,
      signerFingerprintHex: result.signerFingerprintHex,
      signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
      embeddedKeyMatchesLoaded: candidates.embeddedKeyMatchesLoaded,
    };
  }

  return {
    valid: true,
    code: null,
    ...hashDetails,
    suiteId: parsedSig.suiteId,
    hashAlgId: parsedSig.hashAlgId,
    hashAlgName: getHashName(parsedSig.hashAlgId),
    context: parsedSig.ctx,
    signatureLength: parsedSig.signature.length,
    keySource: result.keySource,
    signerFingerprintHex: result.signerFingerprintHex,
    signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
    embeddedKeyMatchesLoaded: candidates.embeddedKeyMatchesLoaded,
    warning:
      result.keySource === 'signature'
        ? 'Verified using public key embedded in .qsig. For identity assurance, compare with a trusted key in Keys tab.'
        : null,
  };
}

async function handleHashFile(id, payload) {
  validateRequired(payload.file, 'file');
  const hashBytes = await hashFileSHA3512(payload.file, {
    chunkSize: payload.chunkSize,
    onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.HASH_FILE, loaded, total),
  });
  return {
    hashAlgId: HashAlgId.SHA3_512,
    hashAlgName: getHashName(HashAlgId.SHA3_512),
    hashHex: bytesToHexLower(hashBytes),
    hashBytes,
  };
}

async function handleHashText(_id, payload) {
  if (typeof payload.text !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'text' });
  }
  const textBytes = new TextEncoder().encode(payload.text);
  const hashBytes = hashBytesSHA3512(textBytes);
  return {
    hashAlgId: HashAlgId.SHA3_512,
    hashAlgName: getHashName(HashAlgId.SHA3_512),
    hashHex: bytesToHexLower(hashBytes),
    hashBytes,
  };
}

async function handleKeygen(_id, payload) {
  const suiteId = payload.suiteId ?? DEFAULT_SUITE_ID;
  const suite = getSuite(suiteId);
  const keys = generateKeypair(suiteId);

  try {
    const publicKeyFile = packPublicKeyV1({ suiteId, keyBytes: keys.publicKey });
    const secretKeyFile = packSecretKeyV1({ suiteId, keyBytes: keys.secretKey });

    return {
      suiteId,
      suiteName: suite.name,
      publicKeyLength: keys.publicKey.length,
      secretKeyLength: keys.secretKey.length,
      fingerprintShort: computeFingerprint(keys.publicKey, 8),
      fingerprintHex: computeFingerprintHex(keys.publicKey),
      publicKeyFile,
      secretKeyFile,
    };
  } finally {
    wipeBytes(keys.publicKey);
    wipeBytes(keys.secretKey);
  }
}

async function handleSign(id, payload) {
  validateRequired(payload.secretKeyFile, 'secretKeyFile');

  const parsedSecret = unpackSecretKeyV1(payload.secretKeyFile);
  const suite = getSuite(parsedSecret.suiteId);

  let fileHash;
  let authMetaBytes = null;
  let metadataInput = null;
  let inputKind = 'unknown';
  let inputLength = 0;
  let signerPublicKey = null;
  let signerFingerprintDigest = null;

  try {
    if (payload.file) {
      inputKind = 'file';
      inputLength = Number(payload.file.size || 0);
      fileHash = await hashFileSHA3512(payload.file, {
        chunkSize: payload.chunkSize,
        onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.SIGN, loaded, total),
      });
      metadataInput = defaultMetadataFromFile(payload.file);
    } else if (typeof payload.text === 'string') {
      inputKind = 'text';
      const textBytes = new TextEncoder().encode(payload.text);
      inputLength = textBytes.length;
      fileHash = hashBytesSHA3512(textBytes);
      metadataInput = defaultMetadataFromText(textBytes);
    } else {
      throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file|text' });
    }

    const ctxBytes = new TextEncoder().encode(QSIG_V2_DEFAULT_CTX);
    const signatureProfileId = SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2;
    const payloadDigestAlgId = HashAlgId.SHA3_512;
    const authDigestAlgId = AuthDigestAlgId.SHA3_256;

    signerPublicKey = getPublicKeyFromSecret(parsedSecret.suiteId, parsedSecret.keyBytes);
    signerFingerprintDigest = computeFingerprintBytes(signerPublicKey);
    const signerFingerprintHex = bytesToHexLower(signerFingerprintDigest);
    const signerFingerprint = packSignerFingerprint({
      algId: FingerprintAlgId.SHA3_256,
      digest: signerFingerprintDigest,
    });

    const authenticatedMetadata = {
      signerPublicKey,
      signerFingerprint,
    };
    const displayMetadata = normalizeMetadata(metadataInput);
    authMetaBytes = packAuthenticatedMetadataV2(authenticatedMetadata);
    const authMetaDigest = computeAuthMetaDigestV2(authMetaBytes, authDigestAlgId);

    const tbs = buildTBSV2({
      suiteId: parsedSecret.suiteId,
      signatureProfileId,
      payloadDigestAlgId,
      authDigestAlgId,
      payloadDigest: fileHash,
      authMetaDigest,
    });

    const signature = signBytes({
      suiteId: parsedSecret.suiteId,
      message: tbs,
      secretKey: parsedSecret.keyBytes,
      hedged: true,
      contextBytes: ctxBytes,
    });

    const sigBytes = packSignatureV2({
      suiteId: parsedSecret.suiteId,
      signatureProfileId,
      payloadDigestAlgId,
      authDigestAlgId,
      payloadDigest: fileHash,
      authMetaDigest,
      signature,
      ctx: QSIG_V2_DEFAULT_CTX,
      authenticatedMetadata,
      displayMetadata,
    });

    return {
      valid: true,
      inputKind,
      inputLength,
      suiteId: parsedSecret.suiteId,
      suiteName: suite.name,
      hashAlgId: payloadDigestAlgId,
      hashAlgName: getHashName(payloadDigestAlgId),
      context: QSIG_V2_DEFAULT_CTX,
      fileHashHex: bytesToHexLower(fileHash),
      signatureLength: signature.length,
      signerFingerprintHex,
      sigBytes,
    };
  } finally {
    wipeBytes(parsedSecret.keyBytes);
    if (signerPublicKey) wipeBytes(signerPublicKey);
    if (signerFingerprintDigest) wipeBytes(signerFingerprintDigest);
    if (authMetaBytes) wipeBytes(authMetaBytes);
  }
}

async function handleVerifyFile(id, payload) {
  validateRequired(payload.file, 'file');
  validateRequired(payload.sigFile, 'sigFile');

  const parsedSig = unpackSignatureV2(payload.sigFile);
  assertSignatureLength(parsedSig.suiteId, parsedSig.signature);
  const computedHash = await hashFileSHA3512(payload.file, {
    chunkSize: payload.chunkSize,
    onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.VERIFY_FILE, loaded, total),
  });

  const computedHashHex = bytesToHexLower(computedHash);
  const signedHashHex = bytesToHexLower(parsedSig.fileHash);

  if (computedHashHex !== signedHashHex) {
    return {
      valid: false,
      inputKind: 'file',
      inputLength: Number(payload.file.size || 0),
      code: ErrorCode.E_FILE_HASH_MISMATCH,
      computedHashHex,
      signedHashHex,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      signatureMetadataFingerprintHex: metadataFingerprintHex(parsedSig),
    };
  }

  return finalizeVerification(parsedSig, payload.publicKeyFile || null, {
    inputKind: 'file',
    inputLength: Number(payload.file.size || 0),
    computedHashHex,
    signedHashHex,
  });
}

async function handleVerifyText(_id, payload) {
  validateRequired(payload.sigFile, 'sigFile');
  if (typeof payload.text !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'text' });
  }

  const parsedSig = unpackSignatureV2(payload.sigFile);
  assertSignatureLength(parsedSig.suiteId, parsedSig.signature);
  const textBytes = new TextEncoder().encode(payload.text);
  const providedHashBytes = hashBytesSHA3512(textBytes);

  const providedHashHex = bytesToHexLower(providedHashBytes);
  const signedHashHex = bytesToHexLower(parsedSig.fileHash);

  if (providedHashHex !== signedHashHex) {
    return {
      valid: false,
      inputKind: 'text',
      inputLength: textBytes.length,
      code: ErrorCode.E_FILE_HASH_MISMATCH,
      providedHashHex,
      signedHashHex,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      signatureMetadataFingerprintHex: metadataFingerprintHex(parsedSig),
    };
  }

  return finalizeVerification(parsedSig, payload.publicKeyFile || null, {
    inputKind: 'text',
    inputLength: textBytes.length,
    providedHashHex,
    signedHashHex,
  });
}

async function handleSelfTest(id, payload) {
  const full = payload?.full === true;
  return runSelfTest({
    full,
    onProgress: (loaded, total, current) => {
      sendProgress(id, WorkerMessageType.SELFTEST, loaded, total, { current });
    },
  });
}
