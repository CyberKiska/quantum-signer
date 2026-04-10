import {
  DEFAULT_SUITE_ID,
  QSIG_DEFAULT_CTX,
  assertSignatureLength,
  bytesToHexLower,
  computeFingerprintBytes,
  getDefaultSignatureProfileId,
  getSuite,
  hashBytesSHA3512,
  hashFileSHA3512,
  signBytes,
} from './crypto/algorithms.js';
import { ErrorCode, createError, normalizeError } from './crypto/errors.js';
import {
  MAX_KEY_FILE_BYTES,
  MAX_PAYLOAD_FILE_BYTES,
  MAX_SIGNATURE_FILE_BYTES,
  MAX_TEXT_INPUT_BYTES,
  assertBytesLimit,
  assertFileSizeLimit,
} from './crypto/policy.js';
import {
  AuthDigestAlgId,
  FingerprintAlgId,
  HashAlgId,
  buildTBSV2,
  computeAuthMetaDigestV2,
  getHashName,
  packAuthenticatedMetadataV2,
  packSignatureV2,
  packSignerFingerprint,
  unpackSignatureV2,
} from './formats/containers.js';
import {
  normalizeMetadata,
  validateRequired,
} from './crypto/validate.js';
import { runSelfTest } from './crypto/selftest.js';
import { wipeBytes } from './crypto/bytes.js';
import { createSecretSessionManager } from './crypto/secret-session.js';
import { finalizeVerification, getSignatureMetadataFingerprintHex } from './crypto/verify-policy.js';

export const WorkerMessageType = Object.freeze({
  HASH_FILE: 'HASH_FILE',
  KEYGEN: 'KEYGEN',
  IMPORT_SECRET: 'IMPORT_SECRET',
  EXPORT_SECRET: 'EXPORT_SECRET',
  CLEAR_SECRET_SESSION: 'CLEAR_SECRET_SESSION',
  SIGN: 'SIGN',
  VERIFY_FILE: 'VERIFY_FILE',
  VERIFY_TEXT: 'VERIFY_TEXT',
  HASH_TEXT: 'HASH_TEXT',
  SELFTEST: 'SELFTEST',
});

const secretSessions = createSecretSessionManager();

const Handlers = {
  [WorkerMessageType.HASH_FILE]: handleHashFile,
  [WorkerMessageType.HASH_TEXT]: handleHashText,
  [WorkerMessageType.KEYGEN]: handleKeygen,
  [WorkerMessageType.IMPORT_SECRET]: handleImportSecret,
  [WorkerMessageType.EXPORT_SECRET]: handleExportSecret,
  [WorkerMessageType.CLEAR_SECRET_SESSION]: handleClearSecretSession,
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

async function readBinaryInput(value, field, maxBytes) {
  if (value instanceof Uint8Array) {
    assertBytesLimit(value, maxBytes, field);
    return Uint8Array.from(value);
  }
  if (value && typeof value.arrayBuffer === 'function' && typeof value.size === 'number') {
    assertFileSizeLimit(value, maxBytes, field);
    return new Uint8Array(await value.arrayBuffer());
  }
  throw createError(ErrorCode.E_INPUT_REQUIRED, { field });
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

async function handleHashFile(id, payload) {
  validateRequired(payload.file, 'file');
  assertFileSizeLimit(payload.file, MAX_PAYLOAD_FILE_BYTES, 'file');
  const hashBytes = await hashFileSHA3512(payload.file, {
    chunkSize: payload.chunkSize,
    onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.HASH_FILE, loaded, total),
  });
  return {
    hashAlgId: HashAlgId.SHA3_512,
    hashAlgName: getHashName(HashAlgId.SHA3_512),
    hashHex: bytesToHexLower(hashBytes),
    hashBytes,
    inputLength: payload.file.size,
  };
}

async function handleHashText(_id, payload) {
  if (typeof payload.text !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'text' });
  }
  const textBytes = new TextEncoder().encode(payload.text);
  assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
  const hashBytes = hashBytesSHA3512(textBytes);
  return {
    hashAlgId: HashAlgId.SHA3_512,
    hashAlgName: getHashName(HashAlgId.SHA3_512),
    hashHex: bytesToHexLower(hashBytes),
    hashBytes,
    inputLength: textBytes.length,
  };
}

async function handleKeygen(_id, payload) {
  const suiteId = payload.suiteId ?? DEFAULT_SUITE_ID;
  const suite = getSuite(suiteId);
  const session = secretSessions.generateSession(suiteId);
  return {
    suiteId,
    suiteName: suite.name,
    ...session,
  };
}

async function handleImportSecret(_id, payload) {
  const secretKeyFile = await readBinaryInput(payload.secretKeyFile, 'secretKeyFile', MAX_KEY_FILE_BYTES);
  try {
    const session = secretSessions.importSecretKeyFile(secretKeyFile);
    const suite = getSuite(session.suiteId);
    return {
      suiteId: session.suiteId,
      suiteName: suite.name,
      ...session,
    };
  } finally {
    wipeBytes(secretKeyFile);
  }
}

async function handleExportSecret(_id, payload) {
  if (typeof payload.secretSessionHandle !== 'string' || payload.secretSessionHandle.length === 0) {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'secretSessionHandle' });
  }
  const secretKeyFile = secretSessions.exportSecretKeyFile(payload.secretSessionHandle);
  return { secretKeyFile };
}

async function handleClearSecretSession(_id, payload) {
  const handle = payload?.secretSessionHandle;
  if (handle !== undefined && handle !== null && typeof handle !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'secretSessionHandle' });
  }
  return {
    cleared: typeof handle === 'string' ? secretSessions.clearSession(handle) : false,
  };
}

async function handleSign(id, payload) {
  validateRequired(payload.secretSessionHandle, 'secretSessionHandle');

  const session = secretSessions.getSession(payload.secretSessionHandle);
  const suite = getSuite(session.suiteId);

  let fileHash;
  let authMetaBytes = null;
  let metadataInput = null;
  let inputKind = 'unknown';
  let inputLength = 0;
  let signerPublicKey = null;
  let signerFingerprintDigest = null;

  try {
    if (payload.file) {
      assertFileSizeLimit(payload.file, MAX_PAYLOAD_FILE_BYTES, 'file');
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
      assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
      inputLength = textBytes.length;
      fileHash = hashBytesSHA3512(textBytes);
      metadataInput = defaultMetadataFromText(textBytes);
    } else {
      throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file|text' });
    }

    const ctxBytes = new TextEncoder().encode(QSIG_DEFAULT_CTX);
    const signatureProfileId = getDefaultSignatureProfileId(session.suiteId);
    const payloadDigestAlgId = HashAlgId.SHA3_512;
    const authDigestAlgId = AuthDigestAlgId.SHA3_256;

    signerPublicKey = Uint8Array.from(session.publicKey);
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
      suiteId: session.suiteId,
      signatureProfileId,
      payloadDigestAlgId,
      authDigestAlgId,
      payloadDigest: fileHash,
      authMetaDigest,
    });

    const signature = signBytes({
      suiteId: session.suiteId,
      signatureProfileId,
      message: tbs,
      secretKey: session.secretKey,
      hedged: true,
      contextBytes: ctxBytes,
    });

    const sigBytes = packSignatureV2({
      suiteId: session.suiteId,
      signatureProfileId,
      payloadDigestAlgId,
      authDigestAlgId,
      payloadDigest: fileHash,
      authMetaDigest,
      signature,
      ctx: QSIG_DEFAULT_CTX,
      authenticatedMetadata,
      displayMetadata,
    });

    return {
      valid: true,
      inputKind,
      inputLength,
      suiteId: session.suiteId,
      suiteName: suite.name,
      hashAlgId: payloadDigestAlgId,
      hashAlgName: getHashName(payloadDigestAlgId),
      context: QSIG_DEFAULT_CTX,
      fileHashHex: bytesToHexLower(fileHash),
      signatureLength: signature.length,
      signerFingerprintHex,
      sigBytes,
    };
  } finally {
    if (signerPublicKey) wipeBytes(signerPublicKey);
    if (signerFingerprintDigest) wipeBytes(signerFingerprintDigest);
    if (authMetaBytes) wipeBytes(authMetaBytes);
  }
}

async function handleVerifyFile(id, payload) {
  validateRequired(payload.file, 'file');
  validateRequired(payload.sigFile, 'sigFile');
  assertFileSizeLimit(payload.file, MAX_PAYLOAD_FILE_BYTES, 'file');
  assertBytesLimit(payload.sigFile, MAX_SIGNATURE_FILE_BYTES, 'sigFile');

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
      cryptoValid: false,
      inputKind: 'file',
      inputLength: Number(payload.file.size || 0),
      code: ErrorCode.E_FILE_HASH_MISMATCH,
      verifiedKeySource: 'none',
      trustSource: 'payload-mismatch',
      computedHashHex,
      signedHashHex,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      signatureMetadataFingerprintHex: getSignatureMetadataFingerprintHex(parsedSig),
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
  assertBytesLimit(payload.sigFile, MAX_SIGNATURE_FILE_BYTES, 'sigFile');

  const parsedSig = unpackSignatureV2(payload.sigFile);
  assertSignatureLength(parsedSig.suiteId, parsedSig.signature);
  const textBytes = new TextEncoder().encode(payload.text);
  assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
  const providedHashBytes = hashBytesSHA3512(textBytes);

  const providedHashHex = bytesToHexLower(providedHashBytes);
  const signedHashHex = bytesToHexLower(parsedSig.fileHash);

  if (providedHashHex !== signedHashHex) {
    return {
      valid: false,
      cryptoValid: false,
      inputKind: 'text',
      inputLength: textBytes.length,
      code: ErrorCode.E_FILE_HASH_MISMATCH,
      verifiedKeySource: 'none',
      trustSource: 'payload-mismatch',
      providedHashHex,
      signedHashHex,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      signatureMetadataFingerprintHex: getSignatureMetadataFingerprintHex(parsedSig),
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
