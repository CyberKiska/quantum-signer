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
  signBytesVerified,
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
import { validateRequired } from './crypto/validate.js';
import { runSelfTest } from './crypto/selftest.js';
import { equalsBytes, wipeBytes } from './crypto/bytes.js';
import { createSecretSessionManager } from './crypto/secret-session.js';
import { utf8ToBytesStrict } from './crypto/text-encoding.js';
import { finalizePayloadVerification } from './crypto/verify-policy.js';
import { resolveSignInputKind } from './core/sign-input.js';

export const WorkerMessageType = Object.freeze({
  HASH_FILE: 'HASH_FILE',
  KEYGEN: 'KEYGEN',
  IMPORT_SECRET: 'IMPORT_SECRET',
  AUTHORIZE_SECRET_EXPORT: 'AUTHORIZE_SECRET_EXPORT',
  EXPORT_SECRET: 'EXPORT_SECRET',
  CLEAR_SECRET_SESSION: 'CLEAR_SECRET_SESSION',
  SIGN: 'SIGN',
  VERIFY_FILE: 'VERIFY_FILE',
  VERIFY_TEXT: 'VERIFY_TEXT',
  HASH_TEXT: 'HASH_TEXT',
  SELFTEST: 'SELFTEST',
});

const secretSessions = createSecretSessionManager({
  onSessionExpired(secretSessionHandle) {
    postMessage({
      type: 'SECRET_SESSION_INVALIDATED',
      reason: 'idle-timeout',
      secretSessionHandle,
    });
  },
});

function encodeUserText(text) {
  try {
    return utf8ToBytesStrict(text, 'text');
  } catch (err) {
    if (err instanceof RangeError || err instanceof TypeError) {
      throw createError(ErrorCode.E_TEXT_ENCODING, { reason: err.message });
    }
    throw err;
  }
}

const Handlers = {
  [WorkerMessageType.HASH_FILE]: handleHashFile,
  [WorkerMessageType.HASH_TEXT]: handleHashText,
  [WorkerMessageType.KEYGEN]: handleKeygen,
  [WorkerMessageType.IMPORT_SECRET]: handleImportSecret,
  [WorkerMessageType.AUTHORIZE_SECRET_EXPORT]: handleAuthorizeSecretExport,
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
    const response = { id, type: 'RESULT', op: type, ok: true, result };
    if (type === WorkerMessageType.EXPORT_SECRET && result?.secretKeyFile instanceof Uint8Array) {
      // Transfer rather than structured-clone the encrypted key container.
      // The worker-side source buffer is detached when postMessage succeeds.
      try {
        postMessage(response, [result.secretKeyFile.buffer]);
      } catch (error) {
        wipeBytes(result.secretKeyFile);
        throw error;
      }
    } else {
      postMessage(response);
    }
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
  const textBytes = encodeUserText(payload.text);
  try {
    assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
    const hashBytes = hashBytesSHA3512(textBytes);
    return {
      hashAlgId: HashAlgId.SHA3_512,
      hashAlgName: getHashName(HashAlgId.SHA3_512),
      hashHex: bytesToHexLower(hashBytes),
      hashBytes,
      inputLength: textBytes.length,
    };
  } finally {
    wipeBytes(textBytes);
  }
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
    const session = await secretSessions.importSecretKeyFile(secretKeyFile, payload.passphrase);
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

async function handleAuthorizeSecretExport(_id, payload) {
  if (typeof payload.secretSessionHandle !== 'string' || payload.secretSessionHandle.length === 0) {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'secretSessionHandle' });
  }
  return secretSessions.authorizeSecretKeyExport(payload.secretSessionHandle);
}

async function handleExportSecret(_id, payload) {
  if (typeof payload.secretSessionHandle !== 'string' || payload.secretSessionHandle.length === 0) {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'secretSessionHandle' });
  }
  if (typeof payload.exportConsentToken !== 'string' || payload.exportConsentToken.length === 0) {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'exportConsentToken' });
  }
  const secretKeyFile = await secretSessions.exportSecretKeyFile(
    payload.secretSessionHandle,
    payload.exportConsentToken,
    {
      passphrase: payload.passphrase,
      rawExport: payload.rawExport === true,
    }
  );
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
  const requestedInputKind = resolveSignInputKind(payload);

  let fileHash;
  let authMetaBytes = null;
  let inputKind = 'unknown';
  let inputLength = 0;
  let signerPublicKey = null;
  let signerFingerprintDigest = null;
  let sessionLease = null;
  let signature = null;

  try {
    if (requestedInputKind === 'file') {
      assertFileSizeLimit(payload.file, MAX_PAYLOAD_FILE_BYTES, 'file');
      inputKind = 'file';
      inputLength = Number(payload.file.size || 0);
      fileHash = await hashFileSHA3512(payload.file, {
        chunkSize: payload.chunkSize,
        onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.SIGN, loaded, total),
      });
    } else {
      inputKind = 'text';
      const textBytes = encodeUserText(payload.text);
      try {
        assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
        inputLength = textBytes.length;
        fileHash = hashBytesSHA3512(textBytes);
      } finally {
        wipeBytes(textBytes);
      }
    }

    // Acquire key material only after all asynchronous hashing has completed.
    // The lease prevents a concurrent clear/replace request from wiping the
    // arrays while the synchronous sign-and-verify transaction is running.
    sessionLease = secretSessions.acquireSession(payload.secretSessionHandle);
    const { session } = sessionLease;
    const suite = getSuite(session.suiteId);

    const ctxBytes = utf8ToBytesStrict(QSIG_DEFAULT_CTX, 'context');
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
    // QSIG v2 can parse legacy display-only metadata, but new signatures omit
    // it. Carrying unsigned filenames/timestamps inside a signature container
    // invites downstream code to mistake untrusted hints for signed claims.
    const displayMetadata = {};
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

    signature = signBytesVerified({
      suiteId: session.suiteId,
      signatureProfileId,
      message: tbs,
      secretKey: session.secretKey,
      publicKey: signerPublicKey,
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
    const roundTrip = unpackSignatureV2(sigBytes);
    if (
      !equalsBytes(roundTrip.tbs, tbs) ||
      !equalsBytes(roundTrip.ctxBytes, ctxBytes) ||
      !equalsBytes(roundTrip.signature, signature) ||
      !equalsBytes(roundTrip.authenticatedMetadata.signerPublicKey, signerPublicKey)
    ) {
      wipeBytes(sigBytes);
      throw createError(ErrorCode.E_SIGN_SELF_VERIFY, {
        reason: 'container_round_trip_mismatch',
        suiteId: session.suiteId,
      });
    }

    return {
      created: true,
      selfVerified: true,
      valid: true,
      inputKind,
      inputLength,
      suiteId: session.suiteId,
      suiteName: suite.name,
      signatureProfileId,
      hashAlgId: payloadDigestAlgId,
      authDigestAlgId,
      hashAlgName: getHashName(payloadDigestAlgId),
      context: QSIG_DEFAULT_CTX,
      fileHashHex: bytesToHexLower(fileHash),
      signatureLength: signature.length,
      signerFingerprintHex,
      sigBytes,
    };
  } finally {
    if (signature) wipeBytes(signature);
    if (signerPublicKey) wipeBytes(signerPublicKey);
    if (signerFingerprintDigest) wipeBytes(signerFingerprintDigest);
    if (authMetaBytes) wipeBytes(authMetaBytes);
    if (sessionLease) sessionLease.release();
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

  return {
    signatureProfileId: parsedSig.signatureProfileId,
    authDigestAlgId: parsedSig.authDigestAlgId,
    ...finalizePayloadVerification(parsedSig, payload.publicKeyFile || null, {
      inputKind: 'file',
      inputLength: Number(payload.file.size || 0),
      computedHashHex,
    }),
  };
}

async function handleVerifyText(_id, payload) {
  validateRequired(payload.sigFile, 'sigFile');
  if (typeof payload.text !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'text' });
  }
  assertBytesLimit(payload.sigFile, MAX_SIGNATURE_FILE_BYTES, 'sigFile');

  const parsedSig = unpackSignatureV2(payload.sigFile);
  assertSignatureLength(parsedSig.suiteId, parsedSig.signature);
  const textBytes = encodeUserText(payload.text);
  try {
    assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
    const providedHashBytes = hashBytesSHA3512(textBytes);
    const providedHashHex = bytesToHexLower(providedHashBytes);

    return {
      signatureProfileId: parsedSig.signatureProfileId,
      authDigestAlgId: parsedSig.authDigestAlgId,
      ...finalizePayloadVerification(parsedSig, payload.publicKeyFile || null, {
        inputKind: 'text',
        inputLength: textBytes.length,
        providedHashHex,
      }),
    };
  } finally {
    wipeBytes(textBytes);
  }
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
