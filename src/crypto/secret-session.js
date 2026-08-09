import {
  assertKeyLength,
  computeFingerprint,
  computeFingerprintHex,
  generateKeypair,
  getPublicKeyFromSecret,
  getSuite,
  signBytesVerified,
} from './algorithms.js';
import { equalsBytes, wipeBytes } from './bytes.js';
import { ErrorCode, createError } from './errors.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit } from './policy.js';
import { utf8ToBytesStrict } from './text-encoding.js';
import {
  decryptSecretKeyFile,
  encryptSecretKeyFile,
  isProtectedSecretKeyFile,
} from './key-protection.js';
import { packPublicKey, packSecretKey, unpackSecretKey } from '../formats/containers.js';

const IMPORT_PCT_CONTEXT = 'quantum-signer/private-key-import-pct/v1';
const IMPORT_PCT_MESSAGE = 'quantum-signer/expanded-private-key-import-check/v1';
const GENERATION_PCT_CONTEXT = 'quantum-signer/private-key-generation-pct/v1';
const GENERATION_PCT_MESSAGE = 'quantum-signer/private-key-generation-check/v1';

function cloneBytes(bytes) {
  return Uint8Array.from(bytes);
}

export const DEFAULT_SECRET_SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const DEFAULT_EXPORT_AUTHORIZATION_TTL_MS = 60 * 1000;
export const DEFAULT_MAX_SECRET_SESSIONS = 2;

function monotonicNow() {
  if (typeof globalThis.performance?.now === 'function') return globalThis.performance.now();
  return Date.now();
}

function validateImportedSecretKeyPair(suiteId, secretKey) {
  let temporarySecretKey;
  let derivedPublicKey;
  let verifiedPublicKey;
  let signature;
  let message;
  let contextBytes;
  let stage = 'derive_public_key';

  try {
    temporarySecretKey = cloneBytes(secretKey);
    derivedPublicKey = getPublicKeyFromSecret(suiteId, temporarySecretKey);
    stage = 'pairwise_consistency_test';
    message = utf8ToBytesStrict(`${IMPORT_PCT_MESSAGE}/suite-${suiteId}`, 'importPctMessage');
    contextBytes = utf8ToBytesStrict(IMPORT_PCT_CONTEXT, 'importPctContext');
    signature = signBytesVerified({
      suiteId,
      message,
      secretKey: temporarySecretKey,
      publicKey: derivedPublicKey,
      hedged: false,
      contextBytes,
    });
    verifiedPublicKey = cloneBytes(derivedPublicKey);
    return verifiedPublicKey;
  } catch (err) {
    throw createError(ErrorCode.E_KEY_CONSISTENCY, {
      reason: 'private_key_import_pct_failed',
      suiteId,
      stage,
      causeCode: typeof err?.code === 'string' ? err.code : undefined,
    });
  } finally {
    wipeBytes(signature);
    wipeBytes(derivedPublicKey);
    wipeBytes(temporarySecretKey);
    wipeBytes(message);
    wipeBytes(contextBytes);
  }
}

export function validateGeneratedKeyPair(suiteId, secretKey, publicKey) {
  let temporarySecretKey;
  let temporaryPublicKey;
  let derivedPublicKey;
  let signature;
  let message;
  let contextBytes;
  let stage = 'derive_public_key';

  try {
    const suite = getSuite(suiteId);
    assertKeyLength(suiteId, secretKey, 'secret');
    assertKeyLength(suiteId, publicKey, 'public');
    temporarySecretKey = cloneBytes(secretKey);
    temporaryPublicKey = cloneBytes(publicKey);
    derivedPublicKey = getPublicKeyFromSecret(suiteId, temporarySecretKey);
    if (!equalsBytes(derivedPublicKey, temporaryPublicKey)) {
      throw createError(ErrorCode.E_KEY_CONSISTENCY, { reason: 'generated_public_key_mismatch' });
    }

    // FIPS 204 key generation requires a sign/verify pairwise consistency
    // test. For SLH-DSA, SP 800-208/CMVP guidance permits checking the public
    // key material embedded in the secret key; the full derived-key comparison
    // above checks both PK.seed and PK.root without an expensive signature.
    if (suite.family !== 'SLH-DSA') {
      stage = 'pairwise_consistency_test';
      message = utf8ToBytesStrict(`${GENERATION_PCT_MESSAGE}/suite-${suiteId}`, 'generationPctMessage');
      contextBytes = utf8ToBytesStrict(GENERATION_PCT_CONTEXT, 'generationPctContext');
      signature = signBytesVerified({
        suiteId,
        message,
        secretKey: temporarySecretKey,
        publicKey: temporaryPublicKey,
        hedged: false,
        contextBytes,
      });
    }
  } catch (err) {
    throw createError(ErrorCode.E_KEY_CONSISTENCY, {
      reason: 'private_key_generation_pct_failed',
      suiteId,
      stage,
      causeCode: typeof err?.code === 'string' ? err.code : undefined,
    });
  } finally {
    wipeBytes(signature);
    wipeBytes(derivedPublicKey);
    wipeBytes(temporaryPublicKey);
    wipeBytes(temporarySecretKey);
    wipeBytes(message);
    wipeBytes(contextBytes);
  }
}

function randomOpaqueId(prefix) {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return `${prefix}-${globalThis.crypto.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  wipeBytes(bytes);
  return `${prefix}-${hex}`;
}

function buildSessionSummary(handle, session) {
  return {
    sessionHandle: handle,
    suiteId: session.suiteId,
    publicKeyLength: session.publicKey.length,
    secretKeyLength: session.secretKey.length,
    fingerprintShort: session.fingerprintShort,
    fingerprintHex: session.fingerprintHex,
    publicKeyFile: packPublicKey({
      suiteId: session.suiteId,
      keyBytes: session.publicKey,
    }),
  };
}

export function createSecretSessionManager({
  idleTimeoutMs = DEFAULT_SECRET_SESSION_IDLE_TIMEOUT_MS,
  exportAuthorizationTtlMs = DEFAULT_EXPORT_AUTHORIZATION_TTL_MS,
  maxSessions = DEFAULT_MAX_SECRET_SESSIONS,
  now = monotonicNow,
  setTimer = (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimer = (timer) => globalThis.clearTimeout(timer),
  onSessionExpired = () => {},
} = {}) {
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs <= 0 || idleTimeoutMs > 0x7fffffff) {
    throw createError(ErrorCode.E_INTERNAL, { reason: 'invalid_secret_session_idle_timeout', idleTimeoutMs });
  }
  if (
    !Number.isInteger(exportAuthorizationTtlMs) ||
    exportAuthorizationTtlMs <= 0 ||
    exportAuthorizationTtlMs > 0x7fffffff
  ) {
    throw createError(ErrorCode.E_INTERNAL, {
      reason: 'invalid_export_authorization_ttl',
      exportAuthorizationTtlMs,
    });
  }
  if (!Number.isInteger(maxSessions) || maxSessions <= 0 || maxSessions > 16) {
    throw createError(ErrorCode.E_INTERNAL, { reason: 'invalid_secret_session_limit', maxSessions });
  }
  if (
    typeof now !== 'function' ||
    typeof setTimer !== 'function' ||
    typeof clearTimer !== 'function' ||
    typeof onSessionExpired !== 'function'
  ) {
    throw createError(ErrorCode.E_INTERNAL, { reason: 'invalid_secret_session_scheduler' });
  }

  const sessions = new Map();

  function readNow() {
    const value = Number(now());
    if (!Number.isFinite(value)) {
      throw createError(ErrorCode.E_INTERNAL, { reason: 'invalid_secret_session_clock' });
    }
    return value;
  }

  function cancelExpiry(session) {
    if (session.expiryTimer === null) return;
    clearTimer(session.expiryTimer);
    session.expiryTimer = null;
  }

  function wipeSession(session) {
    if (session.wiped) return;
    cancelExpiry(session);
    session.wiped = true;
    session.exportAuthorization = null;
    wipeBytes(session.secretKey);
    wipeBytes(session.publicKey);
  }

  function expireSession(handle, session) {
    if (sessions.get(handle) === session) sessions.delete(handle);
    cancelExpiry(session);
    session.clearRequested = true;
    if (session.activeLeases === 0) wipeSession(session);
    try {
      onSessionExpired(handle);
    } catch (_err) {
      // Expiry and wiping must not depend on an observer succeeding.
    }
  }

  function expireIfIdle(handle, session) {
    session.expiryTimer = null;
    if (sessions.get(handle) !== session || session.clearRequested || session.wiped) return;

    const elapsed = Math.max(0, readNow() - session.lastActivityAt);
    if (elapsed < idleTimeoutMs) {
      scheduleExpiry(handle, session);
      return;
    }

    expireSession(handle, session);
  }

  function scheduleExpiry(handle, session) {
    cancelExpiry(session);
    if (session.clearRequested || session.wiped) return;

    const elapsed = Math.max(0, readNow() - session.lastActivityAt);
    const delay = Math.max(0, idleTimeoutMs - elapsed);
    const timer = setTimer(() => expireIfIdle(handle, session), delay);
    session.expiryTimer = timer;
    // Node-based self-tests should not be held open solely by a production
    // browser lifecycle timer. Browser timer ids simply do not expose unref().
    timer?.unref?.();
  }

  function touchSession(handle, session) {
    session.lastActivityAt = readNow();
    scheduleExpiry(handle, session);
  }

  function assertSessionCapacity() {
    if (sessions.size >= maxSessions) {
      throw createError(ErrorCode.E_SESSION_LIMIT, { maxSessions });
    }
  }

  function createSession({ suiteId, secretKey, publicKey }) {
    assertSessionCapacity();
    assertKeyLength(suiteId, secretKey, 'secret');
    const sessionSecretKey = cloneBytes(secretKey);
    const sessionPublicKey = publicKey ? cloneBytes(publicKey) : getPublicKeyFromSecret(suiteId, sessionSecretKey);
    assertKeyLength(suiteId, sessionPublicKey, 'public');

    const handle = randomOpaqueId('secret-session');
    const session = {
      suiteId,
      secretKey: sessionSecretKey,
      publicKey: sessionPublicKey,
      activeLeases: 0,
      clearRequested: false,
      wiped: false,
      lastActivityAt: readNow(),
      expiryTimer: null,
      exportAuthorization: null,
      fingerprintShort: computeFingerprint(sessionPublicKey, 8),
      fingerprintHex: computeFingerprintHex(sessionPublicKey),
    };

    sessions.set(handle, session);
    scheduleExpiry(handle, session);
    return buildSessionSummary(handle, session);
  }

  function requireSession(handle, { touch = true } = {}) {
    if (typeof handle !== 'string' || handle.length === 0) {
      throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'secretSessionHandle' });
    }
    const session = sessions.get(handle);
    if (!session) {
      throw createError(ErrorCode.E_SESSION_MISSING, { field: 'secretSessionHandle', handle });
    }
    const elapsed = Math.max(0, readNow() - session.lastActivityAt);
    if (elapsed >= idleTimeoutMs) {
      expireSession(handle, session);
      throw createError(ErrorCode.E_SESSION_MISSING, {
        field: 'secretSessionHandle',
        handle,
        reason: 'idle_timeout',
      });
    }
    if (touch) touchSession(handle, session);
    return session;
  }

  function clearSession(handle) {
    const session = sessions.get(handle);
    if (!session) return false;
    sessions.delete(handle);
    cancelExpiry(session);
    session.clearRequested = true;
    if (session.activeLeases === 0) wipeSession(session);
    return true;
  }

  function acquireSession(handle) {
    const session = requireSession(handle);
    if (session.clearRequested || session.wiped) {
      throw createError(ErrorCode.E_SESSION_MISSING, { field: 'secretSessionHandle', handle });
    }

    session.activeLeases += 1;
    let released = false;
    return {
      session,
      release() {
        if (released) return;
        released = true;
        session.activeLeases -= 1;
        if (session.activeLeases < 0) {
          session.activeLeases = 0;
          throw createError(ErrorCode.E_INTERNAL, { reason: 'negative_session_lease_count' });
        }
        if (session.clearRequested && session.activeLeases === 0) wipeSession(session);
      },
    };
  }

  return {
    generateSession(suiteId) {
      assertSessionCapacity();
      const keys = generateKeypair(suiteId);
      try {
        validateGeneratedKeyPair(suiteId, keys.secretKey, keys.publicKey);
        return createSession({
          suiteId,
          secretKey: keys.secretKey,
          publicKey: keys.publicKey,
        });
      } finally {
        wipeBytes(keys.publicKey);
        wipeBytes(keys.secretKey);
      }
    },

    async importSecretKeyFile(secretKeyFile, passphrase) {
      assertSessionCapacity();
      assertBytesLimit(secretKeyFile, MAX_KEY_FILE_BYTES, 'secretKeyFile');
      let decryptedSecretKeyFile;
      let parsedSecret;
      let verifiedPublicKey;
      try {
        if (isProtectedSecretKeyFile(secretKeyFile)) {
          if (typeof passphrase !== 'string' || passphrase.length === 0) {
            throw createError(ErrorCode.E_KEY_PASSPHRASE_REQUIRED);
          }
          const decrypted = await decryptSecretKeyFile(secretKeyFile, passphrase);
          decryptedSecretKeyFile = decrypted.secretKeyFile;
          parsedSecret = unpackSecretKey(decryptedSecretKeyFile);
          if (parsedSecret.suiteId !== decrypted.suiteId) {
            throw createError(ErrorCode.E_KEY_SUITE_MISMATCH, {
              protectedSuiteId: decrypted.suiteId,
              secretKeySuiteId: parsedSecret.suiteId,
            });
          }
        } else {
          // Backward-compatible import only. New exports are always encrypted.
          parsedSecret = unpackSecretKey(secretKeyFile);
        }
        verifiedPublicKey = validateImportedSecretKeyPair(parsedSecret.suiteId, parsedSecret.keyBytes);
        return createSession({
          suiteId: parsedSecret.suiteId,
          secretKey: parsedSecret.keyBytes,
          publicKey: verifiedPublicKey,
        });
      } finally {
        wipeBytes(verifiedPublicKey);
        wipeBytes(parsedSecret?.keyBytes);
        wipeBytes(decryptedSecretKeyFile);
      }
    },

    authorizeSecretKeyExport(handle) {
      const session = requireSession(handle, { touch: false });
      const exportConsentToken = randomOpaqueId('export-consent');
      session.exportAuthorization = {
        token: exportConsentToken,
        expiresAt: readNow() + exportAuthorizationTtlMs,
      };
      return {
        exportConsentToken,
        expiresInMs: exportAuthorizationTtlMs,
      };
    },

    async exportSecretKeyFile(handle, exportConsentToken, { passphrase, rawExport = false } = {}) {
      const session = requireSession(handle, { touch: false });
      const authorization = session.exportAuthorization;
      // Consume every grant on its first use attempt. This makes export
      // authorization short-lived and non-replayable even after a bad token.
      session.exportAuthorization = null;
      if (typeof exportConsentToken !== 'string' || exportConsentToken.length === 0) {
        throw createError(ErrorCode.E_EXPORT_AUTH, { field: 'exportConsentToken', reason: 'missing' });
      }
      if (!authorization || authorization.token !== exportConsentToken) {
        throw createError(ErrorCode.E_EXPORT_AUTH, { field: 'exportConsentToken', reason: 'mismatch' });
      }
      if (readNow() >= authorization.expiresAt) {
        throw createError(ErrorCode.E_EXPORT_AUTH, { field: 'exportConsentToken', reason: 'expired' });
      }
      let plaintextSecretKeyFile;
      try {
        plaintextSecretKeyFile = packSecretKey({
          suiteId: session.suiteId,
          keyBytes: session.secretKey,
        });
        if (rawExport === true) {
          // Explicit compatibility escape hatch. Callers must opt in for each
          // export; encrypted output remains the API default.
          const rawCopy = Uint8Array.from(plaintextSecretKeyFile);
          return rawCopy;
        }
        return await encryptSecretKeyFile({
          suiteId: session.suiteId,
          secretKeyFile: plaintextSecretKeyFile,
          passphrase,
        });
      } finally {
        wipeBytes(plaintextSecretKeyFile);
      }
    },

    getSession(handle) {
      return requireSession(handle);
    },

    acquireSession,

    hasSession(handle) {
      const session = sessions.get(handle);
      if (!session) return false;
      const elapsed = Math.max(0, readNow() - session.lastActivityAt);
      if (elapsed >= idleTimeoutMs) {
        expireSession(handle, session);
        return false;
      }
      return true;
    },

    clearSession,

    clearAllSessions() {
      for (const handle of Array.from(sessions.keys())) {
        clearSession(handle);
      }
    },
  };
}
