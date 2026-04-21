import {
  assertKeyLength,
  computeFingerprint,
  computeFingerprintHex,
  generateKeypair,
  getPublicKeyFromSecret,
} from './algorithms.js';
import { wipeBytes } from './bytes.js';
import { ErrorCode, createError } from './errors.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit } from './policy.js';
import { packPublicKey, packSecretKey, unpackSecretKey } from '../formats/containers.js';

function cloneBytes(bytes) {
  return Uint8Array.from(bytes);
}

function randomOpaqueId(prefix) {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return `${prefix}-${globalThis.crypto.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}-${hex}`;
}

function buildSessionSummary(handle, session) {
  return {
    sessionHandle: handle,
    exportConsentToken: session.exportConsentToken,
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

export function createSecretSessionManager() {
  const sessions = new Map();

  function createSession({ suiteId, secretKey, publicKey }) {
    assertKeyLength(suiteId, secretKey, 'secret');
    const sessionSecretKey = cloneBytes(secretKey);
    const sessionPublicKey = publicKey ? cloneBytes(publicKey) : getPublicKeyFromSecret(suiteId, sessionSecretKey);
    assertKeyLength(suiteId, sessionPublicKey, 'public');

    const handle = randomOpaqueId('secret-session');
    const session = {
      suiteId,
      secretKey: sessionSecretKey,
      publicKey: sessionPublicKey,
      exportConsentToken: randomOpaqueId('export-consent'),
      fingerprintShort: computeFingerprint(sessionPublicKey, 8),
      fingerprintHex: computeFingerprintHex(sessionPublicKey),
    };

    sessions.set(handle, session);
    return buildSessionSummary(handle, session);
  }

  function requireSession(handle) {
    if (typeof handle !== 'string' || handle.length === 0) {
      throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'secretSessionHandle' });
    }
    const session = sessions.get(handle);
    if (!session) {
      throw createError(ErrorCode.E_SESSION_MISSING, { field: 'secretSessionHandle', handle });
    }
    return session;
  }

  function clearSession(handle) {
    const session = sessions.get(handle);
    if (!session) return false;
    wipeBytes(session.secretKey);
    wipeBytes(session.publicKey);
    sessions.delete(handle);
    return true;
  }

  return {
    generateSession(suiteId) {
      const keys = generateKeypair(suiteId);
      try {
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

    importSecretKeyFile(secretKeyFile) {
      assertBytesLimit(secretKeyFile, MAX_KEY_FILE_BYTES, 'secretKeyFile');
      const parsedSecret = unpackSecretKey(secretKeyFile);
      try {
        return createSession({
          suiteId: parsedSecret.suiteId,
          secretKey: parsedSecret.keyBytes,
        });
      } finally {
        wipeBytes(parsedSecret.keyBytes);
      }
    },

    exportSecretKeyFile(handle, exportConsentToken) {
      const session = requireSession(handle);
      if (typeof exportConsentToken !== 'string' || exportConsentToken.length === 0) {
        throw createError(ErrorCode.E_EXPORT_AUTH, { field: 'exportConsentToken', reason: 'missing' });
      }
      if (session.exportConsentToken !== exportConsentToken) {
        throw createError(ErrorCode.E_EXPORT_AUTH, { field: 'exportConsentToken', reason: 'mismatch', handle });
      }
      return packSecretKey({
        suiteId: session.suiteId,
        keyBytes: session.secretKey,
      });
    },

    getSession(handle) {
      return requireSession(handle);
    },

    hasSession(handle) {
      return sessions.has(handle);
    },

    clearSession,

    clearAllSessions() {
      for (const handle of Array.from(sessions.keys())) {
        clearSession(handle);
      }
    },
  };
}
