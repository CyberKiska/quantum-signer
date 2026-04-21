import { ErrorCode, createError } from './errors.js';
import { normalizeCanonicalUtcIso8601 } from './time.js';
import {
  FILE_HASH_LENGTH,
  KEY_FORMAT_VERSION_MAJOR,
  HASH_NAMES,
  HashAlgId,
  SUITE_NAMES,
  SuiteId,
} from '../formats/containers.js';

const HASH_HEX_RE = /^[0-9a-fA-F]{128}$/;

export function assertCondition(condition, code, details) {
  if (!condition) {
    throw createError(code, details);
  }
}

export function validateRequired(value, field) {
  const ok = !(value === null || value === undefined || value === '');
  assertCondition(ok, ErrorCode.E_INPUT_REQUIRED, { field });
}

export function validateBytes(value, field, minLength = 1) {
  assertCondition(value instanceof Uint8Array, ErrorCode.E_FORMAT_LENGTH, { field, expected: 'Uint8Array' });
  assertCondition(value.length >= minLength, ErrorCode.E_FORMAT_LENGTH, {
    field,
    minLength,
    actual: value.length,
  });
}

export function validateHashHex(hashHex) {
  validateRequired(hashHex, 'hashHex');
  assertCondition(typeof hashHex === 'string' && HASH_HEX_RE.test(hashHex), ErrorCode.E_HASH_HEX_INVALID, {
    hashHex,
  });
  return hashHex.toLowerCase();
}

export function validateFileHashBytes(fileHash) {
  validateBytes(fileHash, 'fileHash', FILE_HASH_LENGTH);
  assertCondition(fileHash.length === FILE_HASH_LENGTH, ErrorCode.E_FORMAT_LENGTH, {
    field: 'fileHash',
    expected: FILE_HASH_LENGTH,
    actual: fileHash.length,
  });
}

export function validateSuiteId(suiteId) {
  const supported = Object.values(SuiteId).includes(suiteId);
  assertCondition(supported, ErrorCode.E_SUITE_UNSUPPORTED, { suiteId });
}

export function validateHashAlgId(hashAlgId) {
  assertCondition(hashAlgId === HashAlgId.SHA3_512, ErrorCode.E_HASH_UNSUPPORTED, { hashAlgId });
}

export function validateSignatureAndKeySuites(sigSuiteId, keySuiteId) {
  assertCondition(sigSuiteId === keySuiteId, ErrorCode.E_KEY_SUITE_MISMATCH, {
    signatureSuite: sigSuiteId,
    keySuite: keySuiteId,
  });
}

export function validateVersionMajor(versionMajor) {
  assertCondition(versionMajor === KEY_FORMAT_VERSION_MAJOR, ErrorCode.E_FORMAT_VERSION, {
    versionMajor,
    expectedMajor: KEY_FORMAT_VERSION_MAJOR,
  });
}

export function ensureExpectedLength(actual, expected, field) {
  assertCondition(actual === expected, ErrorCode.E_FORMAT_LENGTH, {
    field,
    expected,
    actual,
  });
}

function normalizeCreatedAt(value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    try {
      return normalizeCanonicalUtcIso8601(trimmed);
    } catch (_err) {
      throw createError(ErrorCode.E_FORMAT_TLV, { field: 'createdAt', reason: 'invalid_iso8601' });
    }
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    const seconds = Number(value);
    if (!Number.isFinite(seconds)) {
      throw createError(ErrorCode.E_FORMAT_TLV, { field: 'createdAt', reason: 'invalid_epoch' });
    }
    return new Date(Math.trunc(seconds) * 1000).toISOString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  throw createError(ErrorCode.E_FORMAT_TLV, { field: 'createdAt', reason: 'invalid_type' });
}

export function normalizeMetadata(metadata = {}) {
  const out = {};
  if (typeof metadata.filename === 'string') {
    const trimmed = metadata.filename.trim();
    if (trimmed.length > 0) out.filename = trimmed;
  }
  if (metadata.filesize !== undefined && metadata.filesize !== null) {
    out.filesize = typeof metadata.filesize === 'bigint' ? metadata.filesize : BigInt(metadata.filesize);
  }
  const normalizedCreatedAt = normalizeCreatedAt(metadata.createdAt);
  if (normalizedCreatedAt) {
    out.createdAt = normalizedCreatedAt;
  }
  return out;
}

export function suiteLabel(suiteId) {
  return SUITE_NAMES[suiteId] || `Unknown(${suiteId})`;
}

export function hashLabel(hashAlgId) {
  return HASH_NAMES[hashAlgId] || `Unknown(${hashAlgId})`;
}
