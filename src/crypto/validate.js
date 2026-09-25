import { ErrorCode, createError } from './errors.js';
import { HashAlgId, SuiteId } from '../formats/containers.js';

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

