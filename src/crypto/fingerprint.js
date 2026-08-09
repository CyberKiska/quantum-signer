import { sha3_256 } from '@noble/hashes/sha3.js';
import { ErrorCode, createError } from './errors.js';
import { bytesToHexLower } from '../formats/encoding.js';

function validateFingerprintInput(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'fingerprintInput' });
  }
}

export function computeFingerprintBytes(bytes) {
  validateFingerprintInput(bytes);
  return sha3_256(bytes);
}

export function computeFingerprint(bytes, size = 16) {
  validateFingerprintInput(bytes);
  const digest = computeFingerprintBytes(bytes);
  const take = Math.max(1, Math.min(size, digest.length));
  return bytesToHexLower(digest.subarray(0, take));
}

export function computeFingerprintHex(bytes) {
  return bytesToHexLower(computeFingerprintBytes(bytes));
}
