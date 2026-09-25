import { sha3_256 } from '#crypto/hashes';
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

export function computeFingerprintHex(bytes) {
  return bytesToHexLower(computeFingerprintBytes(bytes));
}
