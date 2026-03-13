import { ErrorCode, createError } from './errors.js';

export const MAX_CONTEXT_BYTES = 255;
export const DEFAULT_HASH_CHUNK_SIZE = 4 * 1024 * 1024;
export const MAX_HASH_CHUNK_SIZE = 16 * 1024 * 1024;

export const MAX_PAYLOAD_FILE_BYTES = 1024 * 1024 * 1024;
export const MAX_TEXT_INPUT_BYTES = 8 * 1024 * 1024;

export const MAX_SIGNATURE_BYTES = 64 * 1024;
export const MAX_AUTH_METADATA_BYTES = 8 * 1024;
export const MAX_DISPLAY_METADATA_BYTES = 4 * 1024;
export const MAX_SIGNATURE_FILE_BYTES = 128 * 1024;

export const MAX_KEY_BYTES = 16 * 1024;
export const MAX_KEY_FILE_BYTES = 32 * 1024;

export function assertMaxLength(actual, max, field, code = ErrorCode.E_INPUT_TOO_LARGE) {
  if (!Number.isInteger(actual) || actual < 0) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field, actual, reason: 'invalid_length' });
  }
  if (actual > max) {
    throw createError(code, { field, max, actual });
  }
}

export function assertBytesLimit(bytes, max, field, code = ErrorCode.E_INPUT_TOO_LARGE) {
  if (!(bytes instanceof Uint8Array)) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field, expected: 'Uint8Array' });
  }
  assertMaxLength(bytes.length, max, field, code);
}

export function assertFileSizeLimit(file, max, field = 'file') {
  const actual = Number(file?.size);
  if (!Number.isFinite(actual) || actual < 0) {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field });
  }
  assertMaxLength(actual, max, field, ErrorCode.E_INPUT_TOO_LARGE);
}

export function normalizeChunkSize(chunkSize, fallback = DEFAULT_HASH_CHUNK_SIZE) {
  if (chunkSize === undefined || chunkSize === null) return fallback;
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'chunkSize', actual: chunkSize });
  }
  assertMaxLength(chunkSize, MAX_HASH_CHUNK_SIZE, 'chunkSize', ErrorCode.E_INPUT_TOO_LARGE);
  return chunkSize;
}
