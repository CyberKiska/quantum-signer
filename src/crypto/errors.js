export const ErrorCode = Object.freeze({
  E_INPUT_REQUIRED: 'E_INPUT_REQUIRED',
  E_INPUT_TOO_LARGE: 'E_INPUT_TOO_LARGE',
  E_TEXT_ENCODING: 'E_TEXT_ENCODING',
  E_HASH_HEX_INVALID: 'E_HASH_HEX_INVALID',
  E_FORMAT_MAGIC: 'E_FORMAT_MAGIC',
  E_FORMAT_VERSION: 'E_FORMAT_VERSION',
  E_FORMAT_LENGTH: 'E_FORMAT_LENGTH',
  E_FORMAT_FLAGS: 'E_FORMAT_FLAGS',
  E_FORMAT_TLV: 'E_FORMAT_TLV',
  E_FORMAT_CRC32: 'E_FORMAT_CRC32',
  E_SUITE_UNSUPPORTED: 'E_SUITE_UNSUPPORTED',
  E_HASH_UNSUPPORTED: 'E_HASH_UNSUPPORTED',
  E_KEY_SUITE_MISMATCH: 'E_KEY_SUITE_MISMATCH',
  E_KEY_CONSISTENCY: 'E_KEY_CONSISTENCY',
  E_SESSION_LIMIT: 'E_SESSION_LIMIT',
  E_SESSION_MISSING: 'E_SESSION_MISSING',
  E_EXPORT_AUTH: 'E_EXPORT_AUTH',
  E_SIGN_SELF_VERIFY: 'E_SIGN_SELF_VERIFY',
  E_SIGNATURE_INVALID: 'E_SIGNATURE_INVALID',
  E_SIGNER_BINDING_MISMATCH: 'E_SIGNER_BINDING_MISMATCH',
  E_FILE_HASH_MISMATCH: 'E_FILE_HASH_MISMATCH',
  E_WORKER_PROTOCOL: 'E_WORKER_PROTOCOL',
  E_INTERNAL: 'E_INTERNAL',
});

const MESSAGES = {
  [ErrorCode.E_INPUT_REQUIRED]: 'Required input is missing.',
  [ErrorCode.E_INPUT_TOO_LARGE]: 'Input exceeds the configured size limit.',
  [ErrorCode.E_TEXT_ENCODING]: 'Text contains invalid Unicode and cannot be encoded canonically.',
  [ErrorCode.E_HASH_HEX_INVALID]: 'Invalid SHA3-512 hash format (expected 128 hex chars).',
  [ErrorCode.E_FORMAT_MAGIC]: 'Invalid file magic header.',
  [ErrorCode.E_FORMAT_VERSION]: 'Unsupported file format version.',
  [ErrorCode.E_FORMAT_LENGTH]: 'Invalid or corrupted file length fields.',
  [ErrorCode.E_FORMAT_FLAGS]: 'Invalid format flags or reserved bits.',
  [ErrorCode.E_FORMAT_TLV]: 'Invalid metadata TLV structure.',
  [ErrorCode.E_FORMAT_CRC32]: 'CRC32 mismatch (file likely corrupted).',
  [ErrorCode.E_SUITE_UNSUPPORTED]: 'Unsupported cryptographic suite.',
  [ErrorCode.E_HASH_UNSUPPORTED]: 'Unsupported hash algorithm.',
  [ErrorCode.E_KEY_SUITE_MISMATCH]: 'Key suite does not match signature suite.',
  [ErrorCode.E_KEY_CONSISTENCY]: 'Private key failed pairwise consistency validation.',
  [ErrorCode.E_SESSION_LIMIT]: 'Secret-session capacity reached; clear an existing session and retry.',
  [ErrorCode.E_SESSION_MISSING]: 'Secret session not found or already cleared.',
  [ErrorCode.E_EXPORT_AUTH]: 'Secret export authorization failed.',
  [ErrorCode.E_SIGN_SELF_VERIFY]: 'Generated signature failed self-verification; output was discarded.',
  [ErrorCode.E_SIGNATURE_INVALID]: 'Signature verification failed.',
  [ErrorCode.E_SIGNER_BINDING_MISMATCH]:
    'Loaded public key does not match the signer public key authenticated by the signature container.',
  [ErrorCode.E_FILE_HASH_MISMATCH]: 'Provided file/hash does not match signed file hash.',
  [ErrorCode.E_WORKER_PROTOCOL]: 'Worker protocol error.',
  [ErrorCode.E_INTERNAL]: 'Internal error.',
};

export class AppError extends Error {
  constructor(code, message, details) {
    super(message || code);
    this.name = 'AppError';
    this.code = code;
    this.details = details;
  }
}

export function createError(code, details, locale = 'en', messageOverride = '') {
  const message = messageOverride || toErrorMessage(code, locale);
  return new AppError(code, message, details);
}

export function toErrorMessage(code) {
  return MESSAGES[code] || MESSAGES[ErrorCode.E_INTERNAL];
}

export function normalizeError(err, locale = 'en') {
  if (err instanceof AppError) {
    return {
      code: err.code,
      // Only return catalogued messages across the worker boundary. Custom or
      // dependency-provided exception text can disclose internal state.
      message: toErrorMessage(err.code, locale),
      details: err.code === ErrorCode.E_INTERNAL ? null : err.details || null,
    };
  }
  return {
    code: ErrorCode.E_INTERNAL,
    message: toErrorMessage(ErrorCode.E_INTERNAL, locale),
    details: null,
  };
}
