import { ErrorCode, createError } from '../crypto/errors.js';

export function resolveSignInputKind(payload) {
  const hasFile = payload?.file !== undefined && payload?.file !== null;
  const hasText = typeof payload?.text === 'string';

  if (hasFile && hasText) {
    throw createError(ErrorCode.E_WORKER_PROTOCOL, {
      field: 'file|text',
      reason: 'mutually_exclusive_inputs',
    });
  }
  if (!hasFile && !hasText) {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file|text' });
  }
  return hasFile ? 'file' : 'text';
}
