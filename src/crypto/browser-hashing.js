import { sha3_512 } from '@noble/hashes/sha3.js';
import { ErrorCode, createError } from './errors.js';
import { wipeBytes } from './bytes.js';
import { validateBytes } from './validate.js';
import { DEFAULT_HASH_CHUNK_SIZE, MAX_PAYLOAD_FILE_BYTES, assertFileSizeLimit, normalizeChunkSize } from './policy.js';

export async function hashFileSHA3512(file, { chunkSize = DEFAULT_HASH_CHUNK_SIZE, onProgress } = {}) {
  if (!file || typeof file.size !== 'number' || typeof file.slice !== 'function') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file' });
  }
  assertFileSizeLimit(file, MAX_PAYLOAD_FILE_BYTES);
  const effectiveChunkSize = normalizeChunkSize(chunkSize, DEFAULT_HASH_CHUNK_SIZE);

  const hasher = sha3_512.create();
  const total = file.size;

  if (total === 0) {
    if (typeof onProgress === 'function') onProgress(0, 0);
    return hasher.digest();
  }

  let offset = 0;
  while (offset < total) {
    const end = Math.min(offset + effectiveChunkSize, total);
    const chunk = file.slice(offset, end);
    const chunkBytes = new Uint8Array(await chunk.arrayBuffer());
    try {
      if (chunkBytes.length !== end - offset) throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'fileChunk' });
      hasher.update(chunkBytes);
    } finally {
      // Best-effort privacy hygiene for transient file copies. This cannot
      // erase browser/OS caches or copies retained by the JS engine.
      wipeBytes(chunkBytes);
    }
    offset = end;
    if (typeof onProgress === 'function') onProgress(offset, total);
  }

  return hasher.digest();
}

export function hashBytesSHA3512(bytes) {
  validateBytes(bytes, 'bytes', 0);
  return sha3_512(bytes);
}

