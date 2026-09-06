import { createHash } from 'node:crypto';

// Node resolves this module; browser builds resolve the pinned SHA-3 implementation.
export const sha3_256 = (bytes) => new Uint8Array(createHash('sha3-256').update(bytes).digest());
export const sha3_512 = (bytes) => new Uint8Array(createHash('sha3-512').update(bytes).digest());
