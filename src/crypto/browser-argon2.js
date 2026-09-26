import { argon2idAsync } from '@noble/hashes/argon2.js';

// Web Crypto has no Argon2id in stable browsers; RFC 9106 via the pinned noble
// implementation, with node:crypto's parameter names.
export function argon2id({ message, nonce, memory, passes, parallelism, tagLength, secret, associatedData }) {
  return argon2idAsync(message, nonce, {
    m: memory, t: passes, p: parallelism, dkLen: tagLength, key: secret, personalization: associatedData,
    maxmem: 2 ** 32 - 1,
  });
}
