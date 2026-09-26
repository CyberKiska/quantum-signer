import { argon2 } from 'node:crypto';
import { promisify } from 'node:util';

// Node resolves this module (OpenSSL Argon2id); browser builds resolve browser-argon2.js.
const argon2Async = promisify(argon2);
export const argon2id = (params) => argon2Async('argon2id', params).then((tag) => new Uint8Array(tag));
