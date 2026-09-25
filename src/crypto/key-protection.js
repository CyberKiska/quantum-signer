// Password protection for local private-key files (native CLI only; the build
// forbids this module in browser bundles).
//
// PQSE 3 (current): Argon2id (RFC 9106, via node:crypto) -> AES-256-GCM
//   (SP 800-38D, WebCrypto). Plaintext: PKCS#8 DER (RFC 5958).
// PQSE 1/2 (read-only legacy, and explicit kdf: 'pbkdf2' for compatibility
//   tests): PBKDF2-HMAC-SHA-512 (SP 800-132 / RFC 8018) -> AES-256-GCM.
// The entire header, salt and IV are GCM additional data, so every parameter
// (suite, KDF, cost, lengths) is authenticated.
import { argon2 as argon2Callback } from 'node:crypto';
import { promisify } from 'node:util';
import { equalsBytes, wipeBytes } from './bytes.js';
import { ErrorCode, createError } from './errors.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit, assertMaxLength } from './policy.js';
import { utf8ToBytesStrict } from './text-encoding.js';

const argon2 = promisify(argon2Callback);

export const PROTECTED_SECRET_KEY_MAGIC = Uint8Array.of(0x50, 0x51, 0x53, 0x45); // PQSE
export const PROTECTED_SECRET_KEY_VERSION_MAJOR = 1;
export const PROTECTED_SECRET_KEY_VERSION_MINOR = 0;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
// Exceeds RFC 9106 section 4's second recommended option (64 MiB, t=3, p=4)
// while staying usable on ordinary workstations.
export const DEFAULT_ARGON2ID = Object.freeze({ memoryKiB: 262_144, passes: 3, parallelism: 4 });

const VERSION_PQSK_PBKDF2 = 1;
const VERSION_PKCS8_PBKDF2 = 2;
const VERSION_PKCS8_ARGON2ID = 3;
const KDF_PBKDF2_HMAC_SHA512 = 0x01;
const KDF_ARGON2ID = 0x02;
const AEAD_AES_256_GCM = 0x01;
const PBKDF2_HEADER_LENGTH = 22;
const ARGON2_HEADER_LENGTH = 26;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const GCM_TAG_LENGTH_BYTES = 16;
const AES_KEY_LENGTH = 32;
const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 5_000_000;
// Bounds on attacker-supplied Argon2id costs: at least the RFC 9106 second
// recommended option, at most 2 GiB / 10 passes / 16 lanes (resource limit).
const ARGON2_LIMITS = Object.freeze({
  memoryKiB: [65_536, 2_097_152], passes: [1, 10], parallelism: [1, 16],
});
// SP 800-63B-4 section 3.1.1.2: at least 15 characters for passwords used alone.
const MIN_NEW_PASSPHRASE_CODE_POINTS = 15;
const MAX_PASSPHRASE_BYTES = 1024;

function requireWebCrypto() {
  const cryptoApi = globalThis.crypto;
  if (
    !cryptoApi ||
    typeof cryptoApi.getRandomValues !== 'function' ||
    !cryptoApi.subtle ||
    typeof cryptoApi.subtle.importKey !== 'function'
  ) {
    throw createError(ErrorCode.E_KEY_PROTECTION_UNAVAILABLE);
  }
  return cryptoApi;
}

function encodePassphrase(passphrase, { forEncryption }) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw createError(ErrorCode.E_KEY_PASSPHRASE_REQUIRED);
  }
  if (passphrase.length > MAX_PASSPHRASE_BYTES) {
    throw createError(ErrorCode.E_KEY_PASSPHRASE_INVALID, { reason: 'too_long' });
  }
  if (forEncryption && Array.from(passphrase).length < MIN_NEW_PASSPHRASE_CODE_POINTS) {
    throw createError(ErrorCode.E_KEY_PASSPHRASE_INVALID, {
      reason: 'too_short',
      minCodePoints: MIN_NEW_PASSPHRASE_CODE_POINTS,
    });
  }

  let bytes;
  try {
    bytes = utf8ToBytesStrict(passphrase, 'passphrase');
  } catch (_err) {
    throw createError(ErrorCode.E_KEY_PASSPHRASE_INVALID, { reason: 'invalid_unicode' });
  }
  if (bytes.length > MAX_PASSPHRASE_BYTES) {
    wipeBytes(bytes);
    throw createError(ErrorCode.E_KEY_PASSPHRASE_INVALID, {
      reason: 'too_long',
      maxBytes: MAX_PASSPHRASE_BYTES,
    });
  }
  return bytes;
}

function assertIterations(iterations) {
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, {
      field: 'pbkdf2Iterations',
      min: MIN_PBKDF2_ITERATIONS,
      max: MAX_PBKDF2_ITERATIONS,
      actual: iterations,
    });
  }
}

function assertArgon2Params(params) {
  for (const [field, [min, max]] of Object.entries(ARGON2_LIMITS)) {
    const actual = params?.[field];
    if (!Number.isInteger(actual) || actual < min || actual > max) {
      throw createError(ErrorCode.E_FORMAT_LENGTH, { field: `argon2id.${field}`, min, max, actual });
    }
  }
  // RFC 9106 section 3.1: memory must be at least 8 * parallelism KiB.
  if (params.memoryKiB < 8 * params.parallelism) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'argon2id.memoryKiB', reason: 'below_8p' });
  }
}

// RFC 9106 section 5.3 Argon2id test vector, checked once before first use.
let argon2KatPassed = false;
async function assertArgon2Kat() {
  if (argon2KatPassed) return;
  const tag = await argon2('argon2id', {
    message: new Uint8Array(32).fill(1), nonce: new Uint8Array(16).fill(2), secret: new Uint8Array(8).fill(3),
    associatedData: new Uint8Array(12).fill(4), parallelism: 4, tagLength: 32, memory: 32, passes: 3,
  });
  if (Buffer.from(tag).toString('hex') !== '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659') {
    throw createError(ErrorCode.E_KEY_PROTECTION_UNAVAILABLE, { reason: 'argon2id_kat_failed' });
  }
  argon2KatPassed = true;
}

async function deriveAesKey(cryptoApi, passphraseBytes, salt, kdf, usages) {
  if (kdf.name === 'pbkdf2') {
    const keyMaterial = await cryptoApi.subtle.importKey('raw', passphraseBytes, 'PBKDF2', false, ['deriveKey']);
    return cryptoApi.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-512', salt, iterations: kdf.iterations },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      usages
    );
  }
  await assertArgon2Kat();
  const raw = new Uint8Array(await argon2('argon2id', {
    message: passphraseBytes, nonce: salt, parallelism: kdf.parallelism, tagLength: AES_KEY_LENGTH,
    memory: kdf.memoryKiB, passes: kdf.passes,
  }));
  try {
    return await cryptoApi.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, usages);
  } finally {
    wipeBytes(raw);
  }
}

function createHeader({ suiteId, version, kdf, ciphertextLength }) {
  if (!Number.isInteger(suiteId) || suiteId <= 0 || suiteId > 0xff) {
    throw createError(ErrorCode.E_SUITE_UNSUPPORTED, { suiteId });
  }
  assertMaxLength(ciphertextLength, MAX_KEY_FILE_BYTES + GCM_TAG_LENGTH_BYTES, 'ciphertextLength');
  const argon = kdf.name === 'argon2id';
  const header = new Uint8Array(argon ? ARGON2_HEADER_LENGTH : PBKDF2_HEADER_LENGTH);
  const view = new DataView(header.buffer);
  header.set(PROTECTED_SECRET_KEY_MAGIC, 0);
  header[4] = version;
  header[5] = PROTECTED_SECRET_KEY_VERSION_MINOR;
  header[6] = suiteId;
  header[7] = argon ? KDF_ARGON2ID : KDF_PBKDF2_HMAC_SHA512;
  header[8] = AEAD_AES_256_GCM;
  header[9] = 0;
  if (argon) {
    view.setUint32(10, kdf.memoryKiB, true);
    view.setUint32(14, kdf.passes, true);
    header[18] = kdf.parallelism;
    header[19] = SALT_LENGTH;
    header[20] = IV_LENGTH;
    header[21] = 0;
    view.setUint32(22, ciphertextLength, true);
  } else {
    view.setUint32(10, kdf.iterations, true);
    header[14] = SALT_LENGTH;
    header[15] = IV_LENGTH;
    view.setUint16(16, 0, true);
    view.setUint32(18, ciphertextLength, true);
  }
  return header;
}

// Returns { version, suiteId, kdf, headerLength, ciphertextLength } or throws.
function parseHeader(file) {
  const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const version = file[4];
  if (
    ![VERSION_PQSK_PBKDF2, VERSION_PKCS8_PBKDF2, VERSION_PKCS8_ARGON2ID].includes(version) ||
    file[5] > PROTECTED_SECRET_KEY_VERSION_MINOR
  ) {
    throw createError(ErrorCode.E_FORMAT_VERSION, { versionMajor: version, versionMinor: file[5] });
  }
  const argon = version === VERSION_PKCS8_ARGON2ID;
  const headerLength = argon ? ARGON2_HEADER_LENGTH : PBKDF2_HEADER_LENGTH;
  if (file.length < headerLength + SALT_LENGTH + IV_LENGTH + GCM_TAG_LENGTH_BYTES) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'protectedSecretKeyFile' });
  }
  const common = file[7] === (argon ? KDF_ARGON2ID : KDF_PBKDF2_HMAC_SHA512) && file[8] === AEAD_AES_256_GCM && file[9] === 0;
  const layout = argon
    ? file[19] === SALT_LENGTH && file[20] === IV_LENGTH && file[21] === 0
    : file[14] === SALT_LENGTH && file[15] === IV_LENGTH && view.getUint16(16, true) === 0;
  if (!common || !layout) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'protectedSecretKeyHeader' });
  }
  const kdf = argon
    ? { name: 'argon2id', memoryKiB: view.getUint32(10, true), passes: view.getUint32(14, true), parallelism: file[18] }
    : { name: 'pbkdf2', iterations: view.getUint32(10, true) };
  if (argon) assertArgon2Params(kdf);
  else assertIterations(kdf.iterations);
  const ciphertextLength = view.getUint32(headerLength - 4, true);
  if (ciphertextLength < GCM_TAG_LENGTH_BYTES) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'ciphertextLength' });
  }
  return { version, suiteId: file[6], kdf, headerLength, ciphertextLength };
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function isProtectedSecretKeyFile(bytes) {
  return bytes instanceof Uint8Array &&
    bytes.length >= PROTECTED_SECRET_KEY_MAGIC.length &&
    equalsBytes(bytes.subarray(0, PROTECTED_SECRET_KEY_MAGIC.length), PROTECTED_SECRET_KEY_MAGIC);
}

// New PKCS#8 keys use PQSE 3 / Argon2id. kdf: 'pbkdf2' (PQSE 1/2) exists only
// for legacy-compatibility tests; the CLI never requests it.
export async function encryptSecretKeyFile({
  suiteId,
  secretKeyFile,
  passphrase,
  keyFormat = 'pqsk',
  kdf = keyFormat === 'pkcs8' ? 'argon2id' : 'pbkdf2',
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  argon2id = DEFAULT_ARGON2ID,
}) {
  assertBytesLimit(secretKeyFile, MAX_KEY_FILE_BYTES, 'secretKeyFile');
  if (!['pqsk', 'pkcs8'].includes(keyFormat)) throw new TypeError('Unsupported protected key format');
  if (!['pbkdf2', 'argon2id'].includes(kdf) || (kdf === 'argon2id' && keyFormat !== 'pkcs8')) {
    throw new TypeError('Unsupported protected key KDF');
  }
  const kdfParams = kdf === 'argon2id' ? { name: kdf, ...argon2id } : { name: kdf, iterations };
  if (kdf === 'argon2id') assertArgon2Params(kdfParams);
  else assertIterations(iterations);
  const version = kdf === 'argon2id'
    ? VERSION_PKCS8_ARGON2ID
    : keyFormat === 'pkcs8' ? VERSION_PKCS8_PBKDF2 : VERSION_PQSK_PBKDF2;
  const cryptoApi = requireWebCrypto();
  const passphraseBytes = encodePassphrase(passphrase, { forEncryption: true });
  const plaintext = Uint8Array.from(secretKeyFile);
  const salt = new Uint8Array(SALT_LENGTH);
  const iv = new Uint8Array(IV_LENGTH);
  let header;
  let aad;
  let ciphertext;

  try {
    // Independent CSPRNG requests; a fresh salt gives a fresh AES key per file,
    // so the random 96-bit IV is never reused under one key (SP 800-38D 8.2).
    cryptoApi.getRandomValues(salt);
    cryptoApi.getRandomValues(iv);
    header = createHeader({ suiteId, version, kdf: kdfParams, ciphertextLength: plaintext.length + GCM_TAG_LENGTH_BYTES });
    aad = concatBytes(header, salt, iv);
    const aesKey = await deriveAesKey(cryptoApi, passphraseBytes, salt, kdfParams, ['encrypt']);
    ciphertext = new Uint8Array(
      await cryptoApi.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        plaintext
      )
    );
    if (ciphertext.length !== plaintext.length + GCM_TAG_LENGTH_BYTES) {
      throw createError(ErrorCode.E_INTERNAL, { reason: 'unexpected_aes_gcm_length' });
    }
    return concatBytes(aad, ciphertext);
  } catch (err) {
    if (typeof err?.code === 'string' && err.code.startsWith('E_')) throw err;
    throw createError(ErrorCode.E_KEY_PROTECTION_UNAVAILABLE);
  } finally {
    wipeBytes(passphraseBytes);
    wipeBytes(plaintext);
    wipeBytes(salt);
    wipeBytes(iv);
    wipeBytes(header);
    wipeBytes(aad);
    wipeBytes(ciphertext);
  }
}

// Reports the stored KDF without a password, so callers can recommend migration.
export function describeProtectedSecretKeyFile(protectedFile) {
  if (!isProtectedSecretKeyFile(protectedFile)) throw createError(ErrorCode.E_FORMAT_MAGIC);
  const { version, suiteId, kdf } = parseHeader(protectedFile);
  return { version, suiteId, kdf: kdf.name, legacy: version !== VERSION_PKCS8_ARGON2ID };
}

export async function decryptSecretKeyFile(protectedFile, passphrase) {
  assertBytesLimit(protectedFile, MAX_KEY_FILE_BYTES, 'protectedSecretKeyFile');
  // Take a snapshot before the first await: caller mutation must not replace
  // the authenticated ciphertext while the password derivation is in flight.
  protectedFile = Uint8Array.from(protectedFile);
  if (!isProtectedSecretKeyFile(protectedFile)) {
    throw createError(ErrorCode.E_FORMAT_MAGIC);
  }
  if (protectedFile.length < PBKDF2_HEADER_LENGTH + SALT_LENGTH + IV_LENGTH + GCM_TAG_LENGTH_BYTES) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'protectedSecretKeyFile' });
  }
  const { version, suiteId, kdf, headerLength, ciphertextLength } = parseHeader(protectedFile);
  const expectedLength = headerLength + SALT_LENGTH + IV_LENGTH + ciphertextLength;
  if (protectedFile.length !== expectedLength) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, {
      field: 'protectedSecretKeyFile',
      expected: expectedLength,
      actual: protectedFile.length,
    });
  }

  const cryptoApi = requireWebCrypto();
  const passphraseBytes = encodePassphrase(passphrase, { forEncryption: false });
  const saltOffset = headerLength;
  const ivOffset = saltOffset + SALT_LENGTH;
  const ciphertextOffset = ivOffset + IV_LENGTH;
  const salt = protectedFile.subarray(saltOffset, ivOffset);
  const iv = protectedFile.subarray(ivOffset, ciphertextOffset);
  const aad = protectedFile.subarray(0, ciphertextOffset);
  const ciphertext = protectedFile.subarray(ciphertextOffset);

  try {
    const aesKey = await deriveAesKey(cryptoApi, passphraseBytes, salt, kdf, ['decrypt']);
    const plaintext = new Uint8Array(
      await cryptoApi.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext
      )
    );
    assertBytesLimit(plaintext, MAX_KEY_FILE_BYTES, 'secretKeyFile');
    return {
      suiteId,
      secretKeyFile: plaintext,
      keyFormat: version === VERSION_PQSK_PBKDF2 ? 'pqsk' : 'pkcs8',
      kdf: kdf.name,
      legacy: version !== VERSION_PKCS8_ARGON2ID,
    };
  } catch (err) {
    if (err?.code === ErrorCode.E_INPUT_TOO_LARGE || err?.code === ErrorCode.E_FORMAT_LENGTH ||
        err?.code === ErrorCode.E_KEY_PROTECTION_UNAVAILABLE) throw err;
    throw createError(ErrorCode.E_KEY_DECRYPT_FAILED);
  } finally {
    wipeBytes(passphraseBytes);
    wipeBytes(protectedFile);
  }
}
