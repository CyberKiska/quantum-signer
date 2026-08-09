import { equalsBytes, wipeBytes } from './bytes.js';
import { ErrorCode, createError } from './errors.js';
import { MAX_KEY_FILE_BYTES, assertBytesLimit, assertMaxLength } from './policy.js';
import { utf8ToBytesStrict } from './text-encoding.js';

export const PROTECTED_SECRET_KEY_MAGIC = Uint8Array.of(0x50, 0x51, 0x53, 0x45); // PQSE
export const PROTECTED_SECRET_KEY_VERSION_MAJOR = 1;
export const PROTECTED_SECRET_KEY_VERSION_MINOR = 0;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

const KDF_PBKDF2_HMAC_SHA512 = 0x01;
const AEAD_AES_256_GCM = 0x01;
const HEADER_LENGTH = 22;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const GCM_TAG_LENGTH_BYTES = 16;
const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 5_000_000;
const MIN_NEW_PASSPHRASE_CODE_POINTS = 12;
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

async function deriveAesKey(cryptoApi, passphraseBytes, salt, iterations, usages) {
  const keyMaterial = await cryptoApi.subtle.importKey(
    'raw',
    passphraseBytes,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return cryptoApi.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-512',
      salt,
      iterations,
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

function createHeader({ suiteId, iterations, ciphertextLength }) {
  if (!Number.isInteger(suiteId) || suiteId <= 0 || suiteId > 0xff) {
    throw createError(ErrorCode.E_SUITE_UNSUPPORTED, { suiteId });
  }
  assertIterations(iterations);
  assertMaxLength(ciphertextLength, MAX_KEY_FILE_BYTES + GCM_TAG_LENGTH_BYTES, 'ciphertextLength');

  const header = new Uint8Array(HEADER_LENGTH);
  const view = new DataView(header.buffer);
  header.set(PROTECTED_SECRET_KEY_MAGIC, 0);
  header[4] = PROTECTED_SECRET_KEY_VERSION_MAJOR;
  header[5] = PROTECTED_SECRET_KEY_VERSION_MINOR;
  header[6] = suiteId;
  header[7] = KDF_PBKDF2_HMAC_SHA512;
  header[8] = AEAD_AES_256_GCM;
  header[9] = 0;
  view.setUint32(10, iterations, true);
  header[14] = SALT_LENGTH;
  header[15] = IV_LENGTH;
  view.setUint16(16, 0, true);
  view.setUint32(18, ciphertextLength, true);
  return header;
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

export async function encryptSecretKeyFile({
  suiteId,
  secretKeyFile,
  passphrase,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
}) {
  assertBytesLimit(secretKeyFile, MAX_KEY_FILE_BYTES, 'secretKeyFile');
  const cryptoApi = requireWebCrypto();
  const passphraseBytes = encodePassphrase(passphrase, { forEncryption: true });
  const salt = new Uint8Array(SALT_LENGTH);
  const iv = new Uint8Array(IV_LENGTH);
  let header;
  let aad;
  let ciphertext;

  try {
    cryptoApi.getRandomValues(salt);
    cryptoApi.getRandomValues(iv);
    header = createHeader({
      suiteId,
      iterations,
      ciphertextLength: secretKeyFile.length + GCM_TAG_LENGTH_BYTES,
    });
    aad = concatBytes(header, salt, iv);
    const aesKey = await deriveAesKey(cryptoApi, passphraseBytes, salt, iterations, ['encrypt']);
    ciphertext = new Uint8Array(
      await cryptoApi.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        secretKeyFile
      )
    );
    if (ciphertext.length !== secretKeyFile.length + GCM_TAG_LENGTH_BYTES) {
      throw createError(ErrorCode.E_INTERNAL, { reason: 'unexpected_aes_gcm_length' });
    }
    return concatBytes(aad, ciphertext);
  } catch (err) {
    if (typeof err?.code === 'string') throw err;
    throw createError(ErrorCode.E_KEY_PROTECTION_UNAVAILABLE);
  } finally {
    wipeBytes(passphraseBytes);
    wipeBytes(salt);
    wipeBytes(iv);
    wipeBytes(header);
    wipeBytes(aad);
    wipeBytes(ciphertext);
  }
}

export async function decryptSecretKeyFile(protectedFile, passphrase) {
  assertBytesLimit(protectedFile, MAX_KEY_FILE_BYTES, 'protectedSecretKeyFile');
  if (!isProtectedSecretKeyFile(protectedFile)) {
    throw createError(ErrorCode.E_FORMAT_MAGIC);
  }
  if (protectedFile.length < HEADER_LENGTH + SALT_LENGTH + IV_LENGTH + GCM_TAG_LENGTH_BYTES) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'protectedSecretKeyFile' });
  }

  const header = protectedFile.subarray(0, HEADER_LENGTH);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const versionMajor = header[4];
  const versionMinor = header[5];
  if (
    versionMajor !== PROTECTED_SECRET_KEY_VERSION_MAJOR ||
    versionMinor > PROTECTED_SECRET_KEY_VERSION_MINOR
  ) {
    throw createError(ErrorCode.E_FORMAT_VERSION, { versionMajor, versionMinor });
  }
  const suiteId = header[6];
  if (
    header[7] !== KDF_PBKDF2_HMAC_SHA512 ||
    header[8] !== AEAD_AES_256_GCM ||
    header[9] !== 0 ||
    header[14] !== SALT_LENGTH ||
    header[15] !== IV_LENGTH ||
    view.getUint16(16, true) !== 0
  ) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'protectedSecretKeyHeader' });
  }

  const iterations = view.getUint32(10, true);
  assertIterations(iterations);
  const ciphertextLength = view.getUint32(18, true);
  if (ciphertextLength < GCM_TAG_LENGTH_BYTES) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: 'ciphertextLength' });
  }
  const expectedLength = HEADER_LENGTH + SALT_LENGTH + IV_LENGTH + ciphertextLength;
  if (protectedFile.length !== expectedLength) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, {
      field: 'protectedSecretKeyFile',
      expected: expectedLength,
      actual: protectedFile.length,
    });
  }

  const cryptoApi = requireWebCrypto();
  const passphraseBytes = encodePassphrase(passphrase, { forEncryption: false });
  const saltOffset = HEADER_LENGTH;
  const ivOffset = saltOffset + SALT_LENGTH;
  const ciphertextOffset = ivOffset + IV_LENGTH;
  const salt = protectedFile.subarray(saltOffset, ivOffset);
  const iv = protectedFile.subarray(ivOffset, ciphertextOffset);
  const aad = protectedFile.subarray(0, ciphertextOffset);
  const ciphertext = protectedFile.subarray(ciphertextOffset);

  try {
    const aesKey = await deriveAesKey(cryptoApi, passphraseBytes, salt, iterations, ['decrypt']);
    const plaintext = new Uint8Array(
      await cryptoApi.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        aesKey,
        ciphertext
      )
    );
    assertBytesLimit(plaintext, MAX_KEY_FILE_BYTES, 'secretKeyFile');
    return { suiteId, secretKeyFile: plaintext };
  } catch (err) {
    if (err?.code === ErrorCode.E_INPUT_TOO_LARGE || err?.code === ErrorCode.E_FORMAT_LENGTH) throw err;
    throw createError(ErrorCode.E_KEY_DECRYPT_FAILED);
  } finally {
    wipeBytes(passphraseBytes);
  }
}
