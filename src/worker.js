import { hashBytesSHA3512, hashFileSHA3512 } from './crypto/browser-hashing.js';
import { ErrorCode, createError, normalizeError } from './crypto/errors.js';
import { MAX_KEY_FILE_BYTES, MAX_PAYLOAD_FILE_BYTES, MAX_SIGNATURE_FILE_BYTES, MAX_TEXT_INPUT_BYTES,
  assertBytesLimit, assertFileSizeLimit, assertMaxLength } from './crypto/policy.js';
import { HashAlgId, getHashName, packPublicKey, unpackSecretKey, unpackSignatureV2 } from './formats/containers.js';
import { bytesToHexLower } from './formats/encoding.js';
import { validateRequired } from './crypto/validate.js';
import { runVerificationSelfTest } from './crypto/verification-selftest.js';
import { verifyBytes } from './crypto/browser-verification.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { equalsHex, wipeBytes } from './crypto/bytes.js';
import { utf8ToBytesStrict } from './crypto/text-encoding.js';
import { finalizePayloadVerification } from './crypto/verify-policy.js';
import { computeFingerprintHex } from './crypto/fingerprint.js';
import { createDetachedSignature } from './crypto/detached-signature.js';
import { decryptSecretKeyFile, encryptSecretKeyFile, isProtectedSecretKeyFile } from './crypto/key-protection.js';
import { generatePrivateKey, importPrivateKey, signMessage } from './crypto/browser-signing.js';

export const WorkerMessageType = Object.freeze({
  HASH_FILE: 'HASH_FILE', HASH_TEXT: 'HASH_TEXT', VERIFY_FILE: 'VERIFY_FILE', VERIFY_TEXT: 'VERIFY_TEXT', SELFTEST: 'SELFTEST',
  KEYGEN: 'KEYGEN', UNLOCK: 'UNLOCK', SIGN: 'SIGN',
});
const Handlers = Object.freeze({ HASH_FILE: handleHashFile, HASH_TEXT: handleHashText,
  VERIFY_FILE: handleVerifyFile, VERIFY_TEXT: handleVerifyText, SELFTEST: handleSelfTest,
  KEYGEN: handleKeygen, UNLOCK: handleUnlock, SIGN: handleSign });
// The only private key in this worker. It never crosses postMessage; the page
// locks it by terminating the worker, and a new KEYGEN/UNLOCK replaces it.
let activeKey = null;
// Startup KATs use only public NIST fixtures. A failure latches this worker closed.
let healthy = false;
const runKats = () => runVerificationSelfTest({ verifyBytes, sha3_512 });
try { healthy = runKats().ok; } catch { healthy = false; }
let busy = false;
self.onmessage = async (event) => {
  const request = event.data;
  const id = request?.id;
  const type = request?.type;
  let ownsRequest = false;
  try {
    if (!request || typeof request !== 'object' ||
        !((typeof id === 'string' && id.length > 0 && id.length <= 128) || (Number.isSafeInteger(id) && id > 0)) ||
        typeof type !== 'string' || !Object.hasOwn(Handlers, type)) {
      throw createError(ErrorCode.E_WORKER_PROTOCOL, { reason: 'unsupported_request' });
    }
    if (!healthy) throw createError(ErrorCode.E_INTERNAL);
    if (busy) throw createError(ErrorCode.E_WORKER_PROTOCOL, { reason: 'worker_busy' });
    busy = true; ownsRequest = true;
    const result = await Handlers[type](id, request.payload || {});
    postMessage({ id, type: 'RESULT', op: type, ok: true, result });
  } catch (err) {
    const normalized = normalizeError(err);
    postMessage({ id: id ?? null, type: 'ERROR', op: type ?? null, ok: false,
      code: normalized.code, message: normalized.message, details: normalized.details });
  } finally { if (ownsRequest) busy = false; }
};

function encodeUserText(text) {
  // UTF-8 cannot be shorter than the UTF-16 code-unit count. Reject huge strings
  // before the encoder allocates another potentially large buffer.
  assertMaxLength(text.length, MAX_TEXT_INPUT_BYTES, 'text');
  try { return utf8ToBytesStrict(text, 'text'); }
  catch { throw createError(ErrorCode.E_TEXT_ENCODING); }
}
function sendProgress(id, op, loaded, total) {
  postMessage({ id, type: 'PROGRESS', op, loaded, total, percent: total ? Math.round(loaded / total * 100) : 100 });
}

async function handleHashFile(id, payload) {
  validateRequired(payload.file, 'file');
  assertFileSizeLimit(payload.file, MAX_PAYLOAD_FILE_BYTES, 'file');
  const hashBytes = await hashFileSHA3512(payload.file, {
    chunkSize: payload.chunkSize,
    onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.HASH_FILE, loaded, total),
  });
  return {
    hashAlgId: HashAlgId.SHA3_512,
    hashAlgName: getHashName(HashAlgId.SHA3_512),
    hashHex: bytesToHexLower(hashBytes),
    hashBytes,
    inputLength: payload.file.size,
  };
}

async function handleHashText(_id, payload) {
  if (typeof payload.text !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'text' });
  }
  const textBytes = encodeUserText(payload.text);
  try {
    assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
    const hashBytes = hashBytesSHA3512(textBytes);
    return {
      hashAlgId: HashAlgId.SHA3_512,
      hashAlgName: getHashName(HashAlgId.SHA3_512),
      hashHex: bytesToHexLower(hashBytes),
      hashBytes,
      inputLength: textBytes.length,
    };
  } finally {
    wipeBytes(textBytes);
  }
}

async function handleVerifyFile(id, payload) {
  validateRequired(payload.file, 'file');
  validateRequired(payload.sigFile, 'sigFile');
  assertFileSizeLimit(payload.file, MAX_PAYLOAD_FILE_BYTES, 'file');
  assertBytesLimit(payload.sigFile, MAX_SIGNATURE_FILE_BYTES, 'sigFile');

  const parsedSig = unpackSignatureV2(payload.sigFile);
  const computedHash = await hashFileSHA3512(payload.file, {
    chunkSize: payload.chunkSize,
    onProgress: (loaded, total) => sendProgress(id, WorkerMessageType.VERIFY_FILE, loaded, total),
  });

  const computedHashHex = bytesToHexLower(computedHash);

  return {
    signatureProfileId: parsedSig.signatureProfileId,
    authDigestAlgId: parsedSig.authDigestAlgId,
    ...finalizePayloadVerification(parsedSig, payload.publicKeyFile ?? null, {
      inputKind: 'file',
      inputLength: Number(payload.file.size || 0),
      computedHashHex,
    }),
  };
}

async function handleVerifyText(_id, payload) {
  validateRequired(payload.sigFile, 'sigFile');
  if (typeof payload.text !== 'string') {
    throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'text' });
  }
  assertBytesLimit(payload.sigFile, MAX_SIGNATURE_FILE_BYTES, 'sigFile');

  const parsedSig = unpackSignatureV2(payload.sigFile);
  const textBytes = encodeUserText(payload.text);
  try {
    assertBytesLimit(textBytes, MAX_TEXT_INPUT_BYTES, 'text');
    const providedHashBytes = hashBytesSHA3512(textBytes);
    const providedHashHex = bytesToHexLower(providedHashBytes);

    return {
      signatureProfileId: parsedSig.signatureProfileId,
      authDigestAlgId: parsedSig.authDigestAlgId,
      ...finalizePayloadVerification(parsedSig, payload.publicKeyFile ?? null, {
        inputKind: 'text',
        inputLength: textBytes.length,
        providedHashHex,
      }),
    };
  } finally {
    wipeBytes(textBytes);
  }
}

function handleSelfTest() {
  try {
    const report = runKats();
    healthy = healthy && report.ok;
    return { ...report, ok: healthy };
  } catch (error) { healthy = false; throw error; }
}

function setActiveKey(key) {
  wipeBytes(activeKey?.secretKey);
  const fingerprintHex = computeFingerprintHex(key.publicKey);
  activeKey = { ...key, fingerprintHex };
  return { suiteId: key.suiteId, fingerprintHex, publicKeyFile: packPublicKey({ suiteId: key.suiteId, keyBytes: key.publicKey }) };
}

function requirePassphrase(passphrase) {
  if (typeof passphrase !== 'string') throw createError(ErrorCode.E_KEY_PASSPHRASE_REQUIRED);
  return passphrase;
}

// Encrypted PQSE 3 output only; the plaintext PKCS#8 is wiped before returning.
async function handleKeygen(_id, payload) {
  const passphrase = requirePassphrase(payload.passphrase);
  const { key, pkcs8 } = await generatePrivateKey(payload.suiteId);
  try {
    const secretKeyFile = await encryptSecretKeyFile({ suiteId: key.suiteId, secretKeyFile: pkcs8, passphrase, keyFormat: 'pkcs8' });
    return { ...setActiveKey(key), secretKeyFile };
  } catch (error) { wipeBytes(key.secretKey); throw error; }
  finally { wipeBytes(pkcs8); }
}

// Loads PQSE 1/2/3 or legacy plaintext PQSK, as the CLI does.
async function handleUnlock(_id, payload) {
  const file = payload.secretKeyFile;
  assertBytesLimit(file, MAX_KEY_FILE_BYTES, 'secretKeyFile');
  const opened = isProtectedSecretKeyFile(file)
    ? await decryptSecretKeyFile(file, requirePassphrase(payload.passphrase))
    : { keyFormat: 'pqsk', legacy: true, secretKeyFile: Uint8Array.from(file) };
  let legacyKey;
  try {
    if (opened.keyFormat === 'pkcs8') {
      return { ...setActiveKey(await importPrivateKey(opened.suiteId, opened.secretKeyFile, 'pkcs8')), legacy: opened.legacy };
    }
    legacyKey = unpackSecretKey(opened.secretKeyFile);
    if (opened.suiteId !== undefined && legacyKey.suiteId !== opened.suiteId) throw createError(ErrorCode.E_KEY_SUITE_MISMATCH);
    return { ...setActiveKey(await importPrivateKey(legacyKey.suiteId, legacyKey.keyBytes, 'raw')), legacy: true };
  } finally { wipeBytes(opened.secretKeyFile); wipeBytes(legacyKey?.keyBytes); }
}

// Signs only the digest and signer the page reviewed (CLI --expect-sha3-512).
async function handleSign(id, payload) {
  const { expectedDigestHex, expectedFingerprintHex } = payload;
  if (typeof expectedDigestHex !== 'string' || !/^[0-9a-f]{128}$/u.test(expectedDigestHex)) {
    throw createError(ErrorCode.E_HASH_HEX_INVALID);
  }
  const key = activeKey;
  if (!key) throw createError(ErrorCode.E_SESSION_MISSING);
  if (typeof expectedFingerprintHex !== 'string' || !equalsHex(expectedFingerprintHex, key.fingerprintHex)) {
    throw createError(ErrorCode.E_SESSION_MISSING, { reason: 'signer_changed' });
  }
  const hasText = typeof payload.text === 'string';
  if (hasText === (payload.file !== undefined)) throw createError(ErrorCode.E_INPUT_REQUIRED, { field: 'file|text' });
  const hashed = hasText ? await handleHashText(id, payload) : await handleHashFile(id, payload);
  if (!equalsHex(hashed.hashHex, expectedDigestHex)) {
    throw createError(ErrorCode.E_FILE_HASH_MISMATCH, { reason: 'reviewed_digest' });
  }
  const signatureFile = createDetachedSignature({
    suiteId: key.suiteId, publicKey: key.publicKey, payloadDigest: hashed.hashBytes,
    sign: (message, contextBytes) => signMessage({ ...key, message, contextBytes }),
  });
  return {
    suiteId: key.suiteId, fingerprintHex: key.fingerprintHex, hashHex: hashed.hashHex,
    inputLength: hashed.inputLength, signatureFile,
  };
}
