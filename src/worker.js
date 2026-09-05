import { hashBytesSHA3512, hashFileSHA3512 } from './crypto/browser-hashing.js';
import { ErrorCode, createError, normalizeError } from './crypto/errors.js';
import { MAX_PAYLOAD_FILE_BYTES, MAX_SIGNATURE_FILE_BYTES, MAX_TEXT_INPUT_BYTES,
  assertBytesLimit, assertFileSizeLimit, assertMaxLength } from './crypto/policy.js';
import { HashAlgId, getHashName, unpackSignatureV2 } from './formats/containers.js';
import { bytesToHexLower } from './formats/encoding.js';
import { validateRequired } from './crypto/validate.js';
import { runVerificationSelfTest } from './crypto/verification-selftest.js';
import { wipeBytes } from './crypto/bytes.js';
import { utf8ToBytesStrict } from './crypto/text-encoding.js';
import { finalizePayloadVerification } from './crypto/verify-policy.js';

export const WorkerMessageType = Object.freeze({
  HASH_FILE: 'HASH_FILE', HASH_TEXT: 'HASH_TEXT', VERIFY_FILE: 'VERIFY_FILE', VERIFY_TEXT: 'VERIFY_TEXT', SELFTEST: 'SELFTEST',
});
const Handlers = Object.freeze({ HASH_FILE: handleHashFile, HASH_TEXT: handleHashText,
  VERIFY_FILE: handleVerifyFile, VERIFY_TEXT: handleVerifyText, SELFTEST: handleSelfTest });
// Startup KATs use only public NIST fixtures. A failure latches this worker closed.
let healthy = false;
try { healthy = runVerificationSelfTest().ok; } catch { healthy = false; }
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
    const report = runVerificationSelfTest();
    healthy = healthy && report.ok;
    return { ...report, ok: healthy };
  } catch (error) { healthy = false; throw error; }
}
