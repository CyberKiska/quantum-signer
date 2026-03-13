import { sha3_256 } from '@noble/hashes/sha3.js';
import { ErrorCode, createError } from '../crypto/errors.js';
import { equalsBytes } from '../crypto/bytes.js';
import {
  MAX_AUTH_METADATA_BYTES,
  MAX_CONTEXT_BYTES,
  MAX_DISPLAY_METADATA_BYTES,
  MAX_KEY_BYTES,
  MAX_KEY_FILE_BYTES,
  MAX_SIGNATURE_BYTES,
  MAX_SIGNATURE_FILE_BYTES,
  assertBytesLimit,
  assertMaxLength,
} from '../crypto/policy.js';
import { bytesToHexLower, bytesToUtf8, utf8ToBytes } from './encoding.js';

export const KEY_FORMAT_VERSION_MAJOR = 1;
export const KEY_FORMAT_VERSION_MINOR = 1;

export const QSIG_FORMAT_VERSION_MAJOR = 2;
export const QSIG_FORMAT_VERSION_MINOR = 0;
export const QSIG_TBS_VERSION_MAJOR = 2;
export const QSIG_TBS_VERSION_MINOR = 0;

export const MAGIC_SIG = utf8ToBytes('PQSG');
export const MAGIC_PQPK = utf8ToBytes('PQPK');
export const MAGIC_PQSK = utf8ToBytes('PQSK');
export const MAGIC_TBS = utf8ToBytes('QSTB');

export const SuiteId = Object.freeze({
  ML_DSA_44: 0x01,
  ML_DSA_65: 0x02,
  ML_DSA_87: 0x03,
  SLH_DSA_SHAKE_128S: 0x11,
  SLH_DSA_SHAKE_192S: 0x12,
  SLH_DSA_SHAKE_256S: 0x13,
});

export const HashAlgId = Object.freeze({
  SHA3_512: 0x01,
});

export const FingerprintAlgId = Object.freeze({
  SHA3_256: 0x01,
});

export const SignatureProfileId = Object.freeze({
  PQ_DETACHED_PURE_CONTEXT_V2: 0x01,
});

export const AuthDigestAlgId = Object.freeze({
  SHA3_256: 0x01,
});

export const SUITE_NAMES = Object.freeze({
  [SuiteId.ML_DSA_44]: 'ML-DSA-44',
  [SuiteId.ML_DSA_65]: 'ML-DSA-65',
  [SuiteId.ML_DSA_87]: 'ML-DSA-87',
  [SuiteId.SLH_DSA_SHAKE_128S]: 'SLH-DSA-SHAKE-128s',
  [SuiteId.SLH_DSA_SHAKE_192S]: 'SLH-DSA-SHAKE-192s',
  [SuiteId.SLH_DSA_SHAKE_256S]: 'SLH-DSA-SHAKE-256s',
});

export const HASH_NAMES = Object.freeze({
  [HashAlgId.SHA3_512]: 'SHA3-512',
});

export const FINGERPRINT_NAMES = Object.freeze({
  [FingerprintAlgId.SHA3_256]: 'SHA3-256',
});

export const SIGNATURE_PROFILE_NAMES = Object.freeze({
  [SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2]: 'PQ_DETACHED_PURE_CONTEXT_V2',
});

export const AUTH_DIGEST_NAMES = Object.freeze({
  [AuthDigestAlgId.SHA3_256]: 'SHA3-256',
});

export const FILE_HASH_LENGTH = 64;
export const AUTH_META_DIGEST_LENGTH = 32;
export const SIGNER_FINGERPRINT_DIGEST_LENGTH = 32;
export const SIGNER_FINGERPRINT_RECORD_LENGTH = 1 + SIGNER_FINGERPRINT_DIGEST_LENGTH;

export const SigFlags = Object.freeze({
  CTX_PRESENT: 1 << 0,
  FILENAME_PRESENT: 1 << 1,
  FILESIZE_PRESENT: 1 << 2,
  CREATED_AT_PRESENT: 1 << 3,
});

export const MetadataTag = Object.freeze({
  FILENAME: 0x01,
  FILESIZE: 0x02,
  CREATED_AT: 0x03,
  SIGNER_PUBLIC_KEY: 0x10,
  SIGNER_FINGERPRINT: 0x11,
});

const KNOWN_SIG_FLAGS =
  SigFlags.CTX_PRESENT |
  SigFlags.FILENAME_PRESENT |
  SigFlags.FILESIZE_PRESENT |
  SigFlags.CREATED_AT_PRESENT;

const U32_MAX = 0xffffffff;
const U16_MAX = 0xffff;
const U8_MAX = 0xff;
const U64_MAX = 0xffffffffffffffffn;
function concatBytes(arrays) {
  let total = 0;
  for (const bytes of arrays) total += bytes.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const bytes of arrays) {
    out.set(bytes, offset);
    offset += bytes.length;
  }
  return out;
}

function ensureUint8Array(bytes, code = ErrorCode.E_FORMAT_LENGTH, field = 'bytes') {
  if (!(bytes instanceof Uint8Array)) {
    throw createError(code, { field, expected: 'Uint8Array' });
  }
}

function ensureLength(bytes, expected, code = ErrorCode.E_FORMAT_LENGTH, field = 'length') {
  ensureUint8Array(bytes, code, field);
  if (bytes.length !== expected) {
    throw createError(code, { field, expected, actual: bytes.length });
  }
}

function ensureU8(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > U8_MAX) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field, value });
  }
}

function ensureU16(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > U16_MAX) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field, value });
  }
}

function ensureU32(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field, value });
  }
}

function ensureU64(value, field) {
  if (typeof value === 'number') value = BigInt(value);
  if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field, value: String(value) });
  }
  return value;
}

function writeU64LE(view, offset, value) {
  const normalized = ensureU64(value, 'u64');
  const lo = Number(normalized & 0xffffffffn);
  const hi = Number((normalized >> 32n) & 0xffffffffn);
  view.setUint32(offset, lo, true);
  view.setUint32(offset + 4, hi, true);
}

function readU64LE(view, offset) {
  const lo = BigInt(view.getUint32(offset, true));
  const hi = BigInt(view.getUint32(offset + 4, true));
  return (hi << 32n) | lo;
}

class Reader {
  constructor(bytes) {
    ensureUint8Array(bytes);
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = 0;
  }

  remaining() {
    return this.bytes.length - this.offset;
  }

  take(len, code = ErrorCode.E_FORMAT_LENGTH) {
    if (!Number.isInteger(len) || len < 0) {
      throw createError(code, { len });
    }
    if (this.offset + len > this.bytes.length) {
      throw createError(code, { needed: len, remaining: this.remaining() });
    }
    const out = this.bytes.subarray(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  u8(code = ErrorCode.E_FORMAT_LENGTH) {
    if (this.remaining() < 1) throw createError(code, { needed: 1, remaining: this.remaining() });
    const v = this.view.getUint8(this.offset);
    this.offset += 1;
    return v;
  }

  u16(code = ErrorCode.E_FORMAT_LENGTH) {
    if (this.remaining() < 2) throw createError(code, { needed: 2, remaining: this.remaining() });
    const v = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return v;
  }

  u32(code = ErrorCode.E_FORMAT_LENGTH) {
    if (this.remaining() < 4) throw createError(code, { needed: 4, remaining: this.remaining() });
    const v = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }
}

function decodeUtf8(bytes) {
  try {
    return bytesToUtf8(bytes);
  } catch (_err) {
    throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'invalid_utf8' });
  }
}

function normalizeIso8601(value) {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'createdAt_empty' });
    }
    const ts = Date.parse(trimmed);
    if (Number.isNaN(ts)) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'createdAt_invalid' });
    }
    return new Date(ts).toISOString();
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    const seconds = Number(value);
    if (!Number.isFinite(seconds)) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'createdAt_invalid_epoch' });
    }
    return new Date(Math.trunc(seconds) * 1000).toISOString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'createdAt_invalid_type' });
}

function encodeTLV(tag, valueBytes) {
  ensureU8(tag, 'tag');
  ensureUint8Array(valueBytes, ErrorCode.E_FORMAT_TLV, 'tlvValue');
  ensureU16(valueBytes.length, 'tlvLen');
  const out = new Uint8Array(3 + valueBytes.length);
  const view = new DataView(out.buffer);
  out[0] = tag;
  view.setUint16(1, valueBytes.length, true);
  out.set(valueBytes, 3);
  return out;
}

function decodeTLVBlock(bytes) {
  ensureUint8Array(bytes, ErrorCode.E_FORMAT_TLV, 'metadata');
  const reader = new Reader(bytes);
  const records = [];
  let lastTag = 0;
  const seen = new Set();

  while (reader.remaining() > 0) {
    if (reader.remaining() < 3) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'short_header' });
    }
    const tag = reader.u8(ErrorCode.E_FORMAT_TLV);
    const len = reader.u16(ErrorCode.E_FORMAT_TLV);

    if (tag === 0) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'tag_zero' });
    }
    if (tag <= lastTag) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'non_canonical_order', tag, lastTag });
    }
    if (seen.has(tag)) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'duplicate_tag', tag });
    }
    lastTag = tag;
    seen.add(tag);

    if (reader.remaining() < len) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'bad_length', tag, len, remaining: reader.remaining() });
    }

    const value = reader.take(len, ErrorCode.E_FORMAT_TLV);
    if (tag >= 0x80) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'unknown_critical_tag', tag });
    }
    records.push({ tag, value });
  }

  return records;
}

function ensureSuiteIdSupported(suiteId) {
  if (!Object.values(SuiteId).includes(suiteId)) {
    throw createError(ErrorCode.E_SUITE_UNSUPPORTED, { suiteId });
  }
}

function ensureHashAlgIdSupported(hashAlgId) {
  if (hashAlgId !== HashAlgId.SHA3_512) {
    throw createError(ErrorCode.E_HASH_UNSUPPORTED, { hashAlgId });
  }
}

function ensureSignatureProfileIdSupported(signatureProfileId) {
  if (signatureProfileId !== SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2) {
    throw createError(ErrorCode.E_FORMAT_VERSION, { field: 'signatureProfileId', signatureProfileId });
  }
}

function ensureAuthDigestAlgIdSupported(authDigestAlgId) {
  if (authDigestAlgId !== AuthDigestAlgId.SHA3_256) {
    throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'auth_digest_alg_unsupported', authDigestAlgId });
  }
}

function ensureFingerprintAlgIdSupported(algId) {
  if (algId !== FingerprintAlgId.SHA3_256) {
    throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'fingerprint_alg_unsupported', algId });
  }
}

export function getSuiteName(suiteId) {
  return SUITE_NAMES[suiteId] || `Unknown(${suiteId})`;
}

export function getHashName(hashAlgId) {
  return HASH_NAMES[hashAlgId] || `Unknown(${hashAlgId})`;
}

export function getFingerprintName(fingerprintAlgId) {
  return FINGERPRINT_NAMES[fingerprintAlgId] || `Unknown(${fingerprintAlgId})`;
}

export function getSignatureProfileName(signatureProfileId) {
  return SIGNATURE_PROFILE_NAMES[signatureProfileId] || `Unknown(${signatureProfileId})`;
}

export function getAuthDigestName(authDigestAlgId) {
  return AUTH_DIGEST_NAMES[authDigestAlgId] || `Unknown(${authDigestAlgId})`;
}

export function packSignerFingerprint({ algId = FingerprintAlgId.SHA3_256, digest }) {
  ensureFingerprintAlgIdSupported(algId);
  ensureLength(digest, SIGNER_FINGERPRINT_DIGEST_LENGTH, ErrorCode.E_FORMAT_TLV, 'fingerprintDigest');
  const out = new Uint8Array(SIGNER_FINGERPRINT_RECORD_LENGTH);
  out[0] = algId;
  out.set(digest, 1);
  return out;
}

export function unpackSignerFingerprint(record) {
  ensureLength(record, SIGNER_FINGERPRINT_RECORD_LENGTH, ErrorCode.E_FORMAT_TLV, 'signerFingerprint');
  const algId = record[0];
  ensureFingerprintAlgIdSupported(algId);
  return {
    algId,
    digest: record.subarray(1),
  };
}

function buildMetadataTLV(metadata = {}) {
  const records = [];

  if (metadata.filename !== undefined && metadata.filename !== null && metadata.filename !== '') {
    const nameBytes = utf8ToBytes(metadata.filename);
    records.push(encodeTLV(MetadataTag.FILENAME, nameBytes));
  }

  if (metadata.filesize !== undefined && metadata.filesize !== null) {
    const sizeValue = ensureU64(metadata.filesize, 'filesize');
    const value = new Uint8Array(8);
    const view = new DataView(value.buffer);
    writeU64LE(view, 0, sizeValue);
    records.push(encodeTLV(MetadataTag.FILESIZE, value));
  }

  if (metadata.createdAt !== undefined && metadata.createdAt !== null) {
    const createdAtIso = normalizeIso8601(metadata.createdAt);
    records.push(encodeTLV(MetadataTag.CREATED_AT, utf8ToBytes(createdAtIso)));
  }

  if (metadata.signerPublicKey instanceof Uint8Array && metadata.signerPublicKey.length > 0) {
    records.push(encodeTLV(MetadataTag.SIGNER_PUBLIC_KEY, metadata.signerPublicKey));
  }

  const signerFingerprint = metadata.signerFingerprint ?? metadata.signerKid;
  if (signerFingerprint instanceof Uint8Array && signerFingerprint.length > 0) {
    const parsedFp = unpackSignerFingerprint(signerFingerprint);
    records.push(encodeTLV(MetadataTag.SIGNER_FINGERPRINT, packSignerFingerprint(parsedFp)));
  }

  return concatBytes(records);
}

function ensureOnlyAllowedTags(records, allowedTags, field) {
  for (const { tag } of records) {
    if (!allowedTags.has(tag)) {
      throw createError(ErrorCode.E_FORMAT_TLV, { field, reason: 'unexpected_tag', tag });
    }
  }
}

export function packAuthenticatedMetadataV2(metadata = {}) {
  const authMetadata = {
    signerPublicKey: metadata.signerPublicKey,
    signerFingerprint: metadata.signerFingerprint,
  };
  const bytes = buildMetadataTLV(authMetadata);
  assertMaxLength(bytes.length, MAX_AUTH_METADATA_BYTES, 'authMetaLen', ErrorCode.E_FORMAT_LENGTH);
  const records = decodeTLVBlock(bytes);
  ensureOnlyAllowedTags(records, new Set([MetadataTag.SIGNER_PUBLIC_KEY, MetadataTag.SIGNER_FINGERPRINT]), 'authMeta');
  const parsed = parseMetadata(records);
  if (!(parsed.signerPublicKey instanceof Uint8Array) || !(parsed.signerFingerprint instanceof Uint8Array)) {
    throw createError(ErrorCode.E_FORMAT_TLV, { field: 'authMeta', reason: 'missing_signer_binding' });
  }
  return bytes;
}

export function packDisplayMetadataV2(metadata = {}) {
  const displayMetadata = {
    filename: metadata.filename,
    filesize: metadata.filesize,
    createdAt: metadata.createdAt,
  };
  const bytes = buildMetadataTLV(displayMetadata);
  assertMaxLength(bytes.length, MAX_DISPLAY_METADATA_BYTES, 'displayMetaLen', ErrorCode.E_FORMAT_LENGTH);
  const records = decodeTLVBlock(bytes);
  ensureOnlyAllowedTags(records, new Set([MetadataTag.FILENAME, MetadataTag.FILESIZE, MetadataTag.CREATED_AT]), 'displayMeta');
  return bytes;
}

export function computeAuthMetaDigestV2(authMetaBytes, authDigestAlgId = AuthDigestAlgId.SHA3_256) {
  ensureAuthDigestAlgIdSupported(authDigestAlgId);
  assertBytesLimit(authMetaBytes, MAX_AUTH_METADATA_BYTES, 'authMetaBytes', ErrorCode.E_FORMAT_LENGTH);
  return sha3_256(authMetaBytes);
}

function parseAuthenticatedMetadataV2(authMetaBytes, authDigestAlgId, expectedDigest) {
  ensureAuthDigestAlgIdSupported(authDigestAlgId);
  assertBytesLimit(authMetaBytes, MAX_AUTH_METADATA_BYTES, 'authMetaBytes', ErrorCode.E_FORMAT_LENGTH);
  ensureLength(expectedDigest, AUTH_META_DIGEST_LENGTH, ErrorCode.E_FORMAT_TLV, 'authMetaDigest');

  const records = decodeTLVBlock(authMetaBytes);
  ensureOnlyAllowedTags(records, new Set([MetadataTag.SIGNER_PUBLIC_KEY, MetadataTag.SIGNER_FINGERPRINT]), 'authMeta');
  const metadata = parseMetadata(records);
  if (!(metadata.signerPublicKey instanceof Uint8Array) || !(metadata.signerFingerprint instanceof Uint8Array)) {
    throw createError(ErrorCode.E_FORMAT_TLV, { field: 'authMeta', reason: 'missing_signer_binding' });
  }

  const recomputedDigest = computeAuthMetaDigestV2(authMetaBytes, authDigestAlgId);
  if (!equalsBytes(recomputedDigest, expectedDigest)) {
    throw createError(ErrorCode.E_FORMAT_TLV, { field: 'authMetaDigest', reason: 'auth_meta_digest_mismatch' });
  }

  return metadata;
}

function parseDisplayMetadataV2(displayMetaBytes) {
  assertBytesLimit(displayMetaBytes, MAX_DISPLAY_METADATA_BYTES, 'displayMetaBytes', ErrorCode.E_FORMAT_LENGTH);
  const records = decodeTLVBlock(displayMetaBytes);
  ensureOnlyAllowedTags(records, new Set([MetadataTag.FILENAME, MetadataTag.FILESIZE, MetadataTag.CREATED_AT]), 'displayMeta');
  return parseMetadata(records);
}

function parseCreatedAtValue(value) {
  if (value.length === 8) {
    const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
    const epochSeconds = readU64LE(view, 0);
    return new Date(Number(epochSeconds) * 1000).toISOString();
  }
  const iso = decodeUtf8(value);
  return normalizeIso8601(iso);
}

function parseMetadata(records) {
  const metadata = {};

  for (const { tag, value } of records) {
    if (tag === MetadataTag.FILENAME) {
      metadata.filename = decodeUtf8(value);
      continue;
    }

    if (tag === MetadataTag.FILESIZE) {
      if (value.length !== 8) {
        throw createError(ErrorCode.E_FORMAT_TLV, { tag, reason: 'filesize_len', len: value.length });
      }
      const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
      metadata.filesize = readU64LE(view, 0);
      continue;
    }

    if (tag === MetadataTag.CREATED_AT) {
      metadata.createdAt = parseCreatedAtValue(value);
      continue;
    }

    if (tag === MetadataTag.SIGNER_PUBLIC_KEY) {
      metadata.signerPublicKey = Uint8Array.from(value);
      continue;
    }

    if (tag === MetadataTag.SIGNER_FINGERPRINT) {
      metadata.signerFingerprint = Uint8Array.from(value);
    }
  }

  if (metadata.signerFingerprint) {
    const parsedFingerprint = unpackSignerFingerprint(metadata.signerFingerprint);
    metadata.signerFingerprintAlgId = parsedFingerprint.algId;
    metadata.signerFingerprintDigest = Uint8Array.from(parsedFingerprint.digest);
  }

  if (metadata.signerPublicKey && metadata.signerFingerprint) {
    const recomputedDigest = sha3_256(metadata.signerPublicKey);
    if (!equalsBytes(recomputedDigest, metadata.signerFingerprintDigest)) {
      throw createError(ErrorCode.E_FORMAT_TLV, { reason: 'signer_fingerprint_mismatch' });
    }
  }

  return metadata;
}

function metadataFlags(metadata = {}) {
  let flags = 0;
  if (metadata.filename !== undefined && metadata.filename !== null && metadata.filename !== '') {
    flags |= SigFlags.FILENAME_PRESENT;
  }
  if (metadata.filesize !== undefined && metadata.filesize !== null) {
    flags |= SigFlags.FILESIZE_PRESENT;
  }
  if (metadata.createdAt !== undefined && metadata.createdAt !== null) {
    flags |= SigFlags.CREATED_AT_PRESENT;
  }
  return flags;
}

export function buildTBSV2({
  formatVerMajor = QSIG_FORMAT_VERSION_MAJOR,
  formatVerMinor = QSIG_FORMAT_VERSION_MINOR,
  suiteId,
  signatureProfileId = SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
  payloadDigestAlgId = HashAlgId.SHA3_512,
  authDigestAlgId = AuthDigestAlgId.SHA3_256,
  payloadDigest,
  authMetaDigest,
}) {
  ensureU8(formatVerMajor, 'formatVerMajor');
  ensureU8(formatVerMinor, 'formatVerMinor');
  ensureSuiteIdSupported(suiteId);
  ensureSignatureProfileIdSupported(signatureProfileId);
  ensureHashAlgIdSupported(payloadDigestAlgId);
  ensureAuthDigestAlgIdSupported(authDigestAlgId);
  ensureLength(payloadDigest, FILE_HASH_LENGTH, ErrorCode.E_FORMAT_LENGTH, 'payloadDigest');
  ensureLength(authMetaDigest, AUTH_META_DIGEST_LENGTH, ErrorCode.E_FORMAT_TLV, 'authMetaDigest');

  const out = new Uint8Array(4 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + FILE_HASH_LENGTH + AUTH_META_DIGEST_LENGTH);
  let o = 0;
  out.set(MAGIC_TBS, o);
  o += 4;
  out[o++] = QSIG_TBS_VERSION_MAJOR;
  out[o++] = QSIG_TBS_VERSION_MINOR;
  out[o++] = formatVerMajor;
  out[o++] = formatVerMinor;
  out[o++] = suiteId;
  out[o++] = signatureProfileId;
  out[o++] = payloadDigestAlgId;
  out[o++] = authDigestAlgId;
  out.set(payloadDigest, o);
  o += FILE_HASH_LENGTH;
  out.set(authMetaDigest, o);
  return out;
}

export function packSignatureV2({
  suiteId,
  signatureProfileId = SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
  payloadDigestAlgId = HashAlgId.SHA3_512,
  authDigestAlgId = AuthDigestAlgId.SHA3_256,
  payloadDigest,
  authMetaDigest,
  signature,
  ctx = 'quantum-signer/v2',
  authenticatedMetadata = {},
  displayMetadata = {},
  versionMajor = QSIG_FORMAT_VERSION_MAJOR,
  versionMinor = QSIG_FORMAT_VERSION_MINOR,
}) {
  ensureU8(versionMajor, 'versionMajor');
  ensureU8(versionMinor, 'versionMinor');
  ensureSuiteIdSupported(suiteId);
  ensureSignatureProfileIdSupported(signatureProfileId);
  ensureHashAlgIdSupported(payloadDigestAlgId);
  ensureAuthDigestAlgIdSupported(authDigestAlgId);
  ensureLength(payloadDigest, FILE_HASH_LENGTH, ErrorCode.E_FORMAT_LENGTH, 'payloadDigest');
  ensureLength(authMetaDigest, AUTH_META_DIGEST_LENGTH, ErrorCode.E_FORMAT_TLV, 'authMetaDigest');
  ensureUint8Array(signature, ErrorCode.E_FORMAT_LENGTH, 'signature');

  const ctxBytes = ctx ? utf8ToBytes(ctx) : new Uint8Array();
  assertMaxLength(ctxBytes.length, MAX_CONTEXT_BYTES, 'ctxLen', ErrorCode.E_FORMAT_LENGTH);
  ensureU8(ctxBytes.length, 'ctxLen');
  if (ctxBytes.length === 0) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'ctx', reason: 'required' });
  }

  const authMetaBytes = packAuthenticatedMetadataV2(authenticatedMetadata);
  const recomputedAuthMetaDigest = computeAuthMetaDigestV2(authMetaBytes, authDigestAlgId);
  if (!equalsBytes(recomputedAuthMetaDigest, authMetaDigest)) {
    throw createError(ErrorCode.E_FORMAT_TLV, { field: 'authMetaDigest', reason: 'mismatch_at_pack' });
  }

  const displayMetaBytes = packDisplayMetadataV2(displayMetadata);
  assertMaxLength(authMetaBytes.length, MAX_AUTH_METADATA_BYTES, 'authMetaLen', ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(displayMetaBytes.length, MAX_DISPLAY_METADATA_BYTES, 'displayMetaLen', ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(signature.length, MAX_SIGNATURE_BYTES, 'sigLen', ErrorCode.E_FORMAT_LENGTH);
  ensureU16(authMetaBytes.length, 'authMetaLen');
  ensureU16(displayMetaBytes.length, 'displayMetaLen');
  ensureU32(signature.length, 'sigLen');

  let flags = metadataFlags(displayMetadata);
  flags |= SigFlags.CTX_PRESENT;

  const headerLen = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + FILE_HASH_LENGTH + AUTH_META_DIGEST_LENGTH + 1 + 1 + 2 + 2 + 4;
  const totalLen = headerLen + ctxBytes.length + authMetaBytes.length + displayMetaBytes.length + signature.length;
  assertMaxLength(totalLen, MAX_SIGNATURE_FILE_BYTES, 'sigBytes', ErrorCode.E_FORMAT_LENGTH);
  const out = new Uint8Array(totalLen);
  const view = new DataView(out.buffer);

  let o = 0;
  out.set(MAGIC_SIG, o);
  o += 4;
  out[o++] = versionMajor;
  out[o++] = versionMinor;
  out[o++] = suiteId;
  out[o++] = signatureProfileId;
  out[o++] = payloadDigestAlgId;
  out[o++] = authDigestAlgId;
  view.setUint16(o, flags, true);
  o += 2;
  out.set(payloadDigest, o);
  o += FILE_HASH_LENGTH;
  out.set(authMetaDigest, o);
  o += AUTH_META_DIGEST_LENGTH;
  out[o++] = ctxBytes.length;
  out[o++] = 0;
  view.setUint16(o, authMetaBytes.length, true);
  o += 2;
  view.setUint16(o, displayMetaBytes.length, true);
  o += 2;
  view.setUint32(o, signature.length, true);
  o += 4;
  out.set(ctxBytes, o);
  o += ctxBytes.length;
  out.set(authMetaBytes, o);
  o += authMetaBytes.length;
  out.set(displayMetaBytes, o);
  o += displayMetaBytes.length;
  out.set(signature, o);

  return out;
}

export function unpackSignatureV2(sigBytes) {
  assertBytesLimit(sigBytes, MAX_SIGNATURE_FILE_BYTES, 'sigBytes', ErrorCode.E_FORMAT_LENGTH);
  const minLen = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + FILE_HASH_LENGTH + AUTH_META_DIGEST_LENGTH + 1 + 1 + 2 + 2 + 4;
  if (sigBytes.length < minLen) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { minLen, actual: sigBytes.length });
  }

  const reader = new Reader(sigBytes);
  const magic = reader.take(4, ErrorCode.E_FORMAT_MAGIC);
  if (!equalsBytes(magic, MAGIC_SIG)) {
    throw createError(ErrorCode.E_FORMAT_MAGIC);
  }

  const versionMajor = reader.u8(ErrorCode.E_FORMAT_VERSION);
  const versionMinor = reader.u8(ErrorCode.E_FORMAT_VERSION);
  if (versionMajor !== QSIG_FORMAT_VERSION_MAJOR) {
    throw createError(ErrorCode.E_FORMAT_VERSION, {
      versionMajor,
      expectedMajor: QSIG_FORMAT_VERSION_MAJOR,
    });
  }

  const suiteId = reader.u8(ErrorCode.E_SUITE_UNSUPPORTED);
  const signatureProfileId = reader.u8(ErrorCode.E_FORMAT_VERSION);
  const payloadDigestAlgId = reader.u8(ErrorCode.E_HASH_UNSUPPORTED);
  const authDigestAlgId = reader.u8(ErrorCode.E_FORMAT_TLV);
  ensureSuiteIdSupported(suiteId);
  ensureSignatureProfileIdSupported(signatureProfileId);
  ensureHashAlgIdSupported(payloadDigestAlgId);
  ensureAuthDigestAlgIdSupported(authDigestAlgId);

  const flags = reader.u16(ErrorCode.E_FORMAT_FLAGS);
  if ((flags & ~KNOWN_SIG_FLAGS) !== 0) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { flags });
  }

  const payloadDigest = reader.take(FILE_HASH_LENGTH, ErrorCode.E_FORMAT_LENGTH);
  const authMetaDigest = reader.take(AUTH_META_DIGEST_LENGTH, ErrorCode.E_FORMAT_TLV);
  const ctxLen = reader.u8(ErrorCode.E_FORMAT_LENGTH);
  const reserved = reader.u8(ErrorCode.E_FORMAT_FLAGS);
  if (reserved !== 0) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'reserved', value: reserved });
  }

  const authMetaLen = reader.u16(ErrorCode.E_FORMAT_TLV);
  const displayMetaLen = reader.u16(ErrorCode.E_FORMAT_TLV);
  const sigLen = reader.u32(ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(authMetaLen, MAX_AUTH_METADATA_BYTES, 'authMetaLen', ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(displayMetaLen, MAX_DISPLAY_METADATA_BYTES, 'displayMetaLen', ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(sigLen, MAX_SIGNATURE_BYTES, 'sigLen', ErrorCode.E_FORMAT_LENGTH);
  const expectedRemaining = ctxLen + authMetaLen + displayMetaLen + sigLen;
  if (reader.remaining() !== expectedRemaining) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, {
      expectedRemaining,
      remaining: reader.remaining(),
    });
  }

  const ctxBytes = reader.take(ctxLen, ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(ctxBytes.length, MAX_CONTEXT_BYTES, 'ctxLen', ErrorCode.E_FORMAT_LENGTH);
  if (ctxBytes.length === 0) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'ctx', reason: 'required' });
  }
  const authMetaBytes = reader.take(authMetaLen, ErrorCode.E_FORMAT_TLV);
  const displayMetaBytes = reader.take(displayMetaLen, ErrorCode.E_FORMAT_TLV);
  const signature = reader.take(sigLen, ErrorCode.E_FORMAT_LENGTH);

  const ctxFlag = (flags & SigFlags.CTX_PRESENT) !== 0;
  if (!ctxFlag) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'ctx', flags, ctxLen });
  }

  const authenticatedMetadata = parseAuthenticatedMetadataV2(authMetaBytes, authDigestAlgId, authMetaDigest);
  const displayMetadata = parseDisplayMetadataV2(displayMetaBytes);
  const metadata = { ...displayMetadata, ...authenticatedMetadata };

  const hasFilename = displayMetadata.filename !== undefined;
  const hasFilesize = displayMetadata.filesize !== undefined;
  const hasCreatedAt = displayMetadata.createdAt !== undefined;
  if (((flags & SigFlags.FILENAME_PRESENT) !== 0) !== hasFilename) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'filename', flags });
  }
  if (((flags & SigFlags.FILESIZE_PRESENT) !== 0) !== hasFilesize) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'filesize', flags });
  }
  if (((flags & SigFlags.CREATED_AT_PRESENT) !== 0) !== hasCreatedAt) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { field: 'createdAt', flags });
  }

  const ctx = decodeUtf8(ctxBytes);
  const tbs = buildTBSV2({
    formatVerMajor: versionMajor,
    formatVerMinor: versionMinor,
    suiteId,
    signatureProfileId,
    payloadDigestAlgId,
    authDigestAlgId,
    payloadDigest,
    authMetaDigest,
  });

  return {
    versionMajor,
    versionMinor,
    suiteId,
    signatureProfileId,
    hashAlgId: payloadDigestAlgId,
    payloadDigestAlgId,
    authDigestAlgId,
    flags,
    fileHash: payloadDigest,
    payloadDigest,
    authMetaDigest,
    ctx,
    ctxBytes,
    authenticatedMetadata,
    displayMetadata,
    metadata,
    signature,
    signatureLength: signature.length,
    tbs,
  };
}

function buildKeyFile({ magic, suiteId, keyBytes, versionMajor, versionMinor }) {
  ensureU8(versionMajor, 'versionMajor');
  ensureU8(versionMinor, 'versionMinor');
  ensureSuiteIdSupported(suiteId);
  ensureUint8Array(keyBytes, ErrorCode.E_FORMAT_LENGTH, 'keyBytes');
  assertMaxLength(keyBytes.length, MAX_KEY_BYTES, 'keyLen', ErrorCode.E_FORMAT_LENGTH);
  ensureU32(keyBytes.length, 'keyLen');

  const headerLen = 4 + 1 + 1 + 1 + 1 + 4;
  const withoutCrc = new Uint8Array(headerLen + keyBytes.length);
  const view = new DataView(withoutCrc.buffer);

  let o = 0;
  withoutCrc.set(magic, o);
  o += 4;
  withoutCrc[o++] = versionMajor;
  withoutCrc[o++] = versionMinor;
  withoutCrc[o++] = suiteId;
  withoutCrc[o++] = 0;
  view.setUint32(o, keyBytes.length, true);
  o += 4;
  withoutCrc.set(keyBytes, o);

  const crc = crc32(withoutCrc);
  const out = new Uint8Array(withoutCrc.length + 4);
  assertMaxLength(out.length, MAX_KEY_FILE_BYTES, 'keyFileLen', ErrorCode.E_FORMAT_LENGTH);
  out.set(withoutCrc, 0);
  new DataView(out.buffer).setUint32(withoutCrc.length, crc, true);
  return out;
}

function parseKeyFile(bytes, expectedMagic) {
  assertBytesLimit(bytes, MAX_KEY_FILE_BYTES, 'keyFile', ErrorCode.E_FORMAT_LENGTH);

  const minLen = 4 + 1 + 1 + 1 + 1 + 4 + 4;
  if (bytes.length < minLen) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { minLen, actual: bytes.length });
  }

  const reader = new Reader(bytes);
  const magic = reader.take(4, ErrorCode.E_FORMAT_MAGIC);
  if (!equalsBytes(magic, expectedMagic)) {
    throw createError(ErrorCode.E_FORMAT_MAGIC);
  }

  const versionMajor = reader.u8(ErrorCode.E_FORMAT_VERSION);
  const versionMinor = reader.u8(ErrorCode.E_FORMAT_VERSION);
  if (versionMajor !== KEY_FORMAT_VERSION_MAJOR) {
    throw createError(ErrorCode.E_FORMAT_VERSION, { versionMajor, expectedMajor: KEY_FORMAT_VERSION_MAJOR });
  }

  const suiteId = reader.u8(ErrorCode.E_SUITE_UNSUPPORTED);
  ensureSuiteIdSupported(suiteId);

  const flags = reader.u8(ErrorCode.E_FORMAT_FLAGS);
  if (flags !== 0) {
    throw createError(ErrorCode.E_FORMAT_FLAGS, { flags });
  }

  const keyLen = reader.u32(ErrorCode.E_FORMAT_LENGTH);
  assertMaxLength(keyLen, MAX_KEY_BYTES, 'keyLen', ErrorCode.E_FORMAT_LENGTH);
  const expectedTotal = 4 + 1 + 1 + 1 + 1 + 4 + keyLen + 4;
  if (bytes.length !== expectedTotal) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { expectedTotal, actual: bytes.length });
  }

  const keyBytes = reader.take(keyLen, ErrorCode.E_FORMAT_LENGTH);
  const crcRead = reader.u32(ErrorCode.E_FORMAT_CRC32);

  const crcInput = bytes.subarray(0, bytes.length - 4);
  const crcExpected = crc32(crcInput);
  if (crcRead !== crcExpected) {
    throw createError(ErrorCode.E_FORMAT_CRC32, { expected: crcExpected, actual: crcRead });
  }

  return {
    versionMajor,
    versionMinor,
    suiteId,
    keyBytes,
    crc32: crcRead,
  };
}

export function packPublicKey({
  suiteId,
  keyBytes,
  versionMajor = KEY_FORMAT_VERSION_MAJOR,
  versionMinor = KEY_FORMAT_VERSION_MINOR,
}) {
  return buildKeyFile({
    magic: MAGIC_PQPK,
    suiteId,
    keyBytes,
    versionMajor,
    versionMinor,
  });
}

export function packSecretKey({
  suiteId,
  keyBytes,
  versionMajor = KEY_FORMAT_VERSION_MAJOR,
  versionMinor = KEY_FORMAT_VERSION_MINOR,
}) {
  return buildKeyFile({
    magic: MAGIC_PQSK,
    suiteId,
    keyBytes,
    versionMajor,
    versionMinor,
  });
}

export function unpackPublicKey(bytes) {
  return parseKeyFile(bytes, MAGIC_PQPK);
}

export function unpackSecretKey(bytes) {
  return parseKeyFile(bytes, MAGIC_PQSK);
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  ensureUint8Array(bytes, ErrorCode.E_FORMAT_CRC32, 'crcInput');
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function detectMagic(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) return 'UNKNOWN';
  const m = bytes.subarray(0, 4);
  if (equalsBytes(m, MAGIC_SIG)) return 'SIG';
  if (equalsBytes(m, MAGIC_PQPK)) return 'PQPK';
  if (equalsBytes(m, MAGIC_PQSK)) return 'PQSK';
  return 'UNKNOWN';
}

export function metadataToPlain(metadata) {
  const signerFingerprint = metadata.signerFingerprint ? unpackSignerFingerprint(metadata.signerFingerprint) : null;
  return {
    filename: metadata.filename,
    filesize: metadata.filesize !== undefined ? Number(metadata.filesize) : undefined,
    createdAt: metadata.createdAt,
    signerFingerprintAlg: signerFingerprint ? getFingerprintName(signerFingerprint.algId) : undefined,
    signerFingerprintHex: signerFingerprint ? bytesToHexLower(signerFingerprint.digest) : undefined,
    signerPublicKeyLength: metadata.signerPublicKey ? metadata.signerPublicKey.length : undefined,
  };
}
