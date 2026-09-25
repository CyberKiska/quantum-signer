import { utf8ToBytesStrict } from '../crypto/text-encoding.js';

const decoder = new TextDecoder('utf-8', { fatal: true });

function ensureBytes(value, field = 'bytes') {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${field} must be Uint8Array`);
  }
}

function ensureString(value, field = 'value') {
  if (typeof value !== 'string') {
    throw new TypeError(`${field} must be string`);
  }
}

export function utf8ToBytes(value) {
  return utf8ToBytesStrict(value, 'text');
}

export function bytesToUtf8(bytes) {
  ensureBytes(bytes, 'bytes');
  return decoder.decode(bytes);
}

export function bytesToHexLower(bytes) {
  ensureBytes(bytes, 'bytes');
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytesStrict(value) {
  ensureString(value, 'hex');
  const normalized = value.trim();
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new TypeError('invalid hex string');
  }
  return Uint8Array.from({ length: normalized.length / 2 }, (_, i) => Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16));
}
