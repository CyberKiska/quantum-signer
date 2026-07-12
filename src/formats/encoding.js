import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
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
  return bytesToHex(bytes).toLowerCase();
}

export function hexToBytesStrict(value) {
  ensureString(value, 'hex');
  const normalized = value.trim();
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new TypeError('invalid hex string');
  }
  return hexToBytes(normalized);
}

export function bytesToBase64(bytes) {
  ensureBytes(bytes, 'bytes');
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  ensureString(value, 'base64');
  const normalized = value.trim();
  if (
    normalized.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(normalized)
  ) {
    throw new TypeError('invalid or non-canonical base64 string');
  }
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  if (bytesToBase64(out) !== normalized) throw new TypeError('non-canonical base64 pad bits');
  return out;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value) {
  ensureString(value, 'base64url');
  const input = value.trim();
  if (!/^[A-Za-z0-9_-]*$/.test(input) || input.length % 4 === 1) {
    throw new TypeError('invalid or non-canonical base64url string');
  }
  let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4;
  if (padding === 2) normalized += '==';
  else if (padding === 3) normalized += '=';
  else if (padding !== 0) {
    throw new TypeError('invalid base64url string');
  }
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  if (bytesToBase64Url(out) !== input) throw new TypeError('non-canonical base64url pad bits');
  return out;
}
