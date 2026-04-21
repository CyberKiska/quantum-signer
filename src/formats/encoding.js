import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const encoder = new TextEncoder();
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
  return encoder.encode(String(value));
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
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value) {
  ensureString(value, 'base64url');
  let normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4;
  if (padding === 2) normalized += '==';
  else if (padding === 3) normalized += '=';
  else if (padding !== 0) {
    throw new TypeError('invalid base64url string');
  }
  return base64ToBytes(normalized);
}
