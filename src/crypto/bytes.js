export function equalsBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  const maxLength = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  // Source-level constant-work comparison: there is no early return based on
  // matching prefixes. JavaScript engines do not provide a formal constant-
  // time guarantee, so this remains defence in depth rather than a side-channel
  // certification claim.
  for (let i = 0; i < maxLength; i += 1) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

export function equalsHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const maxLength = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  for (let i = 0; i < maxLength; i += 1) {
    difference |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return difference === 0;
}

export function wipeBytes(bytes) {
  if (bytes instanceof Uint8Array) {
    bytes.fill(0);
  }
}
