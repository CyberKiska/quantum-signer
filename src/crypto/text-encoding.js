export function assertWellFormedUnicodeString(value, field = 'text') {
  if (typeof value !== 'string') throw new TypeError(`${field} must be a string`);

  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new RangeError(`${field} contains an unpaired UTF-16 surrogate at index ${i}`);
      }
      i += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new RangeError(`${field} contains an unpaired UTF-16 surrogate at index ${i}`);
    }
  }

  return value;
}

export function utf8ToBytesStrict(value, field = 'text') {
  assertWellFormedUnicodeString(value, field);
  return new TextEncoder().encode(value);
}
