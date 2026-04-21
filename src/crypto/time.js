const CANONICAL_UTC_ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function normalizeCanonicalUtcIso8601(value) {
  if (typeof value !== 'string') {
    throw new TypeError('createdAt must be string');
  }
  const trimmed = value.trim();
  if (!CANONICAL_UTC_ISO8601_RE.test(trimmed)) {
    throw new RangeError('invalid_iso8601');
  }
  const ts = Date.parse(trimmed);
  if (!Number.isFinite(ts)) {
    throw new RangeError('invalid_iso8601');
  }
  const normalized = new Date(ts).toISOString();
  if (normalized !== trimmed) {
    throw new RangeError('invalid_iso8601');
  }
  return normalized;
}
