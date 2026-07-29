export const DOCUMENT_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "connect-src 'none'",
  "font-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "img-src 'self' data:",
  "manifest-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "worker-src 'self'",
].join('; ');

// frame-ancestors is intentionally omitted from the meta policy because
// browsers ignore that directive in <meta http-equiv>. The response header
// remains authoritative and carries the complete DOCUMENT_CSP.
export const META_DOCUMENT_CSP = DOCUMENT_CSP.split('; ')
  .filter((directive) => !directive.startsWith('frame-ancestors '))
  .join('; ');

export const WORKER_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "connect-src 'none'",
  "object-src 'none'",
  "script-src 'none'",
].join('; ');

export const STANDARD_SECURITY_HEADERS = Object.freeze({
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Origin-Agent-Cluster': '?1',
  'Permissions-Policy':
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
});

function headerBlock(route, headers) {
  const lines = [route];
  for (const [name, value] of Object.entries(headers)) {
    lines.push(`  ${name}: ${value}`);
  }
  return lines.join('\n');
}

export function buildStaticHeadersFile(basePath) {
  const allRoutes = basePath === '/' ? '/*' : `${basePath}*`;
  return [
    headerBlock(allRoutes, STANDARD_SECURITY_HEADERS),
    headerBlock(basePath, {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Content-Security-Policy': DOCUMENT_CSP,
    }),
    headerBlock(`${basePath}index.html`, {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Content-Security-Policy': DOCUMENT_CSP,
    }),
    headerBlock(`${basePath}styles.css`, {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
    }),
    headerBlock(`${basePath}assets/*`, {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
    }),
    headerBlock(`${basePath}assets/worker.js`, {
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Content-Security-Policy': WORKER_CSP,
    }),
    '',
  ].join('\n\n');
}
