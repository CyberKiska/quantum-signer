import {
  DOCUMENT_CSP,
  STANDARD_SECURITY_HEADERS,
  WORKER_CSP,
  buildStaticHeadersFile,
} from './security-headers.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

for (const forbidden of ["'unsafe-inline'", "'unsafe-eval'", 'http:', 'https:']) {
  assert(!DOCUMENT_CSP.includes(forbidden), `document CSP contains forbidden source: ${forbidden}`);
  assert(!WORKER_CSP.includes(forbidden), `worker CSP contains forbidden source: ${forbidden}`);
}

for (const directive of [
  "default-src 'none'",
  "connect-src 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "script-src 'self'",
  "worker-src 'self'",
]) {
  assert(DOCUMENT_CSP.includes(directive), `document CSP is missing ${directive}`);
}

for (const directive of ["default-src 'none'", "connect-src 'none'", "script-src 'none'"]) {
  assert(WORKER_CSP.includes(directive), `worker CSP is missing ${directive}`);
}

for (const header of [
  'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Resource-Policy',
  'Permissions-Policy',
  'Referrer-Policy',
  'Strict-Transport-Security',
  'X-Content-Type-Options',
  'X-Frame-Options',
]) {
  assert(typeof STANDARD_SECURITY_HEADERS[header] === 'string', `security header is missing: ${header}`);
}

const rootHeaders = buildStaticHeadersFile('/');
assert(rootHeaders.startsWith('/*\n'), 'root header file is missing the all-route policy');
assert(rootHeaders.includes('\n/assets/worker.js\n'), 'root header file is missing the worker route');
assert(rootHeaders.includes('\n/assets/*\n'), 'root header file is missing the asset cache policy');
assert(rootHeaders.includes(`Content-Security-Policy: ${DOCUMENT_CSP}`), 'document CSP was not emitted');
assert(rootHeaders.includes(`Content-Security-Policy: ${WORKER_CSP}`), 'worker CSP was not emitted');

const nestedHeaders = buildStaticHeadersFile('/quantum-signer/');
assert(nestedHeaders.startsWith('/quantum-signer/*\n'), 'nested all-route policy has the wrong base path');
assert(
  nestedHeaders.includes('\n/quantum-signer/assets/worker.js\n'),
  'nested worker policy has the wrong base path'
);
assert(
  nestedHeaders.includes('\n/quantum-signer/assets/*\n'),
  'nested asset cache policy has the wrong base path'
);

console.log('Security-header policy tests: PASS');
