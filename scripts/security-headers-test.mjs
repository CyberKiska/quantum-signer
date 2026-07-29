import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DOCUMENT_CSP,
  META_DOCUMENT_CSP,
  STANDARD_SECURITY_HEADERS,
  WORKER_CSP,
  buildStaticHeadersFile,
} from './security-headers.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

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
  'Origin-Agent-Cluster',
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
assert(
  !META_DOCUMENT_CSP.includes("frame-ancestors 'none'"),
  'meta CSP contains a directive browsers ignore in meta policies'
);
for (const directive of DOCUMENT_CSP.split('; ')) {
  if (directive.startsWith('frame-ancestors ')) continue;
  assert(META_DOCUMENT_CSP.includes(directive), `meta CSP is missing ${directive}`);
}

const sourceHtml = await readFile(path.join(root, 'src', 'index.html'), 'utf8');
assert(
  sourceHtml.includes('content="%DOCUMENT_CSP%"'),
  'index.html must obtain its meta CSP from the shared build-time policy'
);
assert(
  sourceHtml.includes('content="%PRIVATE_KEY_OPERATIONS%"'),
  'index.html must obtain its private-key capability from the build profile'
);
assert(
  !sourceHtml.includes("default-src 'none'"),
  'index.html contains a second hand-maintained CSP instead of the shared placeholder'
);

const headerLines = rootHeaders.split('\n');
const headerRuleCount = headerLines.filter((line) => line !== '' && !line.startsWith(' ')).length;
assert(headerRuleCount <= 100, 'generated header policy exceeds the portable static-host rule budget');
for (const line of headerLines) {
  assert(line.length <= 2_000, 'generated header line exceeds the portable static-host line budget');
}

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
