import {
  DOCUMENT_CSP,
  STANDARD_SECURITY_HEADERS,
} from './security-headers.mjs';

const MAX_ATTEMPTS = 10;
const RETRY_DELAY_MS = 2_000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isLoopback(hostname) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '[::1]';
}

function expectedDeploymentUrl() {
  const raw = process.env.DEPLOYMENT_URL;
  assert(typeof raw === 'string' && raw.trim() !== '', 'DEPLOYMENT_URL is required');
  const url = new URL(raw);
  assert(
    url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback(url.hostname)),
    'response probe requires HTTPS except on an explicit loopback address'
  );
  const expectedHost = process.env.EXPECTED_DEPLOYMENT_HOST;
  assert(
    isLoopback(url.hostname) || (typeof expectedHost === 'string' && url.hostname === expectedHost),
    `refusing to probe an unexpected deployment host: ${url.hostname}`
  );
  url.pathname = '/';
  url.search = '';
  url.hash = '';
  return url;
}

function assertHeader(response, name, expected) {
  const actual = response.headers.get(name);
  assert(actual === expected, `${response.url}: ${name} mismatch; expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function assertStandardHeaders(response, { skipHsts = false } = {}) {
  for (const [name, value] of Object.entries(STANDARD_SECURITY_HEADERS)) {
    if (skipHsts && name === 'Strict-Transport-Security') continue;
    assertHeader(response, name, value);
  }
}

async function fetchWithRetry(url) {
  let lastError = null;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch(url, {
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      });
      if (response.ok) return response;
      lastError = new Error(`${url}: unexpected HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    if (attempt < MAX_ATTEMPTS) {
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
    }
  }
  throw lastError || new Error(`${url}: response was unavailable`);
}

const deploymentUrl = expectedDeploymentUrl();
const loopbackHttp = deploymentUrl.protocol === 'http:' && isLoopback(deploymentUrl.hostname);
const documentResponse = await fetchWithRetry(deploymentUrl);
assertHeader(documentResponse, 'Content-Security-Policy', DOCUMENT_CSP);
assertHeader(documentResponse, 'Cache-Control', 'no-cache, no-store, must-revalidate');
assertStandardHeaders(documentResponse, { skipHsts: loopbackHttp });
const documentType = documentResponse.headers.get('Content-Type') || '';
assert(documentType.toLowerCase().startsWith('text/html'), `document has unsafe MIME type: ${documentType}`);
const documentHtml = await documentResponse.text();
const expectedPrivateKeyProfile = process.env.EXPECTED_PRIVATE_KEY_OPERATIONS || 'disabled';
assert(
  documentHtml.includes(
    `<meta name="private-key-operations" content="${expectedPrivateKeyProfile}" />`
  ),
  `document does not declare the expected ${expectedPrivateKeyProfile} private-key profile`
);
assert(!documentHtml.includes('%DOCUMENT_CSP%'), 'document contains an unreplaced CSP placeholder');

const appUrl = new URL('assets/app.js', deploymentUrl);
const appResponse = await fetchWithRetry(appUrl);
assertHeader(appResponse, 'Cache-Control', 'no-cache, no-store, must-revalidate');
assertStandardHeaders(appResponse, { skipHsts: loopbackHttp });
assert(/^(application|text)\/javascript(?:;|$)/i.test(appResponse.headers.get('Content-Type') || ''), 'Unsafe application MIME type');
const appBytes = new Uint8Array(await appResponse.arrayBuffer());
const { createHash } = await import('node:crypto');
const sri = `sha384-${createHash('sha384').update(appBytes).digest('base64')}`;
assert(documentHtml.includes(`integrity="${sri}"`), 'Served app/embedded worker does not match HTML integrity');
const separateWorker = await fetch(new URL('assets/worker.js', deploymentUrl), { redirect: 'error', signal: AbortSignal.timeout(10000) });
assert(separateWorker.status === 404, 'An independently delivered worker remains available');

console.log(`Live security-header verification: PASS (${deploymentUrl.origin})`);
