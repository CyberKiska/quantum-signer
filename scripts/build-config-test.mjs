import { normalizeBasePath, normalizeBuildCommit } from './build.mjs';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

assert(normalizeBasePath('') === '/', 'empty BASE_PATH did not normalize to root');
assert(normalizeBasePath('repo') === '/repo/', 'repository BASE_PATH did not normalize canonically');
assert(normalizeBasePath('/a/b/') === '/a/b/', 'nested BASE_PATH did not remain canonical');

for (const invalid of [
  '/a/../b/',
  '/a//b/',
  '/a?x=1/',
  '/a" onload="x/',
  '/a&amp;b/',
  '/a\\b/',
  '/a/%2e%2e/',
]) {
  let rejected = false;
  try {
    normalizeBasePath(invalid);
  } catch (_err) {
    rejected = true;
  }
  assert(rejected, `unsafe BASE_PATH was accepted: ${invalid}`);
}

assert(normalizeBuildCommit() === 'local', 'missing BUILD_COMMIT did not normalize to local');
assert(
  normalizeBuildCommit('0123456789abcdef0123456789abcdef01234567') ===
    '0123456789abcdef0123456789abcdef01234567',
  'valid BUILD_COMMIT was rejected'
);

for (const invalid of ['main', 'ABCDEF', '0123', '0'.repeat(65)]) {
  let rejected = false;
  try {
    normalizeBuildCommit(invalid);
  } catch (_err) {
    rejected = true;
  }
  assert(rejected, `unsafe BUILD_COMMIT was accepted: ${invalid}`);
}

console.log('Build configuration validation tests: PASS');
