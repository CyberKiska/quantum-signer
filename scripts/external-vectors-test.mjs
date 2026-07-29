import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const WYCHEPROOF_COMMIT = 'b61843a9a5115bb758134b6a1f5d5e502d445342';
const VECTOR_SPECS = Object.freeze([
  {
    algorithm: 'ML-DSA-44',
    filename: 'mldsa_44_verify_test.json',
    sha256: '5ec04790c240c443ca8b662b8fc871834602c7cce87fcd36a193110745b2b9ea',
    numberOfTests: 180,
    verifier: ml_dsa44,
  },
  {
    algorithm: 'ML-DSA-65',
    filename: 'mldsa_65_verify_test.json',
    sha256: '5b3ac930c9a38cbfc672cb85eed5ff0db8fcc2c0ac0541821b7d3247bb3956c0',
    numberOfTests: 210,
    verifier: ml_dsa65,
  },
  {
    algorithm: 'ML-DSA-87',
    filename: 'mldsa_87_verify_test.json',
    sha256: 'f788d3b9f50b9048e7a8825972b344800c6e3d3a9f6ed3982da076d24da262b4',
    numberOfTests: 241,
    verifier: ml_dsa87,
  },
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function hexToBytes(value, field) {
  assert(typeof value === 'string', `${field} is not a string`);
  assert(value.length % 2 === 0 && /^[0-9a-f]*$/u.test(value), `${field} is not canonical lowercase hex`);
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

async function loadPinnedVectorBytes(spec) {
  const localDirectory = process.env.WYCHEPROOF_VECTOR_DIR;
  if (localDirectory) return new Uint8Array(await readFile(path.join(localDirectory, spec.filename)));

  const url =
    `https://raw.githubusercontent.com/C2SP/wycheproof/${WYCHEPROOF_COMMIT}` +
    `/testvectors_v1/${spec.filename}`;
  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });
  assert(response.ok, `failed to fetch pinned Wycheproof vector: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

const failures = [];
let totalPassed = 0;
let totalTests = 0;

for (const spec of VECTOR_SPECS) {
  const vectorBytes = await loadPinnedVectorBytes(spec);
  const actualDigest = createHash('sha256').update(vectorBytes).digest('hex');
  assert(
    actualDigest === spec.sha256,
    `${spec.algorithm} vector digest mismatch: expected ${spec.sha256}, got ${actualDigest}`
  );

  const vectors = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(vectorBytes));
  assert(vectors.algorithm === spec.algorithm, `unexpected vector algorithm: ${vectors.algorithm}`);
  assert(vectors.schema === 'mldsa_verify_schema.json', `unexpected vector schema: ${vectors.schema}`);
  assert(
    vectors.numberOfTests === spec.numberOfTests,
    `${spec.algorithm}: unexpected declared vector count: ${vectors.numberOfTests}`
  );

  let passed = 0;
  let validCases = 0;
  let invalidCases = 0;
  for (const [groupIndex, group] of vectors.testGroups.entries()) {
    const publicKey = hexToBytes(group.publicKey, `${spec.algorithm} testGroups[${groupIndex}].publicKey`);
    for (const test of group.tests) {
      const signature = hexToBytes(test.sig, `${spec.algorithm} tcId ${test.tcId} signature`);
      const message = hexToBytes(test.msg, `${spec.algorithm} tcId ${test.tcId} message`);
      const options = test.ctx === undefined
        ? {}
        : { context: hexToBytes(test.ctx, `${spec.algorithm} tcId ${test.tcId} context`) };

      let actual = false;
      try {
        actual = spec.verifier.verify(signature, message, publicKey, options) === true;
      } catch (error) {
        // Malformed keys, signatures, and overlong contexts are invalid test
        // cases; a defensive parser may reject them before returning false.
        actual = false;
      }

      const expected = test.result === 'valid';
      if (expected) validCases += 1;
      else invalidCases += 1;
      if (actual === expected) passed += 1;
      else failures.push(`${spec.algorithm} tcId ${test.tcId}: expected ${test.result}, got ${actual ? 'valid' : 'invalid'}`);
    }
  }

  assert(passed === vectors.numberOfTests, failures.slice(0, 10).join('\n'));
  assert(validCases > 0 && invalidCases > 0, `${spec.algorithm} did not exercise acceptance and rejection`);
  totalPassed += passed;
  totalTests += vectors.numberOfTests;
  console.log(
    `  ${spec.algorithm}: PASS (${passed}/${vectors.numberOfTests}; valid=${validCases}, invalid=${invalidCases})`
  );
}

console.log(`Pinned Wycheproof ML-DSA verification vectors: PASS (${totalPassed}/${totalTests})`);
