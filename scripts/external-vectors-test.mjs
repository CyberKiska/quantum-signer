import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  getPublicKeyFromSecret,
  signBytes,
  verifyBytes,
} from '../src/crypto/algorithms.js';
import { wipeBytes } from '../src/crypto/bytes.js';
import { SuiteId } from '../src/crypto/suite-metadata.js';

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

function base64ToBytes(value, field) {
  assert(typeof value === 'string' && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value), `${field} is not canonical base64`);
  const bytes = Uint8Array.from(Buffer.from(value, 'base64'));
  assert(Buffer.from(bytes).toString('base64') === value, `${field} has non-canonical pad bits`);
  return bytes;
}

async function testPinnedNistSignatureGenerationVectors() {
  const vectorPath = path.join(path.dirname(new URL(import.meta.url).pathname), 'nist-acvp-mldsa-siggen-vectors.json');
  const vectorBytes = await readFile(vectorPath);
  const vectors = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(vectorBytes));
  assert(vectors.schema === 'quantum-signer-nist-acvp-mldsa-siggen/v1', 'unexpected NIST sigGen vector schema');
  assert(vectors.source?.commit === 'a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324', 'unexpected NIST ACVP source commit');
  assert(vectors.vectors?.length === 3, 'expected one NIST sigGen vector per ML-DSA parameter set');

  const suites = {
    'ML-DSA-44': SuiteId.ML_DSA_44,
    'ML-DSA-65': SuiteId.ML_DSA_65,
    'ML-DSA-87': SuiteId.ML_DSA_87,
  };

  for (const vector of vectors.vectors) {
    const suiteId = suites[vector.parameterSet];
    assert(Number.isInteger(suiteId), `unsupported NIST vector parameter set: ${vector.parameterSet}`);
    const message = base64ToBytes(vector.messageBase64, `${vector.parameterSet} message`);
    const secretKey = base64ToBytes(vector.secretKeyBase64, `${vector.parameterSet} secret key`);
    const context = base64ToBytes(vector.contextBase64, `${vector.parameterSet} context`);
    let signature;
    let publicKey;
    try {
      signature = signBytes({
        suiteId,
        message,
        secretKey,
        hedged: false,
        contextBytes: context,
      });
      const actualDigest = createHash('sha256').update(signature).digest('hex');
      assert(
        actualDigest === vector.expectedSignatureSha256,
        `${vector.parameterSet} NIST ACVP sigGen tcId ${vector.tcId} mismatch`
      );
      publicKey = getPublicKeyFromSecret(suiteId, secretKey);
      const verifier = VECTOR_SPECS.find((spec) => spec.algorithm === vector.parameterSet)?.verifier;
      assert(verifier?.verify(signature, message, publicKey, { context }) === true, `${vector.parameterSet} generated NIST signature did not verify`);
      console.log(`  ${vector.parameterSet}: NIST ACVP deterministic sigGen PASS (tcId=${vector.tcId})`);
    } finally {
      wipeBytes(signature);
      wipeBytes(publicKey);
      wipeBytes(message);
      wipeBytes(secretKey);
      wipeBytes(context);
    }
  }
}

async function testPinnedNistSlhSignatureGenerationVectors() {
  const vectorPath = path.join(path.dirname(new URL(import.meta.url).pathname), 'nist-acvp-slhdsa-siggen-vectors.json');
  const vectorBytes = await readFile(vectorPath);
  const vectors = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(vectorBytes));
  assert(vectors.schema === 'quantum-signer-nist-acvp-slhdsa-siggen/v1', 'unexpected NIST SLH sigGen vector schema');
  assert(vectors.source?.commit === 'a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324', 'unexpected NIST SLH ACVP source commit');
  assert(vectors.vectors?.length === 3, 'expected one NIST sigGen vector per supported SLH-DSA parameter set');

  const suites = {
    'SLH-DSA-SHAKE-128s': SuiteId.SLH_DSA_SHAKE_128S,
    'SLH-DSA-SHAKE-192s': SuiteId.SLH_DSA_SHAKE_192S,
    'SLH-DSA-SHAKE-256s': SuiteId.SLH_DSA_SHAKE_256S,
  };

  for (const vector of vectors.vectors) {
    const suiteId = suites[vector.parameterSet];
    assert(Number.isInteger(suiteId), `unsupported NIST vector parameter set: ${vector.parameterSet}`);
    const message = base64ToBytes(vector.messageBase64, `${vector.parameterSet} message`);
    const secretKey = base64ToBytes(vector.secretKeyBase64, `${vector.parameterSet} secret key`);
    const context = base64ToBytes(vector.contextBase64, `${vector.parameterSet} context`);
    let signature;
    let publicKey;
    try {
      signature = signBytes({
        suiteId,
        message,
        secretKey,
        hedged: false,
        contextBytes: context,
      });
      const actualDigest = createHash('sha256').update(signature).digest('hex');
      assert(
        actualDigest === vector.expectedSignatureSha256,
        `${vector.parameterSet} NIST ACVP sigGen tcId ${vector.tcId} mismatch`
      );
      publicKey = getPublicKeyFromSecret(suiteId, secretKey);
      assert(
        verifyBytes({ suiteId, message, signature, publicKey, contextBytes: context }) === true,
        `${vector.parameterSet} generated NIST signature did not verify`
      );
      console.log(`  ${vector.parameterSet}: NIST ACVP deterministic sigGen PASS (tcId=${vector.tcId})`);
    } finally {
      wipeBytes(signature);
      wipeBytes(publicKey);
      wipeBytes(message);
      wipeBytes(secretKey);
      wipeBytes(context);
    }
  }
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
await testPinnedNistSignatureGenerationVectors();
await testPinnedNistSlhSignatureGenerationVectors();
