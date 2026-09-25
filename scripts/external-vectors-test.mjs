import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  getPublicKeyFromSecret,
  signBytes,
  verifyBytes,
} from './lib/reference-pq.mjs';
import { wipeBytes } from '../src/crypto/bytes.js';
import { SuiteId } from '../src/crypto/suite-metadata.js';
import { importMlDsaSeed, publicKeyBytes, verifyBytes as verifyNative } from '../src/native/crypto.js';
import { verifyBytes as verifyBrowser } from '../src/crypto/browser-verification.js';

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
      const suiteId = { 'ML-DSA-44': 1, 'ML-DSA-65': 2, 'ML-DSA-87': 3 }[spec.algorithm];
      const args = { suiteId, publicKey, signature, message, contextBytes: options.context };
      assert(verifyNative(args) === expected, `Native ${spec.algorithm} tcId ${test.tcId} mismatch`);
      assert(verifyBrowser(args) === expected, `Browser ${spec.algorithm} tcId ${test.tcId} mismatch`);
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

// Pinned NIST ACVP files (internalProjection.json carries expected results).
// Set ACVP_DIR to a directory with <name>.json to run offline.
const ACVP_COMMIT = 'a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324';
const ACVP_FILES = Object.freeze({
  'ML-DSA-sigVer-FIPS204': '47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437',
  'SLH-DSA-sigVer-FIPS205': 'a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792',
  'ML-DSA-keyGen-FIPS204': 'e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf',
});
const SUITE_IDS = Object.freeze({
  'ML-DSA-44': SuiteId.ML_DSA_44, 'ML-DSA-65': SuiteId.ML_DSA_65, 'ML-DSA-87': SuiteId.ML_DSA_87,
  'SLH-DSA-SHAKE-128s': SuiteId.SLH_DSA_SHAKE_128S, 'SLH-DSA-SHAKE-192s': SuiteId.SLH_DSA_SHAKE_192S,
  'SLH-DSA-SHAKE-256s': SuiteId.SLH_DSA_SHAKE_256S,
});

async function loadAcvp(name) {
  const bytes = process.env.ACVP_DIR
    ? await readFile(path.join(process.env.ACVP_DIR, `${name}.json`))
    : new Uint8Array(await (await fetch(
      `https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files/${name}/internalProjection.json`,
      { redirect: 'error', signal: AbortSignal.timeout(120_000) })).arrayBuffer());
  assert(createHash('sha256').update(bytes).digest('hex') === ACVP_FILES[name], `${name} ACVP digest mismatch`);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

// sigVer: the QSIG profile is the pure, external interface (FIPS 204 Alg. 3,
// FIPS 205 Alg. 24) for the six supported parameter sets.
for (const name of ['ML-DSA-sigVer-FIPS204', 'SLH-DSA-sigVer-FIPS205']) {
  const file = await loadAcvp(name);
  let valid = 0;
  let invalid = 0;
  for (const group of file.testGroups) {
    const suiteId = SUITE_IDS[group.parameterSet];
    if (suiteId === undefined || group.signatureInterface !== 'external' || group.preHash !== 'pure' || group.externalMu) continue;
    for (const test of group.tests) {
      const args = {
        suiteId,
        publicKey: hexToBytes((test.pk ?? group.pk).toLowerCase(), `${name} tcId ${test.tcId} pk`),
        signature: hexToBytes(test.signature.toLowerCase(), `${name} tcId ${test.tcId} signature`),
        message: hexToBytes(test.message.toLowerCase(), `${name} tcId ${test.tcId} message`),
        contextBytes: hexToBytes((test.context ?? '').toLowerCase(), `${name} tcId ${test.tcId} context`),
      };
      assert(verifyNative(args) === test.testPassed, `Native ${name} tcId ${test.tcId} mismatch (${test.reason})`);
      assert(verifyBrowser(args) === test.testPassed, `Browser ${name} tcId ${test.tcId} mismatch (${test.reason})`);
      if (test.testPassed) valid += 1; else invalid += 1;
    }
  }
  assert(valid > 0 && invalid > 0, `${name} did not exercise acceptance and rejection`);
  console.log(`  ${name}: native and browser PASS (valid=${valid}, invalid=${invalid})`);
}

// keyGen: FIPS 204 ML-DSA.KeyGen from ACVP seeds through native RFC 9881 seed import.
{
  const file = await loadAcvp('ML-DSA-keyGen-FIPS204');
  let count = 0;
  for (const group of file.testGroups) {
    const suiteId = SUITE_IDS[group.parameterSet];
    for (const test of group.tests) {
      const key = importMlDsaSeed(suiteId, hexToBytes(test.seed.toLowerCase(), `keyGen tcId ${test.tcId} seed`));
      assert(Buffer.from(publicKeyBytes(suiteId, key)).equals(Buffer.from(test.pk, 'hex')), `ML-DSA keyGen tcId ${test.tcId} public key mismatch`);
      count += 1;
    }
  }
  console.log(`  ML-DSA-keyGen-FIPS204: native PASS (${count} seeds)`);
}
console.log('Pinned NIST ACVP sigVer/keyGen vectors: PASS');
