import {
  DEFAULT_CTX,
  bytesToHexLower,
  computeFingerprintBytes,
  generateKeypair,
  getSuite,
  hashBytesSHA3512,
  signBytes,
  verifyBytes,
} from './algorithms.js';
import {
  FORMAT_VERSION_MAJOR,
  FORMAT_VERSION_MINOR,
  FingerprintAlgId,
  HashAlgId,
  SuiteId,
  buildTBSV1,
  packPublicKeyV1,
  packSecretKeyV1,
  packSignatureV1,
  packSignerFingerprint,
  unpackPublicKeyV1,
  unpackSecretKeyV1,
  unpackSignatureV1,
} from '../formats/containers.js';
import { wipeBytes } from './bytes.js';

const QUICK_TEST_SUITES = [
  SuiteId.ML_DSA_44,
  SuiteId.ML_DSA_65,
  SuiteId.ML_DSA_87,
  SuiteId.SLH_DSA_SHAKE_128S,
];

const FULL_EXTRA_SUITES = [
  SuiteId.SLH_DSA_SHAKE_192S,
  SuiteId.SLH_DSA_SHAKE_256S,
];

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function buildTbs(suiteId, fileHash) {
  return buildTBSV1({
    formatVerMajor: FORMAT_VERSION_MAJOR,
    formatVerMinor: FORMAT_VERSION_MINOR,
    suiteId,
    hashAlgId: HashAlgId.SHA3_512,
    ctxBytes: textBytes(DEFAULT_CTX),
    fileHash,
  });
}

function buildSignatureContainer({ suiteId, payloadBytes, secretKey, publicKey }) {
  const fileHash = hashBytesSHA3512(payloadBytes);
  const tbs = buildTbs(suiteId, fileHash);
  const signature = signBytes({
    suiteId,
    message: tbs,
    secretKey,
    hedged: true,
  });

  const signerFingerprint = packSignerFingerprint({
    algId: FingerprintAlgId.SHA3_256,
    digest: computeFingerprintBytes(publicKey),
  });

  const sigFile = packSignatureV1({
    suiteId,
    hashAlgId: HashAlgId.SHA3_512,
    fileHash,
    signature,
    ctx: DEFAULT_CTX,
    metadata: {
      filename: 'self-test.txt',
      filesize: BigInt(payloadBytes.length),
      createdAt: '2025-01-01T00:00:00.000Z',
      signerPublicKey: publicKey,
      signerFingerprint,
    },
  });

  return { sigFile, fileHash };
}

async function runCase(name, fn) {
  try {
    await fn();
    return { name, ok: true };
  } catch (err) {
    return {
      name,
      ok: false,
      error: err?.message || String(err),
    };
  }
}

function buildCases(suites) {
  const cases = [];

  for (const suiteId of suites) {
    const suite = getSuite(suiteId);
    const prefix = suite.name;

    cases.push({
      name: `${prefix}: keygen -> sign -> verify`,
      fn: async () => {
        const keys = generateKeypair(suiteId);
        const publicKeyFile = packPublicKeyV1({ suiteId, keyBytes: keys.publicKey });
        const secretKeyFile = packSecretKeyV1({ suiteId, keyBytes: keys.secretKey });

        const parsedPublic = unpackPublicKeyV1(publicKeyFile);
        const parsedSecret = unpackSecretKeyV1(secretKeyFile);

        const payload = textBytes('quantum-signer self-test payload');
        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: payload,
          secretKey: parsedSecret.keyBytes,
          publicKey: parsedPublic.keyBytes,
        });

        const parsedSig = unpackSignatureV1(sigFile);
        const valid = verifyBytes({
          suiteId,
          message: parsedSig.tbs,
          signature: parsedSig.signature,
          publicKey: parsedPublic.keyBytes,
        });

        wipeBytes(parsedSecret.keyBytes);

        if (!valid) {
          throw new Error('valid signature failed verification');
        }
      },
    });

    cases.push({
      name: `${prefix}: verify must fail on modified file`,
      fn: async () => {
        const keys = generateKeypair(suiteId);
        const originalPayload = textBytes('payload-original');
        const modifiedPayload = textBytes('payload-modified');

        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: originalPayload,
          secretKey: keys.secretKey,
          publicKey: keys.publicKey,
        });

        const parsedSig = unpackSignatureV1(sigFile);
        const modifiedHash = hashBytesSHA3512(modifiedPayload);
        if (bytesToHexLower(modifiedHash) === bytesToHexLower(parsedSig.fileHash)) {
          throw new Error('hash collision in self-test input vectors');
        }
        const modifiedTbs = buildTbs(suiteId, modifiedHash);
        const valid = verifyBytes({
          suiteId,
          message: modifiedTbs,
          signature: parsedSig.signature,
          publicKey: keys.publicKey,
        });
        if (valid) {
          throw new Error('signature unexpectedly verified for modified payload');
        }
      },
    });

    cases.push({
      name: `${prefix}: verify must fail with wrong public key`,
      fn: async () => {
        const keyA = generateKeypair(suiteId);
        const keyB = generateKeypair(suiteId);
        const payload = textBytes('wrong-key-check');

        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: payload,
          secretKey: keyA.secretKey,
          publicKey: keyA.publicKey,
        });

        const parsedSig = unpackSignatureV1(sigFile);
        const valid = verifyBytes({
          suiteId,
          message: parsedSig.tbs,
          signature: parsedSig.signature,
          publicKey: keyB.publicKey,
        });

        if (valid) {
          throw new Error('signature unexpectedly verified with wrong key');
        }
      },
    });

    cases.push({
      name: `${prefix}: tampered signature must fail`,
      fn: async () => {
        const keys = generateKeypair(suiteId);
        const fileHash = hashBytesSHA3512(textBytes('tamper-check'));
        const tbs = buildTbs(suiteId, fileHash);
        const signature = signBytes({ suiteId, message: tbs, secretKey: keys.secretKey, hedged: true });
        signature[0] ^= 0x01;

        const valid = verifyBytes({
          suiteId,
          message: tbs,
          signature,
          publicKey: keys.publicKey,
        });

        if (valid) {
          throw new Error('tampered signature unexpectedly verified');
        }
      },
    });
  }

  cases.push({
    name: 'malformed signature container must fail parse',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_87);
      const payload = textBytes('malformed-check');
      const { sigFile } = buildSignatureContainer({
        suiteId: SuiteId.ML_DSA_87,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });
      sigFile[0] = 0x00;
      let failed = false;
      try {
        unpackSignatureV1(sigFile);
      } catch (_err) {
        failed = true;
      }
      if (!failed) {
        throw new Error('invalid magic unexpectedly parsed');
      }
    },
  });

  return cases;
}

export async function runSelfTest({ full = false, onProgress } = {}) {
  const suites = full ? [...QUICK_TEST_SUITES, ...FULL_EXTRA_SUITES] : QUICK_TEST_SUITES;
  const cases = buildCases(suites);
  const results = [];

  if (typeof onProgress === 'function') {
    onProgress(0, cases.length, 'Starting self-test');
  }

  for (let i = 0; i < cases.length; i += 1) {
    const current = cases[i];
    const result = await runCase(current.name, current.fn);
    results.push(result);
    if (typeof onProgress === 'function') {
      onProgress(i + 1, cases.length, current.name);
    }
  }

  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;

  return {
    ok: failed === 0,
    total: results.length,
    passed,
    failed,
    results,
    suites,
    suitesHex: suites.map((id) => bytesToHexLower(Uint8Array.of(id))),
    full,
  };
}
