import {
  QSIG_V2_DEFAULT_CTX,
  bytesToHexLower,
  computeFingerprintBytes,
  generateKeypair,
  getSuite,
  hashBytesSHA3512,
  hashFileSHA3512,
  signBytes,
  verifyBytes,
} from './algorithms.js';
import {
  MAX_CONTEXT_BYTES,
  MAX_PAYLOAD_FILE_BYTES,
  MAX_SIGNATURE_BYTES,
} from './policy.js';
import {
  AuthDigestAlgId,
  FingerprintAlgId,
  HashAlgId,
  SignatureProfileId,
  SuiteId,
  buildTBSV2,
  computeAuthMetaDigestV2,
  packPublicKeyV1,
  packSecretKeyV1,
  packAuthenticatedMetadataV2,
  packSignatureV2,
  packSignerFingerprint,
  unpackPublicKeyV1,
  unpackSecretKeyV1,
  unpackSignatureV2,
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

function buildContextBytes() {
  return textBytes(QSIG_V2_DEFAULT_CTX);
}

function buildTbs(suiteId, fileHash, authMetaDigest) {
  return buildTBSV2({
    suiteId,
    signatureProfileId: SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
    payloadDigestAlgId: HashAlgId.SHA3_512,
    authDigestAlgId: AuthDigestAlgId.SHA3_256,
    payloadDigest: fileHash,
    authMetaDigest,
  });
}

function buildSignatureContainer({ suiteId, payloadBytes, secretKey, publicKey }) {
  const fileHash = hashBytesSHA3512(payloadBytes);
  const signerFingerprint = packSignerFingerprint({
    algId: FingerprintAlgId.SHA3_256,
    digest: computeFingerprintBytes(publicKey),
  });
  const authenticatedMetadata = {
    signerPublicKey: publicKey,
    signerFingerprint,
  };
  const authMetaBytes = packAuthenticatedMetadataV2(authenticatedMetadata);
  const authMetaDigest = computeAuthMetaDigestV2(authMetaBytes, AuthDigestAlgId.SHA3_256);
  const tbs = buildTbs(suiteId, fileHash, authMetaDigest);
  const signature = signBytes({
    suiteId,
    message: tbs,
    secretKey,
    hedged: true,
    contextBytes: buildContextBytes(),
  });

  const sigFile = packSignatureV2({
    suiteId,
    signatureProfileId: SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
    payloadDigestAlgId: HashAlgId.SHA3_512,
    authDigestAlgId: AuthDigestAlgId.SHA3_256,
    payloadDigest: fileHash,
    authMetaDigest,
    signature,
    ctx: QSIG_V2_DEFAULT_CTX,
    authenticatedMetadata,
    displayMetadata: {
      filename: 'self-test.txt',
      filesize: BigInt(payloadBytes.length),
      createdAt: '2025-01-01T00:00:00.000Z',
    },
  });

  wipeBytes(authMetaBytes);
  return { sigFile, fileHash, authMetaDigest };
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

        const parsedSig = unpackSignatureV2(sigFile);
        const valid = verifyBytes({
          suiteId,
          message: parsedSig.tbs,
          signature: parsedSig.signature,
          publicKey: parsedPublic.keyBytes,
          contextBytes: parsedSig.ctxBytes,
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

        const parsedSig = unpackSignatureV2(sigFile);
        const modifiedHash = hashBytesSHA3512(modifiedPayload);
        if (bytesToHexLower(modifiedHash) === bytesToHexLower(parsedSig.fileHash)) {
          throw new Error('hash collision in self-test input vectors');
        }
        const modifiedTbs = buildTbs(suiteId, modifiedHash, parsedSig.authMetaDigest);
        const valid = verifyBytes({
          suiteId,
          message: modifiedTbs,
          signature: parsedSig.signature,
          publicKey: keys.publicKey,
          contextBytes: parsedSig.ctxBytes,
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

        const parsedSig = unpackSignatureV2(sigFile);
        const valid = verifyBytes({
          suiteId,
          message: parsedSig.tbs,
          signature: parsedSig.signature,
          publicKey: keyB.publicKey,
          contextBytes: parsedSig.ctxBytes,
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
        const signerFingerprint = packSignerFingerprint({
          algId: FingerprintAlgId.SHA3_256,
          digest: computeFingerprintBytes(keys.publicKey),
        });
        const authMetaBytes = packAuthenticatedMetadataV2({
          signerPublicKey: keys.publicKey,
          signerFingerprint,
        });
        const authMetaDigest = computeAuthMetaDigestV2(authMetaBytes, AuthDigestAlgId.SHA3_256);
        const tbs = buildTbs(suiteId, fileHash, authMetaDigest);
        const signature = signBytes({
          suiteId,
          message: tbs,
          secretKey: keys.secretKey,
          hedged: true,
          contextBytes: buildContextBytes(),
        });
        signature[0] ^= 0x01;
        wipeBytes(authMetaBytes);

        const valid = verifyBytes({
          suiteId,
          message: tbs,
          signature,
          publicKey: keys.publicKey,
          contextBytes: buildContextBytes(),
        });

        if (valid) {
          throw new Error('tampered signature unexpectedly verified');
        }
      },
    });

    cases.push({
      name: `${prefix}: context mismatch must fail`,
      fn: async () => {
        const keys = generateKeypair(suiteId);
        const payload = textBytes('context-mismatch-check');

        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: payload,
          secretKey: keys.secretKey,
          publicKey: keys.publicKey,
        });

        const parsedSig = unpackSignatureV2(sigFile);
        const wrongContext = textBytes(`${QSIG_V2_DEFAULT_CTX}/wrong`);
        const valid = verifyBytes({
          suiteId,
          message: parsedSig.tbs,
          signature: parsedSig.signature,
          publicKey: keys.publicKey,
          contextBytes: wrongContext,
        });

        if (valid) {
          throw new Error('signature unexpectedly verified with wrong context');
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
        unpackSignatureV2(sigFile);
      } catch (_err) {
        failed = true;
      }
      if (!failed) {
        throw new Error('invalid magic unexpectedly parsed');
      }
    },
  });

  cases.push({
    name: 'tampered authenticated metadata must fail parse',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_87);
      const payload = textBytes('auth-meta-check');
      const { sigFile } = buildSignatureContainer({
        suiteId: SuiteId.ML_DSA_87,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });

      const tampered = Uint8Array.from(sigFile);
      const ctxLen = textBytes(QSIG_V2_DEFAULT_CTX).length;
      const headerLen = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + 64 + 32 + 1 + 1 + 2 + 2 + 4;
      tampered[headerLen + ctxLen + 8] ^= 0x01;

      let failed = false;
      try {
        unpackSignatureV2(tampered);
      } catch (_err) {
        failed = true;
      }

      if (!failed) {
        throw new Error('tampered authenticated metadata unexpectedly parsed');
      }
    },
  });

  cases.push({
    name: 'oversized context bytes must be rejected',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_44);
      let failed = false;
      try {
        signBytes({
          suiteId: SuiteId.ML_DSA_44,
          message: textBytes('context-limit'),
          secretKey: keys.secretKey,
          hedged: true,
          contextBytes: new Uint8Array(MAX_CONTEXT_BYTES + 1),
        });
      } catch (_err) {
        failed = true;
      }
      if (!failed) {
        throw new Error('oversized context unexpectedly accepted');
      }
    },
  });

  cases.push({
    name: 'oversized signature bytes must be rejected',
    fn: async () => {
      const signerPublicKey = new Uint8Array(32);
      const signerFingerprint = packSignerFingerprint({
        algId: FingerprintAlgId.SHA3_256,
        digest: computeFingerprintBytes(signerPublicKey),
      });
      const authenticatedMetadata = {
        signerPublicKey,
        signerFingerprint,
      };
      const authMetaBytes = packAuthenticatedMetadataV2(authenticatedMetadata);
      const authMetaDigest = computeAuthMetaDigestV2(authMetaBytes, AuthDigestAlgId.SHA3_256);
      let failed = false;
      try {
        packSignatureV2({
          suiteId: SuiteId.ML_DSA_44,
          signatureProfileId: SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
          payloadDigestAlgId: HashAlgId.SHA3_512,
          authDigestAlgId: AuthDigestAlgId.SHA3_256,
          payloadDigest: new Uint8Array(64),
          authMetaDigest,
          signature: new Uint8Array(MAX_SIGNATURE_BYTES + 1),
          ctx: QSIG_V2_DEFAULT_CTX,
          authenticatedMetadata,
          displayMetadata: {},
        });
      } catch (_err) {
        failed = true;
      }
      wipeBytes(authMetaBytes);
      if (!failed) {
        throw new Error('oversized signature unexpectedly accepted');
      }
    },
  });

  cases.push({
    name: 'oversized payload file must be rejected',
    fn: async () => {
      const oversizedFile = {
        size: MAX_PAYLOAD_FILE_BYTES + 1,
        slice() {
          throw new Error('slice should not be called for oversized input');
        },
      };

      let failed = false;
      try {
        await hashFileSHA3512(oversizedFile);
      } catch (_err) {
        failed = true;
      }
      if (!failed) {
        throw new Error('oversized payload file unexpectedly accepted');
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
