import {
  QSIG_DEFAULT_CTX,
  bytesToHexLower,
  computeFingerprintBytes,
  getDefaultSignatureProfileId,
  generateKeypair,
  getPublicKeyFromSecret,
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
import { createSecretSessionManager } from './secret-session.js';
import { finalizeVerification } from './verify-policy.js';
import {
  AuthDigestAlgId,
  FingerprintAlgId,
  HashAlgId,
  SignatureProfileId,
  SuiteId,
  buildTBSV2,
  computeAuthMetaDigestV2,
  packPublicKey,
  packSecretKey,
  packAuthenticatedMetadataV2,
  packSignatureV2,
  packSignerFingerprint,
  unpackPublicKey,
  unpackSecretKey,
  unpackSignatureV2,
} from '../formats/containers.js';
import { wipeBytes } from './bytes.js';

const QSIG_V2_SIG_HEADER_LENGTH = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + 64 + 32 + 1 + 1 + 2 + 2 + 4;

const QUICK_TEST_SUITES = [
  SuiteId.ML_DSA_44,
  SuiteId.ML_DSA_65,
  SuiteId.ML_DSA_87,
  SuiteId.SLH_DSA_SHAKE_128S,
  SuiteId.FALCON_512_PADDED,
];

const FULL_EXTRA_SUITES = [
  SuiteId.SLH_DSA_SHAKE_192S,
  SuiteId.SLH_DSA_SHAKE_256S,
  SuiteId.FALCON_1024_PADDED,
];

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function buildContextBytes() {
  return textBytes(QSIG_DEFAULT_CTX);
}

function buildTbs(
  suiteId,
  fileHash,
  authMetaDigest,
  signatureProfileId = getDefaultSignatureProfileId(suiteId)
) {
  return buildTBSV2({
    suiteId,
    signatureProfileId,
    payloadDigestAlgId: HashAlgId.SHA3_512,
    authDigestAlgId: AuthDigestAlgId.SHA3_256,
    payloadDigest: fileHash,
    authMetaDigest,
  });
}

function getAuthMetadataOffsets(sigFile) {
  const view = new DataView(sigFile.buffer, sigFile.byteOffset, sigFile.byteLength);
  const ctxLen = sigFile[108];
  const authMetaLen = view.getUint16(110, true);
  const authMetaOffset = QSIG_V2_SIG_HEADER_LENGTH + ctxLen;
  return {
    authMetaOffset,
    authMetaLen,
  };
}

function getDisplayMetadataOffsets(sigFile) {
  const view = new DataView(sigFile.buffer, sigFile.byteOffset, sigFile.byteLength);
  const ctxLen = sigFile[108];
  const authMetaLen = view.getUint16(110, true);
  const displayMetaLen = view.getUint16(112, true);
  const displayMetaOffset = QSIG_V2_SIG_HEADER_LENGTH + ctxLen + authMetaLen;
  return {
    displayMetaOffset,
    displayMetaLen,
  };
}

function getSecondAuthMetaRecordOffset(sigFile) {
  const { authMetaOffset } = getAuthMetadataOffsets(sigFile);
  const view = new DataView(sigFile.buffer, sigFile.byteOffset, sigFile.byteLength);
  const firstLen = view.getUint16(authMetaOffset + 1, true);
  return authMetaOffset + 3 + firstLen;
}

function buildSignatureContainer({ suiteId, payloadBytes, secretKey, publicKey, embeddedPublicKey = publicKey }) {
  const fileHash = hashBytesSHA3512(payloadBytes);
  const signatureProfileId = getDefaultSignatureProfileId(suiteId);
  const signerFingerprint = packSignerFingerprint({
    algId: FingerprintAlgId.SHA3_256,
    digest: computeFingerprintBytes(embeddedPublicKey),
  });
  const authenticatedMetadata = {
    signerPublicKey: embeddedPublicKey,
    signerFingerprint,
  };
  const authMetaBytes = packAuthenticatedMetadataV2(authenticatedMetadata);
  const authMetaDigest = computeAuthMetaDigestV2(authMetaBytes, AuthDigestAlgId.SHA3_256);
  const tbs = buildTbs(suiteId, fileHash, authMetaDigest, signatureProfileId);
  const signature = signBytes({
    suiteId,
    signatureProfileId,
    message: tbs,
    secretKey,
    hedged: true,
    contextBytes: buildContextBytes(),
  });

  const sigFile = packSignatureV2({
    suiteId,
    signatureProfileId,
    payloadDigestAlgId: HashAlgId.SHA3_512,
    authDigestAlgId: AuthDigestAlgId.SHA3_256,
    payloadDigest: fileHash,
    authMetaDigest,
    signature,
    ctx: QSIG_DEFAULT_CTX,
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
        const publicKeyFile = packPublicKey({ suiteId, keyBytes: keys.publicKey });
        const secretKeyFile = packSecretKey({ suiteId, keyBytes: keys.secretKey });

        const parsedPublic = unpackPublicKey(publicKeyFile);
        const parsedSecret = unpackSecretKey(secretKeyFile);

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
          signatureProfileId: parsedSig.signatureProfileId,
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
        const modifiedTbs = buildTbs(suiteId, modifiedHash, parsedSig.authMetaDigest, parsedSig.signatureProfileId);
        const valid = verifyBytes({
          suiteId,
          signatureProfileId: parsedSig.signatureProfileId,
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
          signatureProfileId: parsedSig.signatureProfileId,
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
        const signatureProfileId = getDefaultSignatureProfileId(suiteId);
        const tbs = buildTbs(suiteId, fileHash, authMetaDigest, signatureProfileId);
        const signature = signBytes({
          suiteId,
          signatureProfileId,
          message: tbs,
          secretKey: keys.secretKey,
          hedged: true,
          contextBytes: buildContextBytes(),
        });
        signature[0] ^= 0x01;
        wipeBytes(authMetaBytes);

        const valid = verifyBytes({
          suiteId,
          signatureProfileId,
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
        const wrongContext = textBytes(`${QSIG_DEFAULT_CTX}/wrong`);
        const valid = verifyBytes({
          suiteId,
          signatureProfileId: parsedSig.signatureProfileId,
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

    cases.push({
      name: `${prefix}: embedded-only verification must stay valid with warning`,
      fn: async () => {
        const keys = generateKeypair(suiteId);
        const payload = textBytes('embedded-only-policy-check');
        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: payload,
          secretKey: keys.secretKey,
          publicKey: keys.publicKey,
        });

        const parsedSig = unpackSignatureV2(sigFile);
        const result = finalizeVerification(parsedSig, null, {
          inputKind: 'text',
          inputLength: payload.length,
        });

        if (!result.valid || !result.cryptoValid) {
          throw new Error('embedded-only verification unexpectedly failed');
        }
        if (result.trustSource !== 'embedded-only' || result.verifiedKeySource !== 'signature') {
          throw new Error('embedded-only verification returned wrong trust semantics');
        }
        if (typeof result.warning !== 'string' || result.warning.length === 0) {
          throw new Error('embedded-only verification is missing warning text');
        }
      },
    });

    cases.push({
      name: `${prefix}: wrong loaded key must produce mismatch semantics`,
      fn: async () => {
        const signingKeys = generateKeypair(suiteId);
        const wrongLoadedKeys = generateKeypair(suiteId);
        const payload = textBytes('wrong-loaded-key-policy-check');
        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: payload,
          secretKey: signingKeys.secretKey,
          publicKey: signingKeys.publicKey,
        });

        const parsedSig = unpackSignatureV2(sigFile);
        const wrongPublicKeyFile = packPublicKey({ suiteId, keyBytes: wrongLoadedKeys.publicKey });
        const result = finalizeVerification(parsedSig, wrongPublicKeyFile, {
          inputKind: 'text',
          inputLength: payload.length,
        });

        if (result.valid || !result.cryptoValid || result.keyMismatch !== true) {
          throw new Error('wrong loaded key did not produce mismatch semantics');
        }
        if (result.trustSource !== 'key-mismatch' || result.verifiedKeySource !== 'signature') {
          throw new Error('wrong loaded key mismatch trust semantics are incorrect');
        }
        if (result.loadedKeyValid !== false || result.embeddedKeyValid !== true) {
          throw new Error('wrong loaded key mismatch validity flags are incorrect');
        }
      },
    });

    cases.push({
      name: `${prefix}: inconsistent embedded metadata must still verify only with loaded key`,
      fn: async () => {
        const signingKeys = generateKeypair(suiteId);
        const embeddedKeys = generateKeypair(suiteId);
        const payload = textBytes('inconsistent-embedded-metadata-check');
        const { sigFile } = buildSignatureContainer({
          suiteId,
          payloadBytes: payload,
          secretKey: signingKeys.secretKey,
          publicKey: signingKeys.publicKey,
          embeddedPublicKey: embeddedKeys.publicKey,
        });

        const parsedSig = unpackSignatureV2(sigFile);
        const loadedPublicKeyFile = packPublicKey({ suiteId, keyBytes: signingKeys.publicKey });
        const result = finalizeVerification(parsedSig, loadedPublicKeyFile, {
          inputKind: 'text',
          inputLength: payload.length,
        });

        if (!result.valid || !result.cryptoValid || result.keyMismatch !== true) {
          throw new Error('inconsistent embedded metadata did not produce expected mismatch state');
        }
        if (result.trustSource !== 'key-mismatch' || result.verifiedKeySource !== 'loaded') {
          throw new Error('inconsistent embedded metadata trust semantics are incorrect');
        }
        if (result.loadedKeyValid !== true || result.embeddedKeyValid !== false) {
          throw new Error('inconsistent embedded metadata validity flags are incorrect');
        }
      },
    });
  }

  cases.push({
    name: 'Falcon-512-padded: mutating stored .qsig context must break verification',
    fn: async () => {
      const suiteId = SuiteId.FALCON_512_PADDED;
      const keys = generateKeypair(suiteId);
      const payload = textBytes('falcon-stored-context-check');
      const { sigFile } = buildSignatureContainer({
        suiteId,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });

      const tampered = Uint8Array.from(sigFile);
      const originalCtxLen = tampered[108];
      if (originalCtxLen === 0) {
        throw new Error('test vector unexpectedly missing context');
      }
      tampered[QSIG_V2_SIG_HEADER_LENGTH] ^= 0x01;

      const parsedSig = unpackSignatureV2(tampered);
      if (parsedSig.ctx === QSIG_DEFAULT_CTX) {
        throw new Error('stored context mutation did not change parsed context');
      }

      const valid = verifyBytes({
        suiteId,
        signatureProfileId: parsedSig.signatureProfileId,
        message: parsedSig.tbs,
        signature: parsedSig.signature,
        publicKey: keys.publicKey,
        contextBytes: parsedSig.ctxBytes,
      });

      if (valid) {
        throw new Error('Falcon signature unexpectedly verified after stored context mutation');
      }
    },
  });

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
      const { authMetaOffset } = getAuthMetadataOffsets(tampered);
      tampered[authMetaOffset + 8] ^= 0x01;

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
    name: 'unknown critical authenticated metadata tag must fail parse',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_87);
      const payload = textBytes('unknown-critical-tag-check');
      const { sigFile } = buildSignatureContainer({
        suiteId: SuiteId.ML_DSA_87,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });

      const tampered = Uint8Array.from(sigFile);
      const secondRecordOffset = getSecondAuthMetaRecordOffset(tampered);
      tampered[secondRecordOffset] = 0x80;

      let failed = false;
      try {
        unpackSignatureV2(tampered);
      } catch (_err) {
        failed = true;
      }

      if (!failed) {
        throw new Error('unknown critical auth metadata tag unexpectedly parsed');
      }
    },
  });

  cases.push({
    name: 'unsupported signer fingerprint alg id must fail parse',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_87);
      const payload = textBytes('unsupported-fingerprint-alg-check');
      const { sigFile } = buildSignatureContainer({
        suiteId: SuiteId.ML_DSA_87,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });

      const tampered = Uint8Array.from(sigFile);
      const secondRecordOffset = getSecondAuthMetaRecordOffset(tampered);
      tampered[secondRecordOffset + 3] = 0x02;

      let failed = false;
      try {
        unpackSignatureV2(tampered);
      } catch (_err) {
        failed = true;
      }

      if (!failed) {
        throw new Error('unsupported fingerprint alg unexpectedly parsed');
      }
    },
  });

  cases.push({
    name: 'invalid UTF-8 in display filename must fail parse',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_87);
      const payload = textBytes('invalid-display-utf8-check');
      const { sigFile } = buildSignatureContainer({
        suiteId: SuiteId.ML_DSA_87,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });

      const tampered = Uint8Array.from(sigFile);
      const { displayMetaOffset, displayMetaLen } = getDisplayMetadataOffsets(tampered);
      if (displayMetaLen < 5) {
        throw new Error('display metadata is unexpectedly too short for UTF-8 test');
      }
      tampered[displayMetaOffset + 3] = 0xc3;
      tampered[displayMetaOffset + 4] = 0x28;

      let failed = false;
      try {
        unpackSignatureV2(tampered);
      } catch (err) {
        failed = err?.code === 'E_FORMAT_TLV' && err?.details?.reason === 'invalid_utf8';
      }

      if (!failed) {
        throw new Error('invalid UTF-8 in display filename unexpectedly parsed');
      }
    },
  });

  cases.push({
    name: 'invalid UTF-8 in stored context must fail parse',
    fn: async () => {
      const keys = generateKeypair(SuiteId.ML_DSA_87);
      const payload = textBytes('invalid-context-utf8-check');
      const { sigFile } = buildSignatureContainer({
        suiteId: SuiteId.ML_DSA_87,
        payloadBytes: payload,
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
      });

      const tampered = Uint8Array.from(sigFile);
      const ctxLen = tampered[108];
      if (ctxLen < 2) {
        throw new Error('context is unexpectedly too short for UTF-8 test');
      }
      tampered[QSIG_V2_SIG_HEADER_LENGTH] = 0xc3;
      tampered[QSIG_V2_SIG_HEADER_LENGTH + 1] = 0x28;

      let failed = false;
      try {
        unpackSignatureV2(tampered);
      } catch (err) {
        failed = err?.code === 'E_FORMAT_TLV' && err?.details?.reason === 'invalid_utf8';
      }

      if (!failed) {
        throw new Error('invalid UTF-8 in stored context unexpectedly parsed');
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
          ctx: QSIG_DEFAULT_CTX,
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

  cases.push({
    name: 'secret session export must round-trip',
    fn: async () => {
      const manager = createSecretSessionManager();
      const session = manager.generateSession(SuiteId.ML_DSA_65);
      const exported = manager.exportSecretKeyFile(session.sessionHandle, session.exportConsentToken);
      const parsedSecret = unpackSecretKey(exported);
      const parsedPublic = unpackPublicKey(session.publicKeyFile);
      const derivedPublic = getPublicKeyFromSecret(parsedSecret.suiteId, parsedSecret.keyBytes);

      const sameSuite = parsedSecret.suiteId === parsedPublic.suiteId;
      const samePublic = bytesToHexLower(derivedPublic) === bytesToHexLower(parsedPublic.keyBytes);

      wipeBytes(parsedSecret.keyBytes);
      wipeBytes(derivedPublic);
      manager.clearAllSessions();

      if (!sameSuite || !samePublic) {
        throw new Error('exported secret key did not round-trip to stored public key');
      }
    },
  });

  cases.push({
    name: 'secret session export must require consent token',
    fn: async () => {
      const manager = createSecretSessionManager();
      const session = manager.generateSession(SuiteId.ML_DSA_44);
      let failed = false;
      try {
        manager.exportSecretKeyFile(session.sessionHandle);
      } catch (_err) {
        failed = true;
      }

      manager.clearAllSessions();

      if (!failed) {
        throw new Error('secret export unexpectedly succeeded without consent token');
      }
    },
  });

  cases.push({
    name: 'secret session export must reject wrong consent token',
    fn: async () => {
      const manager = createSecretSessionManager();
      const session = manager.generateSession(SuiteId.ML_DSA_44);
      let failed = false;
      try {
        manager.exportSecretKeyFile(session.sessionHandle, 'export-consent-wrong');
      } catch (_err) {
        failed = true;
      }

      manager.clearAllSessions();

      if (!failed) {
        throw new Error('secret export unexpectedly succeeded with wrong consent token');
      }
    },
  });

  cases.push({
    name: 'secret session handles must not use legacy sequential format',
    fn: async () => {
      const manager = createSecretSessionManager();
      const sessionA = manager.generateSession(SuiteId.ML_DSA_44);
      const sessionB = manager.generateSession(SuiteId.ML_DSA_44);

      manager.clearAllSessions();

      if (/^secret-session-\d+$/.test(sessionA.sessionHandle) || /^secret-session-\d+$/.test(sessionB.sessionHandle)) {
        throw new Error('secret session handle still uses sequential format');
      }
      if (sessionA.sessionHandle === sessionB.sessionHandle) {
        throw new Error('secret session handles unexpectedly collided');
      }
    },
  });

  cases.push({
    name: 'cleared secret session must reject access',
    fn: async () => {
      const manager = createSecretSessionManager();
      const session = manager.generateSession(SuiteId.ML_DSA_44);
      const cleared = manager.clearSession(session.sessionHandle);

      let failed = false;
      try {
        manager.getSession(session.sessionHandle);
      } catch (_err) {
        failed = true;
      }

      manager.clearAllSessions();

      if (!cleared || !failed) {
        throw new Error('cleared secret session remained accessible');
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
