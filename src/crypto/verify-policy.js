import {
  computeFingerprintHex,
  verifyBytes,
} from './algorithms.js';
import { ErrorCode } from './errors.js';
import {
  MAX_KEY_FILE_BYTES,
  assertBytesLimit,
} from './policy.js';
import {
  getHashName,
  unpackPublicKeyV1,
  unpackSignerFingerprint,
} from '../formats/containers.js';
import { validateSignatureAndKeySuites } from './validate.js';
import { equalsBytes } from './bytes.js';
import { bytesToHexLower } from '../formats/encoding.js';

export function getSignatureMetadataFingerprintHex(parsedSig) {
  if (!(parsedSig.metadata?.signerFingerprint instanceof Uint8Array)) return null;
  try {
    const parsed = unpackSignerFingerprint(parsedSig.metadata.signerFingerprint);
    return bytesToHexLower(parsed.digest);
  } catch (_err) {
    return null;
  }
}

function resolveVerificationCandidates(parsedSig, publicKeyFile) {
  const embeddedKey =
    parsedSig.metadata?.signerPublicKey instanceof Uint8Array && parsedSig.metadata.signerPublicKey.length > 0
      ? parsedSig.metadata.signerPublicKey
      : null;

  let loaded = null;
  if (publicKeyFile instanceof Uint8Array) {
    assertBytesLimit(publicKeyFile, MAX_KEY_FILE_BYTES, 'publicKeyFile');
    const parsedPublic = unpackPublicKeyV1(publicKeyFile);
    validateSignatureAndKeySuites(parsedSig.suiteId, parsedPublic.suiteId);
    loaded = {
      keySource: 'keys',
      publicKey: parsedPublic.keyBytes,
      signerFingerprintHex: computeFingerprintHex(parsedPublic.keyBytes),
    };
  }

  const embedded = embeddedKey
    ? {
        keySource: 'signature',
        publicKey: embeddedKey,
        signerFingerprintHex: computeFingerprintHex(embeddedKey),
      }
    : null;

  return {
    loaded,
    embedded,
    embeddedKeyMatchesLoaded: loaded && embedded ? equalsBytes(loaded.publicKey, embedded.publicKey) : null,
    signatureMetadataFingerprintHex: getSignatureMetadataFingerprintHex(parsedSig),
  };
}

function verifyWithCandidate(parsedSig, candidate) {
  const valid = verifyBytes({
    suiteId: parsedSig.suiteId,
    message: parsedSig.tbs,
    signature: parsedSig.signature,
    publicKey: candidate.publicKey,
    contextBytes: parsedSig.ctxBytes,
  });
  return {
    keySource: candidate.keySource,
    signerFingerprintHex: candidate.signerFingerprintHex,
    valid,
  };
}

function mismatchWarning(loadedValid, embeddedValid) {
  if (loadedValid && embeddedValid) {
    return 'Loaded public key differs from embedded key, but both verify. Use trusted key identity for final trust decision.';
  }
  if (loadedValid && !embeddedValid) {
    return 'Loaded public key verifies, embedded key does not. Signature metadata key may be stale or modified.';
  }
  if (!loadedValid && embeddedValid) {
    return 'Loaded public key fails, embedded key verifies. You may have loaded the wrong public key.';
  }
  return 'Loaded and embedded keys both fail verification.';
}

export function finalizeVerification(parsedSig, publicKeyFile, hashDetails) {
  const candidates = resolveVerificationCandidates(parsedSig, publicKeyFile);

  if (!candidates.loaded && !candidates.embedded) {
    return {
      valid: false,
      cryptoValid: false,
      code: ErrorCode.E_INPUT_REQUIRED,
      verifiedKeySource: 'none',
      trustSource: 'none',
      warning: 'No verification key available. Load a public key in Keys, or use a .qsig that embeds signer public key.',
      ...hashDetails,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
    };
  }

  if (candidates.loaded && candidates.embedded && candidates.embeddedKeyMatchesLoaded === false) {
    const loadedResult = verifyWithCandidate(parsedSig, candidates.loaded);
    const embeddedResult = verifyWithCandidate(parsedSig, candidates.embedded);
    const cryptoValid = loadedResult.valid || embeddedResult.valid;
    let verifiedKeySource = 'none';
    if (loadedResult.valid && embeddedResult.valid) verifiedKeySource = 'both';
    else if (loadedResult.valid) verifiedKeySource = 'loaded';
    else if (embeddedResult.valid) verifiedKeySource = 'signature';

    return {
      valid: loadedResult.valid,
      cryptoValid,
      code: loadedResult.valid ? null : ErrorCode.E_SIGNATURE_INVALID,
      ...hashDetails,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      keySource: loadedResult.keySource,
      signerFingerprintHex: loadedResult.signerFingerprintHex,
      signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
      embeddedKeyMatchesLoaded: false,
      keyMismatch: true,
      verifiedKeySource,
      trustSource: 'key-mismatch',
      loadedKeyValid: loadedResult.valid,
      embeddedKeyValid: embeddedResult.valid,
      loadedKeyFingerprintHex: loadedResult.signerFingerprintHex,
      embeddedKeyFingerprintHex: embeddedResult.signerFingerprintHex,
      warning: mismatchWarning(loadedResult.valid, embeddedResult.valid),
    };
  }

  const activeCandidate = candidates.loaded || candidates.embedded;
  const result = verifyWithCandidate(parsedSig, activeCandidate);

  if (!result.valid) {
    return {
      valid: false,
      cryptoValid: false,
      code: ErrorCode.E_SIGNATURE_INVALID,
      ...hashDetails,
      suiteId: parsedSig.suiteId,
      hashAlgId: parsedSig.hashAlgId,
      hashAlgName: getHashName(parsedSig.hashAlgId),
      context: parsedSig.ctx,
      signatureLength: parsedSig.signature.length,
      keySource: result.keySource,
      signerFingerprintHex: result.signerFingerprintHex,
      signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
      embeddedKeyMatchesLoaded: candidates.embeddedKeyMatchesLoaded,
      verifiedKeySource: 'none',
      trustSource: result.keySource === 'signature' ? 'embedded-only' : 'loaded-key',
    };
  }

  return {
    valid: true,
    cryptoValid: true,
    code: null,
    ...hashDetails,
    suiteId: parsedSig.suiteId,
    hashAlgId: parsedSig.hashAlgId,
    hashAlgName: getHashName(parsedSig.hashAlgId),
    context: parsedSig.ctx,
    signatureLength: parsedSig.signature.length,
    keySource: result.keySource,
    signerFingerprintHex: result.signerFingerprintHex,
    signatureMetadataFingerprintHex: candidates.signatureMetadataFingerprintHex,
    embeddedKeyMatchesLoaded: candidates.embeddedKeyMatchesLoaded,
    verifiedKeySource: result.keySource === 'signature' ? 'signature' : 'loaded',
    trustSource: result.keySource === 'signature' ? 'embedded-only' : 'loaded-key',
    warning:
      result.keySource === 'signature'
        ? 'Verified using public key embedded in .qsig. For identity assurance, compare with a trusted key in Keys tab.'
        : null,
  };
}
