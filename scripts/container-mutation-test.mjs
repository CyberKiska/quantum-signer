import {
  QSIG_DEFAULT_CTX,
  generateKeypair,
  getDefaultSignatureProfileId,
  hashBytesSHA3512,
  signBytesVerified,
} from '../src/crypto/algorithms.js';
import { computeFingerprintBytes } from '../src/crypto/fingerprint.js';
import { finalizePayloadVerification } from '../src/crypto/verify-policy.js';
import { equalsBytes, wipeBytes } from '../src/crypto/bytes.js';
import { utf8ToBytesStrict } from '../src/crypto/text-encoding.js';
import {
  AuthDigestAlgId,
  FingerprintAlgId,
  HashAlgId,
  SuiteId,
  buildTBSV2,
  computeAuthMetaDigestV2,
  packAuthenticatedMetadataV2,
  packPublicKey,
  packSecretKey,
  packSignatureV2,
  packSignerFingerprint,
  unpackPublicKey,
  unpackSecretKey,
  unpackSignatureV2,
} from '../src/formats/containers.js';
import { bytesToHexLower } from '../src/formats/encoding.js';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertMutatedKeyRejected(original, unpack, label) {
  let tested = 0;
  for (let offset = 0; offset < original.length; offset += 1) {
    const mutated = Uint8Array.from(original);
    mutated[offset] ^= 1 << (offset % 8);
    let rejected = false;
    try {
      const parsed = unpack(mutated);
      wipeBytes(parsed?.keyBytes);
    } catch (_err) {
      rejected = true;
    } finally {
      wipeBytes(mutated);
    }
    assert(rejected, `${label} accepted a one-bit mutation at offset ${offset}`);
    tested += 1;
  }
  return tested;
}

const suiteId = SuiteId.ML_DSA_44;
const keys = generateKeypair(suiteId);
const payload = utf8ToBytesStrict('quantum-signer deterministic mutation corpus', 'mutationPayload');
const contextBytes = utf8ToBytesStrict(QSIG_DEFAULT_CTX, 'mutationContext');
let publicKeyFile;
let secretKeyFile;
let authMetaBytes;
let signature;
let signatureFile;
let fingerprintDigest;

try {
  publicKeyFile = packPublicKey({ suiteId, keyBytes: keys.publicKey });
  secretKeyFile = packSecretKey({ suiteId, keyBytes: keys.secretKey });
  const payloadDigest = hashBytesSHA3512(payload);
  fingerprintDigest = computeFingerprintBytes(keys.publicKey);
  const authenticatedMetadata = {
    signerPublicKey: keys.publicKey,
    signerFingerprint: packSignerFingerprint({
      algId: FingerprintAlgId.SHA3_256,
      digest: fingerprintDigest,
    }),
  };
  authMetaBytes = packAuthenticatedMetadataV2(authenticatedMetadata);
  const authMetaDigest = computeAuthMetaDigestV2(authMetaBytes);
  const signatureProfileId = getDefaultSignatureProfileId(suiteId);
  const tbs = buildTBSV2({
    suiteId,
    signatureProfileId,
    payloadDigestAlgId: HashAlgId.SHA3_512,
    authDigestAlgId: AuthDigestAlgId.SHA3_256,
    payloadDigest,
    authMetaDigest,
  });
  signature = signBytesVerified({
    suiteId,
    signatureProfileId,
    message: tbs,
    secretKey: keys.secretKey,
    publicKey: keys.publicKey,
    hedged: false,
    contextBytes,
  });
  signatureFile = packSignatureV2({
    suiteId,
    signatureProfileId,
    payloadDigestAlgId: HashAlgId.SHA3_512,
    authDigestAlgId: AuthDigestAlgId.SHA3_256,
    payloadDigest,
    authMetaDigest,
    signature,
    authenticatedMetadata,
    displayMetadata: {},
  });

  const baseline = unpackSignatureV2(signatureFile);
  assert(equalsBytes(baseline.tbs, tbs), 'mutation corpus baseline TBS did not round-trip');
  const baselineResult = finalizePayloadVerification(baseline, publicKeyFile, {
    providedHashHex: bytesToHexLower(payloadDigest),
    inputKind: 'text',
    inputLength: payload.length,
  });
  assert(baselineResult.valid === true, 'mutation corpus baseline signature was invalid');

  const signatureOffset = signatureFile.length - signature.length;
  const offsets = new Set();
  for (let offset = 0; offset < signatureOffset; offset += 1) offsets.add(offset);
  for (let offset = signatureOffset; offset < signatureFile.length; offset += 31) offsets.add(offset);
  offsets.add(signatureFile.length - 1);

  let signatureMutations = 0;
  for (const offset of offsets) {
    const mutated = Uint8Array.from(signatureFile);
    mutated[offset] ^= 1 << (offset % 8);
    let accepted = false;
    try {
      const parsed = unpackSignatureV2(mutated);
      const result = finalizePayloadVerification(parsed, publicKeyFile, {
        providedHashHex: bytesToHexLower(payloadDigest),
        inputKind: 'text',
        inputLength: payload.length,
      });
      accepted = result.valid === true;
    } catch (_err) {
      accepted = false;
    } finally {
      wipeBytes(mutated);
    }
    assert(!accepted, `QSIG accepted a one-bit mutation at offset ${offset}`);
    signatureMutations += 1;
  }

  const publicMutations = assertMutatedKeyRejected(publicKeyFile, unpackPublicKey, 'PQPK');
  const secretMutations = assertMutatedKeyRejected(secretKeyFile, unpackSecretKey, 'PQSK');
  console.log(
    `Container mutation corpus: PASS (QSIG=${signatureMutations}, PQPK=${publicMutations}, PQSK=${secretMutations})`
  );
} finally {
  wipeBytes(publicKeyFile);
  wipeBytes(secretKeyFile);
  wipeBytes(authMetaBytes);
  wipeBytes(signature);
  wipeBytes(signatureFile);
  wipeBytes(fingerprintDigest);
  wipeBytes(contextBytes);
  wipeBytes(payload);
  wipeBytes(keys.secretKey);
  wipeBytes(keys.publicKey);
}
