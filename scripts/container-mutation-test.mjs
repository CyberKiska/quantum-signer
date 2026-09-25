import {
  QSIG_DEFAULT_CTX,
  generateKeypair,
  getDefaultSignatureProfileId,
  hashBytesSHA3512,
  signBytesVerified,
} from './lib/reference-pq.mjs';
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
import { listSuites } from '../src/crypto/suite-metadata.js';
import { generateNativeKey, publicKeyBytes } from '../src/native/crypto.js';
import { createDetachedSignature } from '../src/native/signing.js';
import { createHash } from 'node:crypto';

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
  });

  const baseline = unpackSignatureV2(signatureFile);
  assert(equalsBytes(baseline.tbs, tbs), 'mutation corpus baseline TBS did not round-trip');
  const baselineResult = finalizePayloadVerification(baseline, publicKeyFile, {
    providedHashHex: bytesToHexLower(payloadDigest),
    inputKind: 'text',
    inputLength: payload.length,
  });
  assert(baselineResult.valid === true, 'mutation corpus baseline signature was invalid');

  // Caller diagnostics cannot override cryptographic or signer-binding decisions.
  const hostileDetails = {
    providedHashHex: bytesToHexLower(payloadDigest),
    valid: true, integrityValid: true, cryptoValid: true, trusted: true, code: null,
    signaturePolicyValid: true, payloadMatches: true, trustSource: 'loaded-key',
  };
  const damaged = unpackSignatureV2(signatureFile);
  damaged.signature[0] ^= 1;
  const rejected = finalizePayloadVerification(damaged, publicKeyFile, hostileDetails);
  assert(!rejected.valid && !rejected.trusted && !rejected.cryptoValid && rejected.code,
    'diagnostics overrode an invalid signature');
  const embeddedOnly = finalizePayloadVerification(baseline, null, hostileDetails);
  assert(!embeddedOnly.valid && embeddedOnly.integrityValid && !embeddedOnly.trusted,
    'diagnostics promoted an embedded key to valid or trusted');
  const otherKeys = generateKeypair(suiteId);
  try {
    const mismatch = finalizePayloadVerification(baseline,
      packPublicKey({ suiteId, keyBytes: otherKeys.publicKey }), hostileDetails);
    assert(!mismatch.valid && !mismatch.trusted, 'diagnostics bypassed selected-key binding');
  } finally { wipeBytes(otherKeys.secretKey); }
  for (const details of [
    {}, { providedHashHex: '00' }, { providedHashHex: 'G'.repeat(128) },
    { providedHashHex: 'A'.repeat(128) },
    { ...hostileDetails, computedHashHex: '00'.repeat(64) },
  ]) {
    let failed = false;
    try { finalizePayloadVerification(baseline, publicKeyFile, details); }
    catch { failed = true; }
    assert(failed, 'accepted an ambiguous or noncanonical digest');
  }

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

// All suites, native signatures: every header/metadata byte and a stride over
// the raw signature. No mutation may yield valid, and none may yield
// integrity-only acceptance when no key is selected.
let allSuiteMutations = 0;
for (const suite of listSuites()) {
  const key = generateNativeKey(suite.id);
  const publicKey = publicKeyBytes(suite.id, key);
  const suitePayloadDigest = createHash('sha3-512').update(`all-suite mutation corpus ${suite.name}`).digest();
  const container = createDetachedSignature(suite.id, key, suitePayloadDigest);
  const suitePublicKeyFile = packPublicKey({ suiteId: suite.id, keyBytes: publicKey });
  const details = { computedHashHex: bytesToHexLower(suitePayloadDigest) };
  const signatureStart = container.length - suite.lengths.signature;
  const offsets = [];
  for (let offset = 0; offset < signatureStart; offset += 1) offsets.push(offset);
  for (let offset = signatureStart; offset < container.length; offset += 97) offsets.push(offset);
  offsets.push(container.length - 1);
  for (const offset of offsets) {
    const mutated = Uint8Array.from(container);
    mutated[offset] ^= 1 << (offset % 8);
    for (const keyFile of [suitePublicKeyFile, null]) {
      let result = null;
      try { result = finalizePayloadVerification(unpackSignatureV2(mutated), keyFile, details); } catch { result = null; }
      assert(!result?.valid && !result?.integrityValid,
        `${suite.name} accepted a one-bit QSIG mutation at offset ${offset} (${keyFile ? 'selected key' : 'embedded key'})`);
    }
    allSuiteMutations += 1;
  }
}
console.log(`All-suite native container mutation corpus: PASS (${allSuiteMutations} mutations x 2 key policies)`);
