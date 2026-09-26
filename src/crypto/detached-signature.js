// QSIG 2.0 detached-signature construction shared by the CLI and the browser
// worker. Each platform supplies only its pure FIPS 204/205 `sign(tbs, context)`.
import { sha3_256 } from '#crypto/hashes';
import { ErrorCode, createError } from './errors.js';
import { finalizePayloadVerification } from './verify-policy.js';
import { bytesToHexLower, utf8ToBytes } from '../formats/encoding.js';
import {
  AuthDigestAlgId, HashAlgId, QSIG_V2_CONTEXT, SignatureProfileId, buildTBSV2, computeAuthMetaDigestV2,
  packAuthenticatedMetadataV2, packPublicKey, packSignatureV2, packSignerFingerprint, unpackSignatureV2,
} from '../formats/containers.js';

export function createDetachedSignature({ suiteId, publicKey, payloadDigest, sign }) {
  const authenticatedMetadata = {
    signerPublicKey: publicKey,
    signerFingerprint: packSignerFingerprint({ digest: sha3_256(publicKey) }),
  };
  const authMetaDigest = computeAuthMetaDigestV2(packAuthenticatedMetadataV2(authenticatedMetadata));
  const fields = {
    suiteId, signatureProfileId: SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
    payloadDigestAlgId: HashAlgId.SHA3_512, authDigestAlgId: AuthDigestAlgId.SHA3_256, payloadDigest, authMetaDigest,
  };
  const signature = sign(buildTBSV2(fields), utf8ToBytes(QSIG_V2_CONTEXT));
  const container = packSignatureV2({ ...fields, signature, authenticatedMetadata });
  // Parse and verify the emitted bytes with the platform verifier before release.
  const verified = finalizePayloadVerification(unpackSignatureV2(container), packPublicKey({ suiteId, keyBytes: publicKey }), {
    computedHashHex: bytesToHexLower(payloadDigest),
  });
  if (!verified.valid || !verified.trusted) {
    container.fill(0);
    throw createError(ErrorCode.E_SIGN_SELF_VERIFY, { reason: 'container' });
  }
  return container;
}
