import { publicKeyBytes, signBytesNative } from './crypto.js';
import { sha3_256 } from '../crypto/native-hashes.js';
import { finalizePayloadVerification } from '../crypto/verify-policy.js';
import {
  AuthDigestAlgId, HashAlgId, SignatureProfileId, buildTBSV2, computeAuthMetaDigestV2, packAuthenticatedMetadataV2,
  packSignerFingerprint, packSignatureV2, unpackSignatureV2, packPublicKey, QSIG_V2_CONTEXT,
} from '../formats/containers.js';

export function createDetachedSignature(suiteId, privateKey, payloadDigest) {
  const publicKey = publicKeyBytes(suiteId, privateKey);
  const authenticatedMetadata = {
    signerPublicKey: publicKey,
    signerFingerprint: packSignerFingerprint({ digest: sha3_256(publicKey) }),
  };
  const authMetaDigest = computeAuthMetaDigestV2(packAuthenticatedMetadataV2(authenticatedMetadata));
  const fields = {
    suiteId, signatureProfileId: SignatureProfileId.PQ_DETACHED_PURE_CONTEXT_V2,
    payloadDigestAlgId: HashAlgId.SHA3_512, authDigestAlgId: AuthDigestAlgId.SHA3_256, payloadDigest, authMetaDigest,
  };
  const tbs = buildTBSV2(fields);
  const signature = signBytesNative({ suiteId, privateKey, message: tbs, contextBytes: Buffer.from(QSIG_V2_CONTEXT) });
  const container = packSignatureV2({ ...fields, signature, authenticatedMetadata });
  const verified = finalizePayloadVerification(unpackSignatureV2(container), packPublicKey({ suiteId, keyBytes: publicKey }), {
    computedHashHex: Buffer.from(payloadDigest).toString('hex'),
  });
  if (!verified.valid || !verified.trusted) throw new Error('Container self-verification failed.');
  return container;
}
