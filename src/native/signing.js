import { publicKeyBytes, signBytesNative } from './crypto.js';
import { createDetachedSignature as createQsig } from '../crypto/detached-signature.js';

export function createDetachedSignature(suiteId, privateKey, payloadDigest) {
  return createQsig({
    suiteId, publicKey: publicKeyBytes(suiteId, privateKey), payloadDigest,
    sign: (message, contextBytes) => signBytesNative({ suiteId, privateKey, message, contextBytes }),
  });
}
