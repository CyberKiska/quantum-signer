import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_shake_128s, slh_dsa_shake_192s, slh_dsa_shake_256s } from '@noble/post-quantum/slh-dsa.js';
import { getSuiteMetadata } from './suite-metadata.js';
const verifiers = new Map([[1, ml_dsa44.verify], [2, ml_dsa65.verify], [3, ml_dsa87.verify],
  [17, slh_dsa_shake_128s.verify], [18, slh_dsa_shake_192s.verify], [19, slh_dsa_shake_256s.verify]]);
export function verifyBytes({ suiteId, signatureProfileId = 1, message, signature, publicKey, contextBytes = new Uint8Array() }) {
  const suite = getSuiteMetadata(suiteId);
  if (signatureProfileId !== 1) throw new Error('Unsupported signature profile.');
  if (!(message instanceof Uint8Array)) throw new TypeError('Message must be bytes.');
  if (!(signature instanceof Uint8Array) || signature.length !== suite.lengths.signature ||
      !(publicKey instanceof Uint8Array) || publicKey.length !== suite.lengths.publicKey ||
      !(contextBytes instanceof Uint8Array) || contextBytes.length > 255) return false;
  try { return verifiers.get(suiteId)(signature, message, publicKey, { context: contextBytes }) === true; }
  catch { return false; }
}
