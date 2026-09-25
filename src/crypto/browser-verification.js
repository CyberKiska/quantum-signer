import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_shake_128s, slh_dsa_shake_192s, slh_dsa_shake_256s } from '@noble/post-quantum/slh-dsa.js';
import { SuiteId, verificationInputsWellFormed } from './suite-metadata.js';

const verifiers = new Map([
  [SuiteId.ML_DSA_44, ml_dsa44.verify],
  [SuiteId.ML_DSA_65, ml_dsa65.verify],
  [SuiteId.ML_DSA_87, ml_dsa87.verify],
  [SuiteId.SLH_DSA_SHAKE_128S, slh_dsa_shake_128s.verify],
  [SuiteId.SLH_DSA_SHAKE_192S, slh_dsa_shake_192s.verify],
  [SuiteId.SLH_DSA_SHAKE_256S, slh_dsa_shake_256s.verify],
]);

// Pure ML-DSA.Verify / SLH-DSA.Verify (FIPS 204 Alg. 3, FIPS 205 Alg. 24): the
// library applies the 00 || len(ctx) || ctx prefix exactly once.
export function verifyBytes({ contextBytes = new Uint8Array(), ...args }) {
  if (!verificationInputsWellFormed({ ...args, contextBytes })) return false;
  const { suiteId, message, signature, publicKey } = args;
  try { return verifiers.get(suiteId)(signature, message, publicKey, { context: contextBytes }) === true; }
  catch { return false; }
}
