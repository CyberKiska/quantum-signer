import vectors from './verification-vectors.json' with { type: 'json' };
import { verifyBytes } from './browser-verification.js';
import { hashBytesSHA3512 } from './browser-hashing.js';
import { bytesToHexLower } from '../formats/encoding.js';

const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
export function runVerificationSelfTest() {
  let total = 0;
  let failed = 0;
  const check = result => { total++; if (!result) failed++; };
  check(bytesToHexLower(hashBytesSHA3512(new Uint8Array())) ===
    'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26');
  check(vectors.vectors.length === 6 && new Set(vectors.vectors.map(v => v.suiteId)).size === 6);
  for (const vector of vectors.vectors) {
    const args = { suiteId: vector.suiteId, publicKey: decode(vector.publicKeyBase64),
      signature: decode(vector.signatureBase64), message: decode(vector.messageBase64), contextBytes: decode(vector.contextBase64) };
    check(verifyBytes(args));
    const wrongContext = Uint8Array.from(args.contextBytes);
    if (wrongContext.length) wrongContext[0] ^= 1;
    check(!verifyBytes({ ...args, contextBytes: wrongContext.length ? wrongContext : Uint8Array.of(1) }));
    args.signature[0] ^= 1;
    check(!verifyBytes(args));
  }
  return { ok: failed === 0, total, passed: total - failed, failed };
}
