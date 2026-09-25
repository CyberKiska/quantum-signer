import vectors from './verification-vectors.json' with { type: 'json' };
import { bytesToHexLower } from '../formats/encoding.js';

const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const SHA3_512_EMPTY =
  'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26';

// Public NIST-derived verification KATs (FIPS 204/205 pure, external interface).
// Adapters are injected so the native CLI never loads the browser libraries.
export function runVerificationSelfTest({ verifyBytes, sha3_512, suiteIds = null }) {
  let total = 0;
  let failed = 0;
  const check = result => { total++; if (!result) failed++; };
  check(bytesToHexLower(sha3_512(new Uint8Array())) === SHA3_512_EMPTY);
  check(vectors.vectors.length === 6 && new Set(vectors.vectors.map(v => v.suiteId)).size === 6);
  const selected = vectors.vectors.filter(v => suiteIds === null || suiteIds.includes(v.suiteId));
  check(selected.length > 0);
  for (const vector of selected) {
    const args = { suiteId: vector.suiteId, publicKey: decode(vector.publicKeyBase64),
      signature: decode(vector.signatureBase64), message: decode(vector.messageBase64), contextBytes: decode(vector.contextBase64) };
    check(verifyBytes(args));
    const wrongContext = Uint8Array.from(args.contextBytes);
    if (wrongContext.length) wrongContext[0] ^= 1;
    check(!verifyBytes({ ...args, contextBytes: wrongContext.length ? wrongContext : Uint8Array.of(1) }));
    const wrongMessage = Uint8Array.from(args.message);
    if (wrongMessage.length) wrongMessage[wrongMessage.length - 1] ^= 0x80;
    check(!verifyBytes({ ...args, message: wrongMessage.length ? wrongMessage : Uint8Array.of(0) }));
    args.signature[0] ^= 1;
    check(!verifyBytes(args));
  }
  return { ok: failed === 0, total, passed: total - failed, failed };
}
