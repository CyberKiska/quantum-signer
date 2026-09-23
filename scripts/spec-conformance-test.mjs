// Keeps spec/qsig-v2.txt and the pinned conformance vector bound to the code.
// A wire-spec edit that disagrees with emitted bytes fails here.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { importMlDsaSeed, publicKeyBytes, verifyBytes as verifyNative } from '../src/native/crypto.js';
import { verifyBytes as verifyBrowser } from '../src/crypto/browser-verification.js';
import { finalizePayloadVerification } from '../src/crypto/verify-policy.js';
import {
  buildTBSV2, computeAuthMetaDigestV2, packAuthenticatedMetadataV2, packPublicKey, packSignerFingerprint, unpackSignatureV2,
} from '../src/formats/containers.js';

const spec = await readFile(new URL('../spec/qsig-v2.txt', import.meta.url), 'utf8');
const vector = JSON.parse(await readFile(new URL('../spec/qsig-v2-vector.json', import.meta.url), 'utf8'));
const hex = (value) => Buffer.from(value, 'hex');
const sha3 = (name, bytes) => createHash(name).update(bytes).digest();

// Normative prose values.
const [, contextText, contextLength] = spec.match(/Context is exactly UTF-8\("([^"]+)"\), (\d+) bytes\./u);
assert.equal(Buffer.byteLength(contextText), Number(contextLength), 'spec context length');
assert.deepEqual(Buffer.from(contextText), hex(vector.contextHex), 'spec context bytes');
const [, tbsLength] = spec.match(/TBS is exactly (\d+) bytes/u);
const [, prefixHex, encodedLength] = spec.match(/encoded message is 00 \|\| ([0-9a-f]{2}) \|\| context \|\| TBS, (\d+) bytes/u);
assert.equal(parseInt(prefixHex, 16), Number(contextLength), 'spec context-length octet (FIPS 204 Alg. 2 / FIPS 205 Alg. 22)');
assert.equal(Number(encodedLength), 2 + Number(contextLength) + Number(tbsLength), 'spec encoded message length');

// QSIG offset table: contiguous offsets and literal byte values must match the vector.
const qsig = hex(vector.qsigHex);
const table = spec.slice(spec.indexOf('QSIG container'), spec.indexOf('No trailing bytes'));
const rows = [...table.matchAll(/^(\d+)\s+(\d+|varies)\s+(.+)$/gmu)].map(([, offset, width, value]) => ({
  offset: Number(offset), width: width === 'varies' ? null : Number(width), value,
}));
assert.equal(rows.length, 16, 'QSIG table rows');
for (let i = 1; i < rows.length && rows[i - 1].width !== null; i++) {
  assert.equal(rows[i].offset, rows[i - 1].offset + rows[i - 1].width, `spec offset ${rows[i].offset}`);
}
for (const { offset, width, value } of rows) {
  const literal = value.match(/^((?:[0-9a-f]{2} ?)+)(?:\(|$)/u);
  if (literal && width !== null) assert.deepEqual(qsig.subarray(offset, offset + width), hex(literal[1].replaceAll(' ', '')), `spec value at ${offset}`);
  if (value.startsWith('ASCII ')) assert.equal(qsig.subarray(offset, offset + width).toString(), value.slice(6), `spec magic at ${offset}`);
}
const contextRow = rows.find((row) => row.value === 'context');
assert.equal(contextRow.width, Number(contextLength));
assert.deepEqual(qsig.subarray(contextRow.offset, contextRow.offset + contextRow.width), Buffer.from(contextText));
const authRow = rows.find((row) => row.value === 'authenticated metadata');
assert.equal(authRow.offset, contextRow.offset + contextRow.width, 'authenticated metadata offset');

// Deterministic components: seed -> key (FIPS 204 KeyGen via RFC 9881 seed form) -> metadata -> TBS.
const suiteId = vector.suiteId;
const publicKey = publicKeyBytes(suiteId, importMlDsaSeed(suiteId, hex(vector.seedHex)));
assert.deepEqual(Buffer.from(publicKey), hex(vector.publicKeyHex), 'seed-derived public key');
assert.deepEqual(sha3('sha3-512', hex(vector.payloadHex)), hex(vector.payloadDigestHex), 'payload digest');
const signerFingerprint = packSignerFingerprint({ digest: sha3('sha3-256', publicKey) });
assert.deepEqual(Buffer.from(signerFingerprint), hex(vector.fingerprintHex), 'fingerprint record');
const authMetadata = packAuthenticatedMetadataV2({ signerPublicKey: publicKey, signerFingerprint });
assert.deepEqual(Buffer.from(authMetadata), hex(vector.authMetadataHex), 'authenticated metadata');
const authMetaDigest = computeAuthMetaDigestV2(authMetadata);
assert.deepEqual(Buffer.from(authMetaDigest), hex(vector.authDigestHex), 'authenticated metadata digest');
const tbs = buildTBSV2({ suiteId, payloadDigest: hex(vector.payloadDigestHex), authMetaDigest });
assert.equal(tbs.length, Number(tbsLength));
assert.deepEqual(Buffer.from(tbs), hex(vector.tbsHex), 'TBS');

// Container parse, primitive verification in both adapters, and final policy.
const parsed = unpackSignatureV2(qsig);
assert.deepEqual(Buffer.from(parsed.tbs), Buffer.from(tbs));
const args = { suiteId, message: tbs, signature: parsed.signature, publicKey, contextBytes: Buffer.from(contextText) };
assert(verifyNative(args) && verifyBrowser(args), 'vector signature must verify natively and in the browser adapter');
assert(!verifyNative({ ...args, contextBytes: new Uint8Array() }) && !verifyBrowser({ ...args, contextBytes: new Uint8Array() }));
const result = finalizePayloadVerification(parsed, packPublicKey({ suiteId, keyBytes: publicKey }), {
  computedHashHex: vector.payloadDigestHex,
});
assert(result.valid && result.trusted, 'vector must pass final verification policy');
console.log('Wire-spec conformance vector: PASS');
