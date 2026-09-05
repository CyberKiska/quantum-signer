// Derive public-only browser KATs from the pinned NIST ACVP signing fixtures.
// No test secret keys are included in the browser artifact.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { listSuites } from '../src/crypto/suite-metadata.js';
import { signBytes, getPublicKeyFromSecret } from '../src/crypto/algorithms.js';
const vectors = [];
for (const file of ['nist-acvp-mldsa-siggen-vectors.json', 'nist-acvp-slhdsa-siggen-vectors.json']) {
  const source = JSON.parse(await readFile(new URL(file, import.meta.url), 'utf8'));
  for (const vector of source.vectors) {
    const suiteId = listSuites().find(s => s.name.toLowerCase() === vector.parameterSet.toLowerCase()).id;
    const secretKey = Buffer.from(vector.secretKeyBase64, 'base64');
    try {
      const signature = signBytes({ suiteId, secretKey, message: Buffer.from(vector.messageBase64, 'base64'),
        contextBytes: Buffer.from(vector.contextBase64, 'base64'), hedged: false });
      if (createHash('sha256').update(signature).digest('hex') !== vector.expectedSignatureSha256) throw new Error('NIST signature mismatch');
      vectors.push({ suiteId, tcId: vector.tcId, sourceCommit: source.source.commit,
        messageBase64: vector.messageBase64, contextBase64: vector.contextBase64,
        publicKeyBase64: Buffer.from(getPublicKeyFromSecret(suiteId, secretKey)).toString('base64'),
        signatureBase64: Buffer.from(signature).toString('base64'), expectedSignatureSha256: vector.expectedSignatureSha256 });
      console.log(`Verified public fixture: ${vector.parameterSet}`);
    } finally { secretKey.fill(0); }
  }
}
await writeFile(new URL('../src/crypto/verification-vectors.json', import.meta.url), `${JSON.stringify({ schema: 'qsig-public-verification-kat/v1', vectors }, null, 2)}\n`);
