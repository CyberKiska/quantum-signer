// Derive the native CLI's startup KAT fixture from pinned NIST ACVP data.
// Set ACVP_DIR to a directory holding ML-DSA-keyGen-FIPS204.json (the ACVP
// internalProjection file) to work offline; otherwise it is fetched and pinned.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const ACVP_COMMIT = 'a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324';
const KEYGEN = { name: 'ML-DSA-keyGen-FIPS204', sha256: 'e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf' };
const SUITES = { 'ML-DSA-44': 1, 'ML-DSA-65': 2, 'ML-DSA-87': 3, 'SLH-DSA-SHAKE-128s': 17, 'SLH-DSA-SHAKE-192s': 18, 'SLH-DSA-SHAKE-256s': 19 };

async function acvpFile({ name, sha256 }) {
  const bytes = process.env.ACVP_DIR
    ? await readFile(path.join(process.env.ACVP_DIR, `${name}.json`))
    : Buffer.from(await (await fetch(`https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files/${name}/internalProjection.json`, { redirect: 'error' })).arrayBuffer());
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== sha256) throw new Error(`${name} digest mismatch: ${actual}`);
  return JSON.parse(bytes.toString('utf8'));
}

const keyGen = await acvpFile(KEYGEN);
const mlDsaKeyGen = keyGen.testGroups.map((group) => {
  const [test] = group.tests;
  return {
    suiteId: SUITES[group.parameterSet], tgId: group.tgId, tcId: test.tcId, seedHex: test.seed.toLowerCase(),
    publicKeySha256: createHash('sha256').update(Buffer.from(test.pk, 'hex')).digest('hex'),
  };
});

const slhSigGen = JSON.parse(await readFile(new URL('nist-acvp-slhdsa-siggen-vectors.json', import.meta.url), 'utf8'));
const slhDsaSecretKeys = slhSigGen.vectors.map((vector) => ({
  suiteId: SUITES[vector.parameterSet], tgId: vector.tgId, tcId: vector.tcId,
  secretKeyHex: Buffer.from(vector.secretKeyBase64, 'base64').toString('hex'),
}));

await writeFile(new URL('../src/native/kat-vectors.json', import.meta.url), `${JSON.stringify({
  schema: 'quantum-signer-native-kat/v1',
  note: 'Public NIST ACVP test data only. No user key material.',
  source: {
    repository: 'https://github.com/usnistgov/ACVP-Server', commit: ACVP_COMMIT,
    mlDsaKeyGen: { path: `gen-val/json-files/${KEYGEN.name}/internalProjection.json`, sha256: KEYGEN.sha256 },
    slhDsaSigGen: slhSigGen.source,
  },
  mlDsaKeyGen,
  slhDsaSecretKeys,
}, null, 2)}\n`);
console.log('Native KAT fixture written.');
