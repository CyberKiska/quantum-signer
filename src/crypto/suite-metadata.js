import { ErrorCode, createError } from './errors.js';

export const SuiteId = Object.freeze({
  ML_DSA_44: 0x01,
  ML_DSA_65: 0x02,
  ML_DSA_87: 0x03,
  SLH_DSA_SHAKE_128S: 0x11,
  SLH_DSA_SHAKE_192S: 0x12,
  SLH_DSA_SHAKE_256S: 0x13,
});

export const DEFAULT_SUITE_ID = SuiteId.ML_DSA_87;
export const DEFAULT_SLH_SUITE_ID = SuiteId.SLH_DSA_SHAKE_128S;

const SUITE_METADATA = Object.freeze([
  Object.freeze({
    id: SuiteId.ML_DSA_44,
    name: 'ML-DSA-44',
    family: 'ML-DSA',
    defaultHedged: true,
    lengths: Object.freeze({ publicKey: 1312, secretKey: 2560, signature: 2420 }),
  }),
  Object.freeze({
    id: SuiteId.ML_DSA_65,
    name: 'ML-DSA-65',
    family: 'ML-DSA',
    defaultHedged: true,
    lengths: Object.freeze({ publicKey: 1952, secretKey: 4032, signature: 3309 }),
  }),
  Object.freeze({
    id: SuiteId.ML_DSA_87,
    name: 'ML-DSA-87',
    family: 'ML-DSA',
    defaultHedged: true,
    lengths: Object.freeze({ publicKey: 2592, secretKey: 4896, signature: 4627 }),
  }),
  Object.freeze({
    id: SuiteId.SLH_DSA_SHAKE_128S,
    name: 'SLH-DSA-SHAKE-128s',
    family: 'SLH-DSA',
    defaultHedged: true,
    lengths: Object.freeze({ publicKey: 32, secretKey: 64, signature: 7856 }),
  }),
  Object.freeze({
    id: SuiteId.SLH_DSA_SHAKE_192S,
    name: 'SLH-DSA-SHAKE-192s',
    family: 'SLH-DSA',
    defaultHedged: true,
    lengths: Object.freeze({ publicKey: 48, secretKey: 96, signature: 16224 }),
  }),
  Object.freeze({
    id: SuiteId.SLH_DSA_SHAKE_256S,
    name: 'SLH-DSA-SHAKE-256s',
    family: 'SLH-DSA',
    defaultHedged: true,
    lengths: Object.freeze({ publicKey: 64, secretKey: 128, signature: 29792 }),
  }),
]);

const SUITE_BY_ID = new Map(SUITE_METADATA.map((suite) => [suite.id, suite]));

export function listSuites() {
  return SUITE_METADATA.map((suite) => ({
    ...suite,
    lengths: { ...suite.lengths },
  }));
}

export function getSuiteMetadata(suiteId) {
  const suite = SUITE_BY_ID.get(suiteId);
  if (!suite) throw createError(ErrorCode.E_SUITE_UNSUPPORTED, { suiteId });
  return suite;
}

export function getSuiteWireLengths(suiteId) {
  return SUITE_BY_ID.get(suiteId)?.lengths || null;
}

export function assertKeyLength(suiteId, keyBytes, kind) {
  const suite = getSuiteMetadata(suiteId);
  if (!(keyBytes instanceof Uint8Array)) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, { field: `${kind}Key`, expected: 'Uint8Array' });
  }
  const expected = kind === 'public' ? suite.lengths.publicKey : suite.lengths.secretKey;
  if (keyBytes.length !== expected) {
    throw createError(ErrorCode.E_FORMAT_LENGTH, {
      field: `${kind}KeyLength`,
      expected,
      actual: keyBytes.length,
      suiteId,
    });
  }
}
