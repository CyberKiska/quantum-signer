export const SuiteId = Object.freeze({
  ML_DSA_44: 0x01,
  ML_DSA_65: 0x02,
  ML_DSA_87: 0x03,
  SLH_DSA_SHAKE_128S: 0x11,
  SLH_DSA_SHAKE_192S: 0x12,
  SLH_DSA_SHAKE_256S: 0x13,
  FALCON_512_PADDED: 0x21,
  FALCON_1024_PADDED: 0x22,
});

const SUITE_WIRE_LENGTHS = Object.freeze({
  [SuiteId.ML_DSA_44]: Object.freeze({ publicKey: 1312, secretKey: 2560, signature: 2420 }),
  [SuiteId.ML_DSA_65]: Object.freeze({ publicKey: 1952, secretKey: 4032, signature: 3309 }),
  [SuiteId.ML_DSA_87]: Object.freeze({ publicKey: 2592, secretKey: 4896, signature: 4627 }),
  [SuiteId.SLH_DSA_SHAKE_128S]: Object.freeze({ publicKey: 32, secretKey: 64, signature: 7856 }),
  [SuiteId.SLH_DSA_SHAKE_192S]: Object.freeze({ publicKey: 48, secretKey: 96, signature: 16224 }),
  [SuiteId.SLH_DSA_SHAKE_256S]: Object.freeze({ publicKey: 64, secretKey: 128, signature: 29792 }),
  [SuiteId.FALCON_512_PADDED]: Object.freeze({ publicKey: 897, secretKey: 1281, signature: 666 }),
  [SuiteId.FALCON_1024_PADDED]: Object.freeze({ publicKey: 1793, secretKey: 2305, signature: 1280 }),
});

export function getSuiteWireLengths(suiteId) {
  return SUITE_WIRE_LENGTHS[suiteId] || null;
}
