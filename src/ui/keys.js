import { computeFingerprintHex } from '../crypto/fingerprint.js';
import { wipeBytes } from '../crypto/bytes.js';
import { getSuiteName, packPublicKey, unpackPublicKey } from '../formats/containers.js';
import { MAX_KEY_FILE_BYTES } from '../crypto/policy.js';
import { byId, downloadBytes, readFileAsBytes, showToast, workerFriendlyError } from './common.js';

export function setupKeysTab(state) {
  const input = byId('keys-import-public');
  const exportButton = byId('keys-export-public');
  const info = byId('keys-info');
  let revision = 0;
  function update() {
    const key = state.keys.public;
    exportButton.disabled = !key;
    info.textContent = key
      ? `${getSuiteName(key.suiteId)}\nFingerprint (SHA3-256): ${key.fingerprintHex}\nCompare this full fingerprint through a trusted channel. Loading a key does not prove its owner's identity.`
      : 'No public key selected. Embedded-key verification alone does not establish signer identity.';
    window.dispatchEvent(new Event('keys:updated'));
  }
  function clear() {
    revision++;
    wipeBytes(state.keys.public?.keyBytes);
    wipeBytes(state.keys.public?.fileBytes);
    state.keys.public = null;
    input.value = '';
    update();
  }
  input.addEventListener('change', async () => {
    const current = ++revision;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const bytes = await readFileAsBytes(file, { maxBytes: MAX_KEY_FILE_BYTES, field: 'publicKeyFile' });
      const parsed = unpackPublicKey(bytes);
      if (current !== revision) return;
      const fingerprintHex = computeFingerprintHex(parsed.keyBytes);
      wipeBytes(state.keys.public?.keyBytes);
      wipeBytes(state.keys.public?.fileBytes);
      state.keys.public = { suiteId: parsed.suiteId, keyBytes: parsed.keyBytes,
        fileBytes: packPublicKey({ suiteId: parsed.suiteId, keyBytes: parsed.keyBytes }),
        fingerprintHex, fingerprintShort: fingerprintHex.slice(0, 32), exported: true };
      update();
    } catch (error) {
      if (current !== revision) return;
      clear();
      showToast('error', workerFriendlyError(error));
    }
  });
  byId('keys-clear').addEventListener('click', clear);
  exportButton.addEventListener('click', () => {
    const key = state.keys.public;
    if (key) downloadBytes(`signer-${key.fingerprintShort}.pqpk`, key.fileBytes);
  });
  update();
}
