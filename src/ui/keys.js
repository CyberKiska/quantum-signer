import { computeFingerprintHex } from '../crypto/fingerprint.js';
import { wipeBytes } from '../crypto/bytes.js';
import { DEFAULT_SUITE_ID, listSuites } from '../crypto/suite-metadata.js';
import { getSuiteName, packPublicKey, unpackPublicKey } from '../formats/containers.js';
import { MAX_KEY_FILE_BYTES } from '../crypto/policy.js';
import { byId, downloadBytes, readFileAsBytes, showToast, workerFriendlyError } from './common.js';

// Argon2id (256 MiB) plus JavaScript SLH-DSA self-test and pairwise signatures.
const KEY_OPERATION_TIMEOUT_MS = 600_000;
const IDLE_LOCK_MS = 15 * 60_000;

export function setupKeysTab(state, workerClient) {
  setupSigningKey(state, workerClient);
  setupPublicKey(state);
}

function setupSigningKey(state, workerClient) {
  const suiteSelect = byId('keygen-suite');
  const keygenForm = byId('keygen-form');
  const keygenPassphrase = byId('keygen-passphrase');
  const keygenConfirm = byId('keygen-confirm');
  const unlockForm = byId('unlock-form');
  const unlockFile = byId('unlock-file');
  const unlockPassphrase = byId('unlock-passphrase');
  const progress = byId('signing-key-progress');
  const saveSecret = byId('signing-key-save-secret');
  const savePublic = byId('signing-key-save-public');
  const lockButton = byId('signing-key-lock');
  const info = byId('signing-key-info');
  let idleTimer = null;

  for (const suite of listSuites()) {
    const option = new Option(`${suite.name}${suite.family === 'SLH-DSA' ? ' (slow in browser)' : ''}`, String(suite.id));
    option.selected = suite.id === DEFAULT_SUITE_ID;
    suiteSelect.append(option);
  }

  function render() {
    const key = state.keys.secret;
    const busy = state.keys.transitioning;
    for (const el of [byId('keygen-run'), byId('unlock-run'), suiteSelect]) el.disabled = busy;
    progress.classList.toggle('hidden', !busy);
    saveSecret.disabled = !key?.secretKeyFile;
    savePublic.disabled = !key;
    lockButton.disabled = !key;
    info.textContent = !key ? 'No signing key unlocked.' : [
      `${getSuiteName(key.suiteId)} signing key unlocked`,
      `Fingerprint (SHA3-256): ${key.fingerprintHex}`,
      key.secretKeyFile ? 'New key: save the encrypted private key now. It cannot be recovered after locking or closing this tab.' : '',
      key.legacy ? 'Legacy key file: migrate it to PQSE 3 with the command line "rewrap" command.' : '',
      `Locks automatically after ${IDLE_LOCK_MS / 60_000} minutes without signing.`,
    ].filter(Boolean).join('\n');
    window.dispatchEvent(new Event('keys:updated'));
  }

  function armIdleLock() {
    clearTimeout(idleTimer);
    if (state.keys.secret) idleTimer = setTimeout(() => lock('Signing key locked after inactivity.'), IDLE_LOCK_MS);
  }

  // Termination is the lock: the key dies with the worker. The client's onReset
  // (also fired on timeouts and worker failures) lands in forget().
  function lock(message) {
    workerClient.reset();
    if (message) showToast('info', message);
  }

  function forget() {
    clearTimeout(idleTimer);
    wipeBytes(state.keys.secret?.secretKeyFile);
    state.keys.secret = null;
    render();
  }

  async function keyOperation(type, payload, clearFields) {
    state.keys.transitioning = true;
    render();
    try {
      const result = await workerClient.call(type, payload, { timeoutMs: KEY_OPERATION_TIMEOUT_MS });
      wipeBytes(state.keys.secret?.secretKeyFile);
      state.keys.secret = {
        suiteId: result.suiteId, fingerprintHex: result.fingerprintHex, publicKeyFile: result.publicKeyFile,
        secretKeyFile: result.secretKeyFile ?? null, legacy: result.legacy === true, saved: false,
      };
      armIdleLock();
      showToast('success', type === 'KEYGEN' ? 'Key generated. Save the encrypted private key and the public key.' : 'Signing key unlocked.');
    } catch (error) {
      showToast('error', workerFriendlyError(error));
    } finally {
      for (const field of clearFields) field.value = '';
      state.keys.transitioning = false;
      render();
    }
  }

  keygenForm.addEventListener('submit', (event) => {
    event.preventDefault();
    if (state.keys.transitioning) return;
    if (keygenPassphrase.value !== keygenConfirm.value) {
      showToast('error', 'Passphrases differ.');
      return;
    }
    if (state.keys.secret?.secretKeyFile && !state.keys.secret.saved &&
        !window.confirm('The current new key has not been saved and will be lost. Continue?')) return;
    void keyOperation('KEYGEN', { suiteId: Number(suiteSelect.value), passphrase: keygenPassphrase.value },
      [keygenPassphrase, keygenConfirm]);
  });

  unlockForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (state.keys.transitioning) return;
    let bytes;
    try {
      bytes = await readFileAsBytes(unlockFile.files?.[0], { maxBytes: MAX_KEY_FILE_BYTES, field: 'secretKeyFile' });
      if (!bytes) throw new Error('Select a private key file.');
      await keyOperation('UNLOCK', { secretKeyFile: bytes, passphrase: unlockPassphrase.value }, [unlockPassphrase]);
    } catch (error) {
      showToast('error', workerFriendlyError(error));
    } finally {
      wipeBytes(bytes);
    }
  });

  saveSecret.addEventListener('click', () => {
    const key = state.keys.secret;
    if (!key?.secretKeyFile) return;
    downloadBytes(`signer-${key.fingerprintHex.slice(0, 16)}.pqse`, key.secretKeyFile);
    key.saved = true;
  });
  savePublic.addEventListener('click', () => {
    const key = state.keys.secret;
    if (key) downloadBytes(`signer-${key.fingerprintHex.slice(0, 16)}.pqpk`, key.publicKeyFile);
  });
  lockButton.addEventListener('click', () => {
    const key = state.keys.secret;
    if (key?.secretKeyFile && !key.saved && !window.confirm('This new key has not been saved and will be lost. Lock anyway?')) return;
    lock();
  });

  window.addEventListener('signing-key:reset', forget);
  window.addEventListener('signing-key:used', armIdleLock);
  render();
}

function setupPublicKey(state) {
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
