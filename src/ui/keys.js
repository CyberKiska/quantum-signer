import {
  assertKeyLength,
  computeFingerprint,
  computeFingerprintHex,
  getPublicKeyFromSecret,
} from '../crypto/algorithms.js';
import { equalsBytes, wipeBytes } from '../crypto/bytes.js';
import {
  getSuiteName,
  packPublicKeyV1,
  packSecretKeyV1,
  unpackPublicKeyV1,
  unpackSecretKeyV1,
} from '../formats/containers.js';
import {
  byId,
  downloadBytes,
  readFileAsBytes,
  safeFileName,
  showToast,
  workerFriendlyError,
} from './common.js';

const KEYGEN_TIMEOUT_MS = Object.freeze({
  ML_DSA: 60_000,
  SLH_DSA: 300_000,
});

const SLH_WARNING_TEXT = 'SLH-DSA generation is computationally intensive. It may take several minutes on mobile devices.';

function formatKeyInfo(state) {
  const lines = [];

  if (!state.keys.public && !state.keys.secret) {
    return 'No keys loaded in active memory.';
  }

  if (state.keys.public) {
    lines.push(`PUBLIC KEY [${getSuiteName(state.keys.public.suiteId)}]`);
    lines.push(`Fingerprint (SHA3-256): ${state.keys.public.fingerprintHex}`);
    lines.push(`Size: ${state.keys.public.keyBytes.length} bytes`);
    lines.push(`Exported: ${state.keys.public.exported ? 'YES' : 'NO'}`);
    lines.push('');
  }

  if (state.keys.secret) {
    lines.push(`SECRET KEY [${getSuiteName(state.keys.secret.suiteId)}]`);
    lines.push(`Fingerprint (SHA3-256): ${state.keys.secret.fingerprintHex}`);
    lines.push(`Size: ${state.keys.secret.keyBytes.length} bytes`);
    lines.push(`Exported: ${state.keys.secret.exported ? 'YES' : 'NO'}`);
    lines.push('Warning: Secret key is in memory. Do not leave unattended.');
  }

  return lines.join('\n');
}

function notifyKeysUpdated(state) {
  window.dispatchEvent(new CustomEvent('keys:updated', { detail: state.keys }));
}

function wipeKeyEntry(entry, { wipeContainer = false } = {}) {
  if (!entry) return;
  wipeBytes(entry.keyBytes);
  if (wipeContainer && entry.fileBytes) {
    wipeBytes(entry.fileBytes);
  }
}

function wipeStoredKeys(state) {
  wipeKeyEntry(state.keys.public, { wipeContainer: true });
  wipeKeyEntry(state.keys.secret, { wipeContainer: true });
}

function createPublicEntry(parsed, { exported = true } = {}) {
  assertKeyLength(parsed.suiteId, parsed.keyBytes, 'public');
  return {
    suiteId: parsed.suiteId,
    keyBytes: parsed.keyBytes,
    fileBytes: packPublicKeyV1({ suiteId: parsed.suiteId, keyBytes: parsed.keyBytes }),
    fingerprintShort: computeFingerprint(parsed.keyBytes, 8),
    fingerprintHex: computeFingerprintHex(parsed.keyBytes),
    exported,
  };
}

function createSecretEntry(parsed, { exported = true } = {}) {
  assertKeyLength(parsed.suiteId, parsed.keyBytes, 'secret');
  const derivedPublic = getPublicKeyFromSecret(parsed.suiteId, parsed.keyBytes);
  return {
    entry: {
      suiteId: parsed.suiteId,
      keyBytes: parsed.keyBytes,
      fileBytes: packSecretKeyV1({ suiteId: parsed.suiteId, keyBytes: parsed.keyBytes }),
      fingerprintShort: computeFingerprint(derivedPublic, 8),
      fingerprintHex: computeFingerprintHex(derivedPublic),
      exported,
    },
    derivedPublic,
  };
}

function setPublicKey(state, parsed, options = {}) {
  wipeKeyEntry(state.keys.public, { wipeContainer: true });
  state.keys.public = createPublicEntry(parsed, options);
}

function setSecretKey(state, parsed, options = {}) {
  wipeKeyEntry(state.keys.secret, { wipeContainer: true });
  const secret = createSecretEntry(parsed, options);
  state.keys.secret = secret.entry;
  return secret.derivedPublic;
}

function setIdentityFromSecret(state, parsedSecret, { exported = true } = {}) {
  const derivedPublic = setSecretKey(state, parsedSecret, { exported });
  setPublicKey(
    state,
    {
      suiteId: parsedSecret.suiteId,
      keyBytes: derivedPublic,
    },
    { exported }
  );
  return derivedPublic;
}

export function populateSuiteSelect(selectEl, suites, defaultSuiteId) {
  selectEl.innerHTML = '';
  for (const suite of suites) {
    const option = document.createElement('option');
    option.value = String(suite.id);
    option.textContent = `${suite.name}`;
    if (suite.id === defaultSuiteId) option.selected = true;
    selectEl.append(option);
  }
}

export function setupKeysTab(state, workerClient, suites, defaultSuiteId) {
  const suiteSelect = byId('keys-suite');
  const suiteWarningEl = byId('keys-suite-warning');
  const generateBtn = byId('keys-generate');

  const importPublicInput = byId('keys-import-public');
  const importSecretInput = byId('keys-import-secret');

  const exportPublicBtn = byId('keys-export-public');
  const exportSecretBtn = byId('keys-export-secret');
  const clearBtn = byId('keys-clear');

  const infoEl = byId('keys-info');
  const suiteMap = new Map(suites.map((suite) => [suite.id, suite]));

  populateSuiteSelect(suiteSelect, suites, defaultSuiteId);
  infoEl.textContent = formatKeyInfo(state);

  function isSlowSuite(suiteId) {
    return suiteMap.get(suiteId)?.family === 'SLH-DSA';
  }

  function refreshSuiteWarning() {
    const suiteId = Number(suiteSelect.value);
    const show = isSlowSuite(suiteId);
    suiteWarningEl.classList.toggle('hidden', !show);
    suiteWarningEl.textContent = show ? SLH_WARNING_TEXT : '';
  }

  function updateExportButtons() {
    exportPublicBtn.disabled = !state.keys.public;
    exportSecretBtn.disabled = !state.keys.secret;
  }

  function syncUi() {
    infoEl.textContent = formatKeyInfo(state);
    updateExportButtons();
    notifyKeysUpdated(state);
  }

  suiteSelect.addEventListener('change', refreshSuiteWarning);

  generateBtn.addEventListener('click', async () => {
    if (state.keys.secret && !confirm('A secret key is already loaded. Generating a new one will overwrite it. Continue?')) {
      return;
    }

    try {
      generateBtn.disabled = true;
      generateBtn.textContent = 'Generating...';

      const suiteId = Number(suiteSelect.value);
      const slowSuite = isSlowSuite(suiteId);

      showToast('info', slowSuite ? 'Generating keypair... (this may take time)' : 'Generating keypair...');

      const result = await workerClient.call(
        'KEYGEN',
        { suiteId },
        { timeoutMs: slowSuite ? KEYGEN_TIMEOUT_MS.SLH_DSA : KEYGEN_TIMEOUT_MS.ML_DSA }
      );

      const parsedPub = unpackPublicKeyV1(result.publicKeyFile);
      const parsedSec = unpackSecretKeyV1(result.secretKeyFile);
      const derivedPublic = setIdentityFromSecret(state, parsedSec, { exported: false });
      if (!equalsBytes(parsedPub.keyBytes, derivedPublic)) {
        throw new Error('Public key mismatch with generated secret key');
      }

      syncUi();
      showToast('success', `Identity created: ${result.suiteName}`);
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate Keypair';
    }
  });

  importPublicInput.addEventListener('change', async () => {
    const file = importPublicInput.files?.[0];
    if (!file) return;

    try {
      const bytes = await readFileAsBytes(file);
      const parsed = unpackPublicKeyV1(bytes);
      assertKeyLength(parsed.suiteId, parsed.keyBytes, 'public');

      if (state.keys.secret) {
        const derivedPublicFromSecret = getPublicKeyFromSecret(state.keys.secret.suiteId, state.keys.secret.keyBytes);
        const sameSuite = parsed.suiteId === state.keys.secret.suiteId;
        const sameKey = equalsBytes(parsed.keyBytes, derivedPublicFromSecret);
        if (!sameSuite || !sameKey) {
          throw new Error('Imported public key does not match loaded secret key. Clear session or import matching key pair.');
        }
      }

      setPublicKey(state, parsed, { exported: true });
      syncUi();
      showToast('success', 'Public key imported');
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      importPublicInput.value = '';
    }
  });

  importSecretInput.addEventListener('change', async () => {
    if (state.keys.secret && !confirm('A secret key is already loaded. Importing a new one will overwrite it. Continue?')) {
      importSecretInput.value = '';
      return;
    }

    const file = importSecretInput.files?.[0];
    if (!file) return;

    try {
      const bytes = await readFileAsBytes(file);
      const parsed = unpackSecretKeyV1(bytes);
      assertKeyLength(parsed.suiteId, parsed.keyBytes, 'secret');

      if (state.keys.public) {
        const derivedPublic = getPublicKeyFromSecret(parsed.suiteId, parsed.keyBytes);
        const sameSuite = parsed.suiteId === state.keys.public.suiteId;
        const sameKey = equalsBytes(derivedPublic, state.keys.public.keyBytes);
        if (!sameSuite || !sameKey) {
          if (!confirm('Loaded public key does not match imported secret key. Replace active public key with derived one?')) {
            importSecretInput.value = '';
            return;
          }
        }
      }

      setIdentityFromSecret(state, parsed, { exported: true });
      syncUi();
      showToast('success', 'Secret key imported (public key synchronized)');
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      importSecretInput.value = '';
    }
  });

  exportPublicBtn.addEventListener('click', () => {
    if (!state.keys.public) return;
    const name = safeFileName(`${getSuiteName(state.keys.public.suiteId)}-${state.keys.public.fingerprintShort}.pqpk`);
    downloadBytes(name, state.keys.public.fileBytes);
    state.keys.public.exported = true;
    syncUi();
    showToast('success', 'Public key exported');
  });

  exportSecretBtn.addEventListener('click', () => {
    if (!state.keys.secret) return;
    const name = safeFileName(`${getSuiteName(state.keys.secret.suiteId)}-${state.keys.secret.fingerprintShort}.pqsk`);
    downloadBytes(name, state.keys.secret.fileBytes);
    state.keys.secret.exported = true;
    syncUi();
    showToast('success', 'Secret key exported');
  });

  clearBtn.addEventListener('click', () => {
    if (!state.keys.public && !state.keys.secret) return;

    const hasUnexported = (state.keys.public && !state.keys.public.exported) || (state.keys.secret && !state.keys.secret.exported);

    if (hasUnexported) {
      if (!confirm('You have keys that have not been exported. They will be lost forever. Continue?')) {
        return;
      }
    }

    wipeStoredKeys(state);
    state.keys.public = null;
    state.keys.secret = null;
    syncUi();
    showToast('info', 'Session cleared');
  });

  refreshSuiteWarning();
  updateExportButtons();

  window.addEventListener('keys:updated', () => {
    const fpEl = document.getElementById('ctx-pub-fp');
    if (fpEl) {
      fpEl.title = state.keys.public ? `SHA3-256: ${state.keys.public.fingerprintHex}` : '';
    }
  });
}
