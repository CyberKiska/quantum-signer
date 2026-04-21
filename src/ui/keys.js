import {
  assertKeyLength,
  computeFingerprint,
  computeFingerprintHex,
} from '../crypto/algorithms.js';
import { equalsBytes, wipeBytes } from '../crypto/bytes.js';
import {
  getSuiteName,
  packPublicKey,
  unpackPublicKey,
} from '../formats/containers.js';
import {
  MAX_KEY_FILE_BYTES,
} from '../crypto/policy.js';
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
  FALCON: 180_000,
  SLH_DSA: 300_000,
});
const SECRET_SESSION_TIMEOUT_MS = 60_000;
const secretExportConsentTokens = new Map();

const SLH_WARNING_TEXT = 'SLH-DSA generation is computationally intensive. It may take several minutes on mobile devices.';
const FALCON_WARNING_TEXT = 'Falcon support here uses Falcon Round 3 padded signatures, not FN-DSA / FIPS-206.';

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
    lines.push(`Size: ${state.keys.secret.secretKeyLength} bytes`);
    lines.push(`Exported: ${state.keys.secret.exported ? 'YES' : 'NO'}`);
    lines.push('Warning: Secret key is isolated in worker session. Browser memory hygiene remains best-effort.');
  }

  return lines.join('\n');
}

function notifyKeysUpdated(state) {
  window.dispatchEvent(new CustomEvent('keys:updated', { detail: state.keys }));
}

function wipePublicEntry(entry, { wipeContainer = false } = {}) {
  if (!entry) return;
  wipeBytes(entry.keyBytes);
  if (wipeContainer && entry.fileBytes) {
    wipeBytes(entry.fileBytes);
  }
}

function createPublicEntry(parsed, { exported = true } = {}) {
  assertKeyLength(parsed.suiteId, parsed.keyBytes, 'public');
  const keyBytes = Uint8Array.from(parsed.keyBytes);
  return {
    suiteId: parsed.suiteId,
    keyBytes,
    fileBytes: packPublicKey({ suiteId: parsed.suiteId, keyBytes }),
    fingerprintShort: computeFingerprint(keyBytes, 8),
    fingerprintHex: computeFingerprintHex(keyBytes),
    exported,
  };
}

function createSecretSessionEntry(result, { exported = true } = {}) {
  return {
    sessionHandle: result.sessionHandle,
    suiteId: result.suiteId,
    secretKeyLength: result.secretKeyLength,
    fingerprintShort: result.fingerprintShort,
    fingerprintHex: result.fingerprintHex,
    exported,
  };
}

function rememberExportConsent(result) {
  if (typeof result?.sessionHandle !== 'string' || typeof result?.exportConsentToken !== 'string') return;
  secretExportConsentTokens.set(result.sessionHandle, result.exportConsentToken);
}

function forgetExportConsent(sessionHandle) {
  if (typeof sessionHandle !== 'string' || sessionHandle.length === 0) return;
  secretExportConsentTokens.delete(sessionHandle);
}

function setPublicKey(state, parsed, options = {}) {
  wipePublicEntry(state.keys.public, { wipeContainer: true });
  state.keys.public = createPublicEntry(parsed, options);
}

function applySecretSessionIdentity(state, result, options = {}) {
  const parsedPublic = unpackPublicKey(result.publicKeyFile);
  setPublicKey(state, parsedPublic, options);
  state.keys.secret = createSecretSessionEntry(result, options);
}

async function clearSecretSession(workerClient, sessionHandle) {
  if (!sessionHandle) return false;
  const result = await workerClient.call(
    'CLEAR_SECRET_SESSION',
    { secretSessionHandle: sessionHandle },
    { timeoutMs: SECRET_SESSION_TIMEOUT_MS }
  );
  return result?.cleared === true;
}

async function replaceSecretSession(state, workerClient, result, options = {}) {
  const previousHandle = state.keys.secret?.sessionHandle || null;
  applySecretSessionIdentity(state, result, options);
  rememberExportConsent(result);
  if (previousHandle && previousHandle !== result.sessionHandle) {
    forgetExportConsent(previousHandle);
    await clearSecretSession(workerClient, previousHandle);
  }
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

  function getSuiteFamily(suiteId) {
    return suiteMap.get(suiteId)?.family || '';
  }

  function getSuiteWarningText(suiteId) {
    const family = getSuiteFamily(suiteId);
    if (family === 'SLH-DSA') return SLH_WARNING_TEXT;
    if (family === 'Falcon') return FALCON_WARNING_TEXT;
    return '';
  }

  function getKeygenTimeoutMs(suiteId) {
    const family = getSuiteFamily(suiteId);
    if (family === 'SLH-DSA') return KEYGEN_TIMEOUT_MS.SLH_DSA;
    if (family === 'Falcon') return KEYGEN_TIMEOUT_MS.FALCON;
    return KEYGEN_TIMEOUT_MS.ML_DSA;
  }

  function refreshSuiteWarning() {
    const suiteId = Number(suiteSelect.value);
    const warningText = getSuiteWarningText(suiteId);
    suiteWarningEl.classList.toggle('hidden', warningText.length === 0);
    suiteWarningEl.textContent = warningText;
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
      const showLongRunningToast = getSuiteFamily(suiteId) !== 'ML-DSA';

      showToast('info', showLongRunningToast ? 'Generating keypair... (this may take time)' : 'Generating keypair...');

      const result = await workerClient.call(
        'KEYGEN',
        { suiteId },
        { timeoutMs: getKeygenTimeoutMs(suiteId) }
      );
      await replaceSecretSession(state, workerClient, result, { exported: false });

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
      const bytes = await readFileAsBytes(file, { maxBytes: MAX_KEY_FILE_BYTES, field: 'publicKeyFile' });
      const parsed = unpackPublicKey(bytes);
      assertKeyLength(parsed.suiteId, parsed.keyBytes, 'public');

      if (state.keys.secret) {
        if (!state.keys.public) {
          throw new Error('Active secret session is missing its synchronized public key. Clear session and retry.');
        }
        const sameSuite = parsed.suiteId === state.keys.public.suiteId;
        const sameKey = equalsBytes(parsed.keyBytes, state.keys.public.keyBytes);
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
      const result = await workerClient.call(
        'IMPORT_SECRET',
        { secretKeyFile: file },
        { timeoutMs: KEYGEN_TIMEOUT_MS.SLH_DSA }
      );
      const parsedPublic = unpackPublicKey(result.publicKeyFile);

      if (state.keys.public) {
        const sameSuite = parsedPublic.suiteId === state.keys.public.suiteId;
        const sameKey = equalsBytes(parsedPublic.keyBytes, state.keys.public.keyBytes);
        if (!sameSuite || !sameKey) {
          if (!confirm('Loaded public key does not match imported secret key. Replace active public key with derived one?')) {
            await clearSecretSession(workerClient, result.sessionHandle);
            importSecretInput.value = '';
            return;
          }
        }
      }

      await replaceSecretSession(state, workerClient, result, { exported: true });
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

  exportSecretBtn.addEventListener('click', async () => {
    if (!state.keys.secret) return;
    if (
      !confirm(
        'Exporting the secret key gives full control over signatures. Continue and write the secret key to a local file?'
      )
    ) {
      return;
    }
    let secretKeyFile = null;
    try {
      const exportConsentToken = secretExportConsentTokens.get(state.keys.secret.sessionHandle);
      if (typeof exportConsentToken !== 'string' || exportConsentToken.length === 0) {
        throw new Error('Secret export authorization is unavailable. Re-import or regenerate the secret key session.');
      }
      const result = await workerClient.call(
        'EXPORT_SECRET',
        {
          secretSessionHandle: state.keys.secret.sessionHandle,
          exportConsentToken,
        },
        { timeoutMs: SECRET_SESSION_TIMEOUT_MS }
      );
      secretKeyFile = result.secretKeyFile;
      const name = safeFileName(`${getSuiteName(state.keys.secret.suiteId)}-${state.keys.secret.fingerprintShort}.pqsk`);
      downloadBytes(name, secretKeyFile);
      state.keys.secret.exported = true;
      syncUi();
      showToast('success', 'Secret key exported');
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      if (secretKeyFile) wipeBytes(secretKeyFile);
    }
  });

  clearBtn.addEventListener('click', async () => {
    if (!state.keys.public && !state.keys.secret) return;

    const hasUnexported = (state.keys.public && !state.keys.public.exported) || (state.keys.secret && !state.keys.secret.exported);

    if (hasUnexported) {
      if (!confirm('You have keys that have not been exported. They will be lost forever. Continue?')) {
        return;
      }
    }

    try {
      if (state.keys.secret?.sessionHandle) {
        await clearSecretSession(workerClient, state.keys.secret.sessionHandle);
        forgetExportConsent(state.keys.secret.sessionHandle);
      }
    } catch (err) {
      showToast('error', workerFriendlyError(err));
      return;
    }

    wipePublicEntry(state.keys.public, { wipeContainer: true });
    state.keys.public = null;
    state.keys.secret = null;
    syncUi();
    showToast('info', 'Session cleared');
  });

  refreshSuiteWarning();
  updateExportButtons();
}
