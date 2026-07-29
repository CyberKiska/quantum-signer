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
const SECRET_SESSION_TIMEOUT_MS = 360_000;

const SLH_WARNING_TEXT = 'SLH-DSA generation is computationally intensive. It may take several minutes on mobile devices.';
const FALCON_WARNING_TEXT = 'Experimental: Falcon support uses Round 3 padded signatures, not FN-DSA / FIPS-206, and may be incompatible with final FN-DSA.';

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
    lines.push(`PRIVATE KEY [${getSuiteName(state.keys.secret.suiteId)}]`);
    lines.push(`Fingerprint (SHA3-256): ${state.keys.secret.fingerprintHex}`);
    lines.push(`Size: ${state.keys.secret.secretKeyLength} bytes`);
    lines.push(`Exported: ${state.keys.secret.exported ? 'YES' : 'NO'}`);
    lines.push('Warning: Private signing key is isolated in worker session. Browser memory hygiene remains best-effort.');
  }

  return lines.join('\n');
}

function notifyKeysUpdated(state) {
  // Subscribers already close over the shared application state. Do not also
  // broadcast the live key object and worker session handle on a DOM event.
  window.dispatchEvent(new Event('keys:updated'));
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
  const ownsTransition = !state.keys.transitioning;
  if (ownsTransition) {
    state.keys.transitioning = true;
    notifyKeysUpdated(state);
  }
  try {
    if (previousHandle && previousHandle !== result.sessionHandle) {
      await clearSecretSession(workerClient, previousHandle);
    }
    applySecretSessionIdentity(state, result, options);
  } catch (err) {
    try {
      await clearSecretSession(workerClient, result.sessionHandle);
    } catch (_cleanupErr) {
      // The worker may still complete a timed-out clear. Do not replace the
      // active UI identity when the transaction itself did not complete.
    }
    throw err;
  } finally {
    if (ownsTransition) {
      state.keys.transitioning = false;
      notifyKeysUpdated(state);
    }
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
  const privateKeyOperationsAllowed = state.privateKeyOperationsAllowed === true;
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
  let keyOperationBusy = false;

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
    exportPublicBtn.disabled = keyOperationBusy || state.keys.transitioning || !state.keys.public;
    exportSecretBtn.disabled =
      !privateKeyOperationsAllowed || keyOperationBusy || state.keys.transitioning || !state.keys.secret;
  }

  function setKeyOperationBusy(busy) {
    keyOperationBusy = busy;
    generateBtn.disabled = busy || !privateKeyOperationsAllowed;
    suiteSelect.disabled = busy;
    importPublicInput.disabled = busy;
    importSecretInput.disabled = busy || !privateKeyOperationsAllowed;
    clearBtn.disabled = busy;
    updateExportButtons();
  }

  function beginKeyTransition() {
    state.keys.transitioning = true;
    setKeyOperationBusy(true);
    notifyKeysUpdated(state);
  }

  function endKeyTransition() {
    state.keys.transitioning = false;
    setKeyOperationBusy(false);
    notifyKeysUpdated(state);
  }

  function syncUi() {
    infoEl.textContent = formatKeyInfo(state);
    updateExportButtons();
    notifyKeysUpdated(state);
  }

  workerClient.onSecretSessionInvalidated(({ reason, sessionHandle }) => {
    const activeHandle = state.keys.secret?.sessionHandle || null;
    if (sessionHandle && activeHandle !== sessionHandle) {
      return;
    }

    if (!state.keys.secret) return;

    state.keys.secret = null;
    // Do not release an in-flight key transaction here. Its own finally block
    // retains ownership of the busy state, preventing an expiry notification
    // from enabling a second key operation before the first one settles.
    syncUi();
    showToast(
      'warning',
      reason === 'idle-timeout' || reason === 'session-missing'
        ? 'Private-key session expired and was cleared. The public key remains loaded for verification.'
        : 'Cryptographic worker failed; the private-key session was cleared. A new worker will start on the next operation. The public key remains loaded for verification.'
    );
  });

  suiteSelect.addEventListener('change', refreshSuiteWarning);

  generateBtn.addEventListener('click', async () => {
    if (!privateKeyOperationsAllowed) return;
    if (keyOperationBusy) return;
    if (state.keys.secret && !confirm('A private key is already loaded. Generating a new one will overwrite it. Continue?')) {
      return;
    }

    try {
      beginKeyTransition();
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
      endKeyTransition();
      generateBtn.textContent = 'Generate Keypair';
    }
  });

  importPublicInput.addEventListener('change', async () => {
    if (keyOperationBusy) return;
    const file = importPublicInput.files?.[0];
    if (!file) return;

    try {
      beginKeyTransition();
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
          throw new Error('Imported public key does not match loaded private key. Clear session or import matching key pair.');
        }
      }

      setPublicKey(state, parsed, { exported: true });
      syncUi();
      showToast('success', 'Public key imported');
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      importPublicInput.value = '';
      endKeyTransition();
    }
  });

  importSecretInput.addEventListener('change', async () => {
    if (!privateKeyOperationsAllowed) {
      importSecretInput.value = '';
      return;
    }
    if (keyOperationBusy) return;
    if (state.keys.secret && !confirm('A private key is already loaded. Importing a new one will overwrite it. Continue?')) {
      importSecretInput.value = '';
      return;
    }

    const file = importSecretInput.files?.[0];
    if (!file) return;

    try {
      beginKeyTransition();
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
          if (!confirm('Loaded public key does not match imported private key. Replace active public key with derived one?')) {
            await clearSecretSession(workerClient, result.sessionHandle);
            importSecretInput.value = '';
            return;
          }
        }
      }

      await replaceSecretSession(state, workerClient, result, { exported: true });
      syncUi();
      showToast('success', 'Private key imported (public key synchronized)');
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      importSecretInput.value = '';
      endKeyTransition();
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
    if (!privateKeyOperationsAllowed) return;
    if (keyOperationBusy) return;
    if (!state.keys.secret) return;
    if (
      !confirm(
        'Exporting writes an unencrypted .pqsk private-key file. Anyone with this file can create signatures as this key. Continue?'
      )
    ) {
      return;
    }
    let secretKeyFile = null;
    const exportingSession = state.keys.secret;
    try {
      setKeyOperationBusy(true);
      const authorization = await workerClient.call(
        'AUTHORIZE_SECRET_EXPORT',
        { secretSessionHandle: exportingSession.sessionHandle },
        { timeoutMs: SECRET_SESSION_TIMEOUT_MS }
      );
      const result = await workerClient.call(
        'EXPORT_SECRET',
        {
          secretSessionHandle: exportingSession.sessionHandle,
          exportConsentToken: authorization.exportConsentToken,
        },
        { timeoutMs: SECRET_SESSION_TIMEOUT_MS }
      );
      secretKeyFile = result.secretKeyFile;
      const name = safeFileName(
        `${getSuiteName(exportingSession.suiteId)}-${exportingSession.fingerprintShort}.pqsk`
      );
      downloadBytes(name, secretKeyFile);
      // Yield once so the browser can begin its download/save UI before the
      // explicit user-attestation prompt is displayed.
      await new Promise((resolve) => setTimeout(resolve, 250));
      const exportConfirmed = confirm(
        `The browser was asked to save ${name}. Verify that the file exists in the intended location, then click OK. ` +
          'Choose Cancel if the download was blocked, cancelled, or not yet verified; the key will remain marked unexported.'
      );
      const activeSessionStillMatches = state.keys.secret?.sessionHandle === exportingSession.sessionHandle;
      if (activeSessionStillMatches) state.keys.secret.exported = exportConfirmed;
      syncUi();
      showToast(
        exportConfirmed && activeSessionStillMatches ? 'success' : 'warning',
        !activeSessionStillMatches
          ? 'Private-key download was requested, but the in-memory session expired before export could be confirmed'
          : exportConfirmed
          ? 'Private-key export confirmed by user'
          : 'Private-key download was requested but remains marked unexported'
      );
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      if (secretKeyFile) wipeBytes(secretKeyFile);
      setKeyOperationBusy(false);
    }
  });

  clearBtn.addEventListener('click', async () => {
    if (keyOperationBusy) return;
    if (!state.keys.public && !state.keys.secret) return;

    const hasUnexported = (state.keys.public && !state.keys.public.exported) || (state.keys.secret && !state.keys.secret.exported);

    if (hasUnexported) {
      if (!confirm('You have keys that have not been exported. They will be lost forever. Continue?')) {
        return;
      }
    }

    beginKeyTransition();
    let cleared = false;
    try {
      if (state.keys.secret?.sessionHandle) {
        await clearSecretSession(workerClient, state.keys.secret.sessionHandle);
      }
      wipePublicEntry(state.keys.public, { wipeContainer: true });
      state.keys.public = null;
      state.keys.secret = null;
      cleared = true;
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      endKeyTransition();
    }

    if (!cleared) return;
    syncUi();
    showToast('info', 'Session cleared');
  });

  refreshSuiteWarning();
  updateExportButtons();
}
