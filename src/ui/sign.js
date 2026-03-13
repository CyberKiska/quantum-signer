import { wipeBytes } from '../crypto/bytes.js';
import { getHashName, getSuiteName } from '../formats/containers.js';
import {
  byId,
  downloadBytes,
  resetProgress,
  setProgress,
  showToast,
  shortHex,
  workerFriendlyError,
} from './common.js';

const SIGN_TIMEOUT_MS = Object.freeze({
  ML_DSA: 90_000,
  SLH_DSA: 300_000,
});

function isSlowSigningSuite(suiteId) {
  return getSuiteName(suiteId).startsWith('SLH-DSA');
}

export function setupSignTab(state, workerClient) {
  const modeFileEl = byId('sign-mode-file');
  const modeTextEl = byId('sign-mode-text');
  const fileGroupEl = byId('sign-file-group');
  const textGroupEl = byId('sign-text-group');
  const fileInput = byId('sign-file');
  const textInput = byId('sign-text');
  const textPasteBtn = byId('sign-text-paste');
  const executeBtn = byId('sign-execute');
  const downloadBtn = byId('sign-download');
  const resetBtn = byId('sign-reset');

  const progressEl = byId('sign-progress');
  const progressLabelEl = byId('sign-progress-label');
  const resultEl = byId('sign-result');

  function clearLastSignature() {
    if (state.sign.lastSignature?.bytes) {
      wipeBytes(state.sign.lastSignature.bytes);
    }
    state.sign.lastSignature = null;
  }

  function getInputMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function applyInputModeUi() {
    const mode = getInputMode();
    fileGroupEl.classList.toggle('hidden', mode !== 'file');
    textGroupEl.classList.toggle('hidden', mode !== 'text');
  }

  function resetUi() {
    clearLastSignature();
    modeFileEl.checked = true;
    modeTextEl.checked = false;
    fileInput.value = '';
    textInput.value = '';
    resultEl.textContent = 'No signature generated yet.';
    downloadBtn.disabled = true;
    resetProgress(progressEl, progressLabelEl);
    applyInputModeUi();
  }

  executeBtn.addEventListener('click', async () => {
    const inputMode = getInputMode();
    const file = fileInput.files?.[0] ?? null;
    const text = textInput.value ?? '';

    if (inputMode === 'file' && !file) {
      showToast('warning', 'Please select a file to sign');
      return;
    }
    if (inputMode === 'text' && !text.length) {
      showToast('warning', 'Please provide plain text to sign');
      return;
    }
    if (!state.keys.secret) {
      showToast('warning', 'Please load a secret key first (Keys tab)');
      return;
    }

    try {
      executeBtn.disabled = true;
      downloadBtn.disabled = true;
      const slowSuite = isSlowSigningSuite(state.keys.secret.suiteId);
      showToast('info', slowSuite ? 'Signing... (this may take time)' : 'Signing...');

      const payload = {
        secretSessionHandle: state.keys.secret.sessionHandle,
      };
      if (inputMode === 'file') payload.file = file;
      else payload.text = text;

      const callOptions = {
        timeoutMs: slowSuite ? SIGN_TIMEOUT_MS.SLH_DSA : SIGN_TIMEOUT_MS.ML_DSA,
      };
      if (inputMode === 'file') {
        callOptions.onProgress = (p) => setProgress(progressEl, progressLabelEl, p.loaded, p.total);
      }

      const result = await workerClient.call(
        'SIGN',
        payload,
        callOptions
      );

      clearLastSignature();

      state.sign.lastSignature = {
        bytes: result.sigBytes,
        filename: inputMode === 'file' ? `${file.name}.qsig` : 'plain-text.qsig',
      };

      resultEl.textContent = [
        `Algorithm: ${getSuiteName(result.suiteId)}`,
        `Input: ${result.inputKind} (${result.inputLength} bytes)`,
        `Payload digest: ${getHashName(result.hashAlgId)} (${shortHex(result.fileHashHex, 16, 16)})`,
        `Context: ${result.context}`,
        `Signer fingerprint (SHA3-256): ${result.signerFingerprintHex}`,
        `Signature size: ${result.signatureLength} bytes`,
      ].join('\n');

      downloadBtn.disabled = false;
      showToast('success', 'Signature created successfully');
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      executeBtn.disabled = false;
      resetProgress(progressEl, progressLabelEl);
    }
  });

  modeFileEl.addEventListener('change', applyInputModeUi);
  modeTextEl.addEventListener('change', applyInputModeUi);

  textPasteBtn.addEventListener('click', async () => {
    if (!navigator.clipboard?.readText) {
      showToast('warning', 'Clipboard API is not available in this browser context');
      return;
    }
    try {
      const clipText = await navigator.clipboard.readText();
      textInput.value = clipText;
      modeTextEl.checked = true;
      modeFileEl.checked = false;
      applyInputModeUi();
      showToast('success', `Pasted ${clipText.length} characters`);
    } catch (_err) {
      showToast('error', 'Cannot read clipboard. Paste manually with Ctrl/Cmd+V');
    }
  });

  downloadBtn.addEventListener('click', () => {
    if (!state.sign.lastSignature) return;
    downloadBytes(state.sign.lastSignature.filename, state.sign.lastSignature.bytes);
    showToast('success', 'Signature downloaded');
  });

  resetBtn.addEventListener('click', resetUi);

  resetUi();
}
