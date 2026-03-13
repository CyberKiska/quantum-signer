import { QSIG_V2_DEFAULT_CTX } from '../crypto/algorithms.js';
import { wipeBytes } from '../crypto/bytes.js';
import { HashAlgId, getHashName, getSuiteName } from '../formats/containers.js';
import {
  byId,
  downloadBytes,
  formatBytes,
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

const PREVIEW_TIMEOUT_MS = Object.freeze({
  FILE: 300_000,
  TEXT: 60_000,
});

const TEXT_PREVIEW_DEBOUNCE_MS = 180;

function isSlowSigningSuite(suiteId) {
  return getSuiteName(suiteId).startsWith('SLH-DSA');
}

function setBadge(badgeEl, tone, text) {
  badgeEl.className = `badge ${tone || 'neutral'}`;
  badgeEl.textContent = text;
}

function describeInput(mode, file, text, inputLength) {
  if (mode === 'file') {
    if (!file) return 'Waiting for file selection';
    return `File: ${file.name} (${formatBytes(inputLength ?? file.size)})`;
  }

  if (!text.length) return 'Waiting for plain text input';

  const sizeSuffix = Number.isInteger(inputLength) ? ` / ${formatBytes(inputLength)}` : '';
  return `Plain text: ${text.length} characters${sizeSuffix}`;
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

  const reviewBadgeEl = byId('sign-review-badge');
  const reviewEl = byId('sign-review');

  const progressEl = byId('sign-progress');
  const progressLabelEl = byId('sign-progress-label');
  const resultEl = byId('sign-result');

  let previewSeq = 0;
  let previewTimer = null;
  let previewState = {
    status: 'idle',
    hashHex: null,
    inputLength: null,
    error: null,
  };

  function clearLastSignature() {
    if (state.sign.lastSignature?.bytes) {
      wipeBytes(state.sign.lastSignature.bytes);
    }
    state.sign.lastSignature = null;
  }

  function invalidateLastSignature() {
    clearLastSignature();
    downloadBtn.disabled = true;
    resultEl.textContent = 'No signature generated yet.';
  }

  function getInputMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function getCurrentInput() {
    const mode = getInputMode();
    return {
      mode,
      file: fileInput.files?.[0] ?? null,
      text: textInput.value ?? '',
    };
  }

  function hasInput(input = getCurrentInput()) {
    return input.mode === 'file' ? Boolean(input.file) : input.text.length > 0;
  }

  function applyInputModeUi() {
    const mode = getInputMode();
    fileGroupEl.classList.toggle('hidden', mode !== 'file');
    textGroupEl.classList.toggle('hidden', mode !== 'text');
  }

  function cancelPreview() {
    previewSeq += 1;
    if (previewTimer) {
      clearTimeout(previewTimer);
      previewTimer = null;
    }
    resetProgress(progressEl, progressLabelEl);
  }

  function updateExecuteState() {
    executeBtn.disabled = !(state.keys.secret && previewState.status === 'ready');
  }

  function renderReview() {
    const { mode, file, text } = getCurrentInput();
    const lines = [];

    lines.push(describeInput(mode, file, text, previewState.inputLength));
    lines.push(`Context: ${QSIG_V2_DEFAULT_CTX}`);

    if (state.keys.secret) {
      lines.push(
        `Active signer: ${getSuiteName(state.keys.secret.suiteId)} / ${state.keys.secret.fingerprintHex}`
      );
    } else {
      lines.push('Active signer: load a secret key in Keys tab');
    }

    if (previewState.status === 'ready') {
      lines.push(`Payload digest (${getHashName(HashAlgId.SHA3_512)}): ${previewState.hashHex}`);
    } else if (previewState.status === 'loading') {
      lines.push('Payload digest (SHA3-512): computing...');
    } else if (previewState.status === 'error') {
      lines.push(`Payload digest (SHA3-512): unavailable (${previewState.error})`);
    } else {
      lines.push('Payload digest (SHA3-512): waiting for review input');
    }

    if (previewState.status === 'error') {
      setBadge(reviewBadgeEl, 'invalid', 'ERROR');
    } else if (previewState.status === 'loading') {
      setBadge(reviewBadgeEl, 'neutral', 'HASHING');
    } else if (previewState.status === 'ready' && !state.keys.secret) {
      setBadge(reviewBadgeEl, 'warning', 'LOAD KEY');
    } else if (previewState.status === 'ready') {
      setBadge(reviewBadgeEl, 'valid', 'READY');
    } else if (hasInput({ mode, file, text })) {
      setBadge(reviewBadgeEl, 'neutral', 'REVIEW');
    } else {
      setBadge(reviewBadgeEl, 'neutral', 'WAITING');
    }

    reviewEl.textContent = lines.join('\n');
    updateExecuteState();
  }

  function setPreviewState(nextState) {
    previewState = nextState;
    renderReview();
  }

  async function refreshPreviewNow() {
    const { mode, file, text } = getCurrentInput();

    if (mode === 'file' && !file) {
      setPreviewState({ status: 'idle', hashHex: null, inputLength: null, error: null });
      return;
    }

    if (mode === 'text' && !text.length) {
      setPreviewState({ status: 'idle', hashHex: null, inputLength: null, error: null });
      return;
    }

    const token = ++previewSeq;
    setPreviewState({
      status: 'loading',
      hashHex: null,
      inputLength: mode === 'file' ? file.size : null,
      error: null,
    });

    try {
      const result =
        mode === 'file'
          ? await workerClient.call(
              'HASH_FILE',
              { file },
              {
                timeoutMs: PREVIEW_TIMEOUT_MS.FILE,
                onProgress: (progress) => {
                  if (token !== previewSeq) return;
                  setProgress(progressEl, progressLabelEl, progress.loaded, progress.total);
                },
              }
            )
          : await workerClient.call('HASH_TEXT', { text }, { timeoutMs: PREVIEW_TIMEOUT_MS.TEXT });

      if (token !== previewSeq) return;

      setPreviewState({
        status: 'ready',
        hashHex: result.hashHex,
        inputLength: result.inputLength,
        error: null,
      });
    } catch (err) {
      if (token !== previewSeq) return;
      setPreviewState({
        status: 'error',
        hashHex: null,
        inputLength: mode === 'file' ? file.size : null,
        error: workerFriendlyError(err),
      });
    } finally {
      if (token === previewSeq) {
        resetProgress(progressEl, progressLabelEl);
      }
    }
  }

  function schedulePreviewRefresh({ debounceText = false } = {}) {
    cancelPreview();
    invalidateLastSignature();
    if (debounceText && getInputMode() === 'text') {
      previewTimer = setTimeout(() => {
        previewTimer = null;
        void refreshPreviewNow();
      }, TEXT_PREVIEW_DEBOUNCE_MS);
      return;
    }
    void refreshPreviewNow();
  }

  function resetUi() {
    cancelPreview();
    clearLastSignature();
    modeFileEl.checked = true;
    modeTextEl.checked = false;
    fileInput.value = '';
    textInput.value = '';
    previewState = {
      status: 'idle',
      hashHex: null,
      inputLength: null,
      error: null,
    };
    resultEl.textContent = 'No signature generated yet.';
    downloadBtn.disabled = true;
    applyInputModeUi();
    renderReview();
  }

  executeBtn.addEventListener('click', async () => {
    const input = getCurrentInput();

    if (input.mode === 'file' && !input.file) {
      showToast('warning', 'Please select a file to sign');
      return;
    }
    if (input.mode === 'text' && !input.text.length) {
      showToast('warning', 'Please provide plain text to sign');
      return;
    }
    if (!state.keys.secret) {
      showToast('warning', 'Please load a secret key first (Keys tab)');
      return;
    }
    if (previewState.status === 'loading') {
      showToast('warning', 'Wait for SHA3-512 review to complete before signing');
      return;
    }
    if (previewState.status === 'error') {
      showToast('error', previewState.error || 'Cannot sign because digest review failed');
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
      if (input.mode === 'file') payload.file = input.file;
      else payload.text = input.text;

      const callOptions = {
        timeoutMs: slowSuite ? SIGN_TIMEOUT_MS.SLH_DSA : SIGN_TIMEOUT_MS.ML_DSA,
      };
      if (input.mode === 'file') {
        callOptions.onProgress = (progress) => setProgress(progressEl, progressLabelEl, progress.loaded, progress.total);
      }

      const result = await workerClient.call('SIGN', payload, callOptions);

      clearLastSignature();

      state.sign.lastSignature = {
        bytes: result.sigBytes,
        filename: input.mode === 'file' ? `${input.file.name}.qsig` : 'plain-text.qsig',
      };

      resultEl.textContent = [
        `Algorithm: ${getSuiteName(result.suiteId)}`,
        `Input: ${result.inputKind} (${formatBytes(result.inputLength)})`,
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
      updateExecuteState();
      resetProgress(progressEl, progressLabelEl);
    }
  });

  modeFileEl.addEventListener('change', () => {
    applyInputModeUi();
    schedulePreviewRefresh();
  });
  modeTextEl.addEventListener('change', () => {
    applyInputModeUi();
    schedulePreviewRefresh();
  });

  fileInput.addEventListener('change', () => {
    schedulePreviewRefresh();
  });

  textInput.addEventListener('input', () => {
    schedulePreviewRefresh({ debounceText: true });
  });

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
      schedulePreviewRefresh({ debounceText: true });
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

  window.addEventListener('keys:updated', () => {
    invalidateLastSignature();
    renderReview();
  });

  resetUi();
}
