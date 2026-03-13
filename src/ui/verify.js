import { MAX_SIGNATURE_FILE_BYTES } from '../crypto/policy.js';
import { bytesToHexLower } from '../formats/encoding.js';
import { HashAlgId, getHashName, getSuiteName, unpackSignatureV2 } from '../formats/containers.js';
import {
  byId,
  formatBytes,
  readFileAsBytes,
  resetProgress,
  setProgress,
  showToast,
  workerFriendlyError,
} from './common.js';

const VERIFY_TIMEOUT_MS = Object.freeze({
  FILE_ML_DSA: 120_000,
  FILE_SLH_DSA: 300_000,
  TEXT_ML_DSA: 60_000,
  TEXT_SLH_DSA: 180_000,
});

const PREVIEW_TIMEOUT_MS = Object.freeze({
  FILE: 300_000,
  TEXT: 60_000,
});

const TEXT_PREVIEW_DEBOUNCE_MS = 180;

function isSlowSuite(suiteId) {
  return getSuiteName(suiteId).startsWith('SLH-DSA');
}

function setBadge(badgeEl, tone, text) {
  badgeEl.className = `badge ${tone || 'neutral'}`;
  badgeEl.textContent = text;
}

function describeVerifyInput(mode, file, text, inputLength) {
  if (mode === 'file') {
    if (!file) return 'Original input: waiting for file selection';
    return `Original input: ${file.name} (${formatBytes(inputLength ?? file.size)})`;
  }

  if (!text.length) return 'Original input: waiting for plain text';

  const sizeSuffix = Number.isInteger(inputLength) ? ` / ${formatBytes(inputLength)}` : '';
  return `Original input: plain text (${text.length} characters${sizeSuffix})`;
}

function describeTrustSource(result) {
  switch (result.trustSource) {
    case 'loaded-key':
      return 'Loaded public key';
    case 'embedded-only':
      return 'Embedded public key from .qsig';
    case 'key-mismatch':
      return 'Loaded and embedded keys disagree';
    case 'none':
      return 'No verification key available';
    default:
      return 'Unknown';
  }
}

function describeVerifiedKeySource(result) {
  switch (result.verifiedKeySource) {
    case 'loaded':
      return 'Loaded public key';
    case 'signature':
      return 'Embedded public key from .qsig';
    case 'both':
      return 'Loaded and embedded public keys';
    case 'none':
    default:
      return 'None';
  }
}

function renderVerifyResult(result) {
  const lines = [];
  lines.push(`Valid: ${result.valid ? 'YES' : 'NO'}`);
  lines.push(`Cryptographic verification: ${result.cryptoValid ? 'YES' : 'NO'}`);
  lines.push(`Trust source: ${describeTrustSource(result)}`);
  lines.push(`Verified key source: ${describeVerifiedKeySource(result)}`);
  lines.push(`Input type: ${result.inputKind}`);
  lines.push(`Input size: ${result.inputLength} bytes`);

  if (result.suiteId) lines.push(`Algorithm: ${getSuiteName(result.suiteId)}`);
  if (result.hashAlgName) lines.push(`Payload digest: ${result.hashAlgName}`);
  if (result.context) lines.push(`Context: ${result.context}`);
  if (typeof result.signatureLength === 'number') lines.push(`Signature size: ${result.signatureLength} bytes`);

  if (result.signerFingerprintHex) lines.push(`Verification key fingerprint (SHA3-256): ${result.signerFingerprintHex}`);
  if (result.signatureMetadataFingerprintHex) {
    lines.push(`Signature metadata fingerprint (SHA3-256): ${result.signatureMetadataFingerprintHex}`);
  }

  if (result.keyMismatch) {
    lines.push('');
    lines.push('--- KEY MISMATCH WARNING ---');
    lines.push('The loaded public key does not match the key embedded in .qsig.');
    lines.push(`Loaded key fingerprint: ${result.loadedKeyFingerprintHex}`);
    lines.push(`Embedded key fingerprint: ${result.embeddedKeyFingerprintHex}`);
    lines.push(`Loaded key verifies: ${result.loadedKeyValid}`);
    lines.push(`Embedded key verifies: ${result.embeddedKeyValid}`);
  }

  if (result.computedHashHex) lines.push(`Computed hash: ${result.computedHashHex}`);
  if (result.providedHashHex) lines.push(`Provided hash: ${result.providedHashHex}`);
  if (result.signedHashHex) lines.push(`Signed hash:   ${result.signedHashHex}`);

  if (result.code) lines.push(`Error code: ${result.code}`);
  if (result.warning) lines.push(`Warning: ${result.warning}`);

  return lines.join('\n');
}

export function setupVerifyTab(state, workerClient) {
  const modeFileEl = byId('verify-mode-file');
  const modeTextEl = byId('verify-mode-text');
  const fileGroupEl = byId('verify-file-group');
  const textGroupEl = byId('verify-text-group');
  const fileInput = byId('verify-file-input');
  const textInput = byId('verify-text-input');
  const textPasteBtn = byId('verify-text-paste');
  const sigInput = byId('verify-sig-file');
  const verifyBtn = byId('verify-run');

  const progressEl = byId('verify-progress');
  const progressLabelEl = byId('verify-progress-label');
  const reviewBadgeEl = byId('verify-review-badge');
  const reviewEl = byId('verify-review');

  const resultCard = byId('verify-result-card');
  const resultIcon = byId('verify-icon');
  const resultHeading = byId('verify-heading');
  const resultBadge = byId('verify-result-badge');
  const resultMessage = byId('verify-message');
  const resultCaveat = byId('verify-caveat');
  const resultDetails = byId('verify-details');

  let inputPreviewSeq = 0;
  let inputPreviewTimer = null;
  let signaturePreviewSeq = 0;

  let inputPreview = {
    status: 'idle',
    hashHex: null,
    inputLength: null,
    error: null,
  };

  let signaturePreview = {
    status: 'idle',
    error: null,
    suiteId: null,
    hashAlgName: null,
    context: null,
    signatureLength: null,
    embeddedFingerprintHex: null,
    displayFilename: null,
    displayFilesize: null,
    displayCreatedAt: null,
    signatureFilename: null,
    loadedKeyMatches: null,
  };

  function setResultTone(tone, badgeText) {
    resultCard.classList.remove('valid', 'invalid', 'warning');
    resultHeading.classList.remove('valid', 'invalid', 'warning');

    resultBadge.className = 'badge neutral';
    resultBadge.textContent = badgeText;

    if (!tone) return;

    resultCard.classList.add(tone);
    resultHeading.classList.add(tone);
    resultBadge.className = `badge ${tone}`;
  }

  function setResultCaveat(message = '') {
    resultCaveat.textContent = message || '';
    resultCaveat.classList.toggle('hidden', !message);
  }

  function hideResultCard() {
    resultCard.classList.add('hidden');
    resultIcon.textContent = '';
    resultHeading.textContent = '';
    resultMessage.textContent = '';
    resultDetails.textContent = '';
    setResultTone(null, '-');
    setResultCaveat('');
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

  function hasVerifyInput(input = getCurrentInput()) {
    return input.mode === 'file' ? Boolean(input.file) : input.text.length > 0;
  }

  function deriveLoadedKeyMatches(embeddedFingerprintHex) {
    if (!embeddedFingerprintHex || !state.keys.public) return null;
    return state.keys.public.fingerprintHex === embeddedFingerprintHex;
  }

  function applyInputModeUi() {
    const mode = getInputMode();
    fileGroupEl.classList.toggle('hidden', mode !== 'file');
    textGroupEl.classList.toggle('hidden', mode !== 'text');
  }

  function cancelInputPreview() {
    inputPreviewSeq += 1;
    if (inputPreviewTimer) {
      clearTimeout(inputPreviewTimer);
      inputPreviewTimer = null;
    }
    resetProgress(progressEl, progressLabelEl);
  }

  function updateVerifyButtonState() {
    verifyBtn.disabled = !(inputPreview.status === 'ready' && signaturePreview.status === 'ready');
  }

  function renderReview() {
    const { mode, file, text } = getCurrentInput();
    const sigFile = sigInput.files?.[0] ?? null;
    const lines = [];

    lines.push(describeVerifyInput(mode, file, text, inputPreview.inputLength));
    if (inputPreview.status === 'ready') {
      lines.push(`Computed payload digest (${getHashName(HashAlgId.SHA3_512)}): ${inputPreview.hashHex}`);
    } else if (inputPreview.status === 'loading') {
      lines.push('Computed payload digest (SHA3-512): computing...');
    } else if (inputPreview.status === 'error') {
      lines.push(`Computed payload digest (SHA3-512): unavailable (${inputPreview.error})`);
    } else {
      lines.push('Computed payload digest (SHA3-512): waiting for review input');
    }

    if (!sigFile) {
      lines.push('Signature file: waiting for .qsig selection');
    } else {
      lines.push(`Signature file: ${sigFile.name} (${formatBytes(sigFile.size)})`);
    }

    if (signaturePreview.status === 'ready') {
      lines.push(`Declared algorithm: ${getSuiteName(signaturePreview.suiteId)}`);
      lines.push(`Declared payload digest: ${signaturePreview.hashAlgName}`);
      lines.push(`Context: ${signaturePreview.context}`);
      lines.push(`Embedded signer fingerprint (SHA3-256): ${signaturePreview.embeddedFingerprintHex}`);
      if (signaturePreview.displayFilename) {
        lines.push(`Display filename: ${signaturePreview.displayFilename}`);
      }
      if (signaturePreview.displayFilesize !== null) {
        lines.push(`Display filesize: ${signaturePreview.displayFilesize} bytes`);
      }
      if (signaturePreview.displayCreatedAt) {
        lines.push(`Display createdAt: ${signaturePreview.displayCreatedAt}`);
      }
    } else if (signaturePreview.status === 'loading') {
      lines.push('Signature metadata: parsing .qsig...');
    } else if (signaturePreview.status === 'error') {
      lines.push(`Signature metadata: unavailable (${signaturePreview.error})`);
    } else {
      lines.push('Signature metadata: waiting for .qsig selection');
    }

    if (state.keys.public) {
      lines.push(`Loaded public key (SHA3-256): ${state.keys.public.fingerprintHex}`);
    } else {
      lines.push('Loaded public key: none loaded');
    }

    if (signaturePreview.status === 'ready') {
      if (signaturePreview.loadedKeyMatches === true) {
        lines.push('Key relationship: loaded public key matches embedded signer key');
      } else if (signaturePreview.loadedKeyMatches === false) {
        lines.push('Key relationship: warning, loaded public key differs from embedded signer key');
      } else {
        lines.push('Key relationship: verification can use embedded signer key if no public key is loaded');
      }
    }

    if (inputPreview.status === 'error' || signaturePreview.status === 'error') {
      setBadge(reviewBadgeEl, 'invalid', 'ERROR');
    } else if (inputPreview.status === 'loading' || signaturePreview.status === 'loading') {
      setBadge(reviewBadgeEl, 'neutral', 'REVIEW');
    } else if (inputPreview.status === 'ready' && signaturePreview.status === 'ready') {
      setBadge(reviewBadgeEl, 'valid', 'READY');
    } else if (hasVerifyInput({ mode, file, text }) || sigFile) {
      setBadge(reviewBadgeEl, 'neutral', 'REVIEW');
    } else {
      setBadge(reviewBadgeEl, 'neutral', 'WAITING');
    }

    reviewEl.textContent = lines.join('\n');
    updateVerifyButtonState();
  }

  function setInputPreview(nextState) {
    inputPreview = nextState;
    renderReview();
  }

  function setSignaturePreview(nextState) {
    signaturePreview = nextState;
    renderReview();
  }

  function timeoutForMode(mode) {
    const suiteId = signaturePreview.suiteId ?? state.keys.public?.suiteId;
    const slow = suiteId !== undefined ? isSlowSuite(suiteId) : true;
    if (mode === 'text') {
      return slow ? VERIFY_TIMEOUT_MS.TEXT_SLH_DSA : VERIFY_TIMEOUT_MS.TEXT_ML_DSA;
    }
    return slow ? VERIFY_TIMEOUT_MS.FILE_SLH_DSA : VERIFY_TIMEOUT_MS.FILE_ML_DSA;
  }

  async function refreshInputPreviewNow() {
    const { mode, file, text } = getCurrentInput();

    if (mode === 'file' && !file) {
      setInputPreview({ status: 'idle', hashHex: null, inputLength: null, error: null });
      return;
    }

    if (mode === 'text' && !text.length) {
      setInputPreview({ status: 'idle', hashHex: null, inputLength: null, error: null });
      return;
    }

    const token = ++inputPreviewSeq;
    setInputPreview({
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
                  if (token !== inputPreviewSeq) return;
                  setProgress(progressEl, progressLabelEl, progress.loaded, progress.total);
                },
              }
            )
          : await workerClient.call('HASH_TEXT', { text }, { timeoutMs: PREVIEW_TIMEOUT_MS.TEXT });

      if (token !== inputPreviewSeq) return;

      setInputPreview({
        status: 'ready',
        hashHex: result.hashHex,
        inputLength: result.inputLength,
        error: null,
      });
    } catch (err) {
      if (token !== inputPreviewSeq) return;
      setInputPreview({
        status: 'error',
        hashHex: null,
        inputLength: mode === 'file' ? file.size : null,
        error: workerFriendlyError(err),
      });
    } finally {
      if (token === inputPreviewSeq) {
        resetProgress(progressEl, progressLabelEl);
      }
    }
  }

  function scheduleInputPreviewRefresh({ debounceText = false } = {}) {
    cancelInputPreview();
    hideResultCard();
    if (debounceText && getInputMode() === 'text') {
      inputPreviewTimer = setTimeout(() => {
        inputPreviewTimer = null;
        void refreshInputPreviewNow();
      }, TEXT_PREVIEW_DEBOUNCE_MS);
      return;
    }
    void refreshInputPreviewNow();
  }

  async function refreshSignaturePreview() {
    const sigFile = sigInput.files?.[0] ?? null;
    const token = ++signaturePreviewSeq;
    hideResultCard();

    if (!sigFile) {
      setSignaturePreview({
        status: 'idle',
        error: null,
        suiteId: null,
        hashAlgName: null,
        context: null,
        signatureLength: null,
        embeddedFingerprintHex: null,
        displayFilename: null,
        displayFilesize: null,
        displayCreatedAt: null,
        signatureFilename: null,
        loadedKeyMatches: null,
      });
      return;
    }

    setSignaturePreview({
      status: 'loading',
      error: null,
      suiteId: null,
      hashAlgName: null,
      context: null,
      signatureLength: null,
      embeddedFingerprintHex: null,
      displayFilename: null,
      displayFilesize: null,
      displayCreatedAt: null,
      signatureFilename: sigFile.name,
      loadedKeyMatches: null,
    });

    try {
      const sigBytes = await readFileAsBytes(sigFile, { maxBytes: MAX_SIGNATURE_FILE_BYTES, field: 'sigFile' });
      const parsedSig = unpackSignatureV2(sigBytes);
      const embeddedFingerprintHex = parsedSig.metadata?.signerFingerprintDigest
        ? bytesToHexLower(parsedSig.metadata.signerFingerprintDigest)
        : null;

      if (token !== signaturePreviewSeq) return;

      setSignaturePreview({
        status: 'ready',
        error: null,
        suiteId: parsedSig.suiteId,
        hashAlgName: getHashName(parsedSig.payloadDigestAlgId),
        context: parsedSig.ctx,
        signatureLength: parsedSig.signatureLength,
        embeddedFingerprintHex,
        displayFilename: parsedSig.displayMetadata?.filename || null,
        displayFilesize:
          typeof parsedSig.displayMetadata?.filesize === 'bigint' ? parsedSig.displayMetadata.filesize.toString() : null,
        displayCreatedAt: parsedSig.displayMetadata?.createdAt || null,
        signatureFilename: sigFile.name,
        loadedKeyMatches: deriveLoadedKeyMatches(embeddedFingerprintHex),
      });
    } catch (err) {
      if (token !== signaturePreviewSeq) return;
      setSignaturePreview({
        status: 'error',
        error: workerFriendlyError(err),
        suiteId: null,
        hashAlgName: null,
        context: null,
        signatureLength: null,
        embeddedFingerprintHex: null,
        displayFilename: null,
        displayFilesize: null,
        displayCreatedAt: null,
        signatureFilename: sigFile.name,
        loadedKeyMatches: null,
      });
    }
  }

  function renderResultCard(result) {
    resultCard.classList.remove('hidden');
    resultDetails.textContent = renderVerifyResult(result);
    setResultCaveat(result.warning || '');

    if (result.keyMismatch) {
      const loadedValid = result.loadedKeyValid === true;
      const embeddedValid = result.embeddedKeyValid === true;

      setResultTone('warning', 'WARNING');
      resultIcon.textContent = '⚠️';

      if (loadedValid && embeddedValid) {
        resultHeading.textContent = 'Signature Valid With Key Mismatch';
        resultMessage.textContent =
          'Both loaded and embedded public keys verify this signature, but they are different keys.';
        showToast('warning', 'Key mismatch detected');
        return;
      }

      if (result.valid) {
        resultHeading.textContent = 'Signature Valid With Key Mismatch';
        resultMessage.textContent =
          'Signature is valid with the loaded public key, but embedded signer metadata in .qsig does not match it.';
        showToast('warning', 'Key mismatch detected');
        return;
      }

      setResultTone('invalid', 'INVALID');
      resultIcon.textContent = '❌';
      resultHeading.textContent = 'Verification Failed';
      resultMessage.textContent = embeddedValid
        ? 'Signature matches the embedded key in .qsig, but it does not match the loaded public key.'
        : 'Verification failed for both loaded and embedded public keys.';
      showToast('error', 'Verification failed');
      return;
    }

    if (result.valid) {
      setResultTone('valid', 'VALID');
      resultIcon.textContent = '✅';
      resultHeading.textContent = 'Signature Valid';
      resultMessage.textContent =
        result.inputKind === 'text'
          ? 'The signature is valid and matches the provided plain text.'
          : 'The signature is valid and matches the selected file.';
      showToast('success', 'Verification successful');
      return;
    }

    setResultTone('invalid', 'INVALID');
    resultIcon.textContent = '❌';
    resultHeading.textContent = 'Verification Failed';

    if (result.code === 'E_INPUT_REQUIRED') {
      resultMessage.textContent = 'No verification key is available. Load a public key or use a .qsig with embedded signer metadata.';
    } else {
      resultMessage.textContent = result.cryptoValid
        ? 'Cryptographic verification succeeded with a non-trusted key source, but final verification failed under the current trust policy.'
        : `The signature is invalid. Error: ${result.code || 'Unknown'}`;
    }

    showToast('error', 'Verification failed');
  }

  verifyBtn.addEventListener('click', async () => {
    const input = getCurrentInput();
    const sigFile = sigInput.files?.[0] ?? null;

    if (input.mode === 'file' && !input.file) {
      showToast('warning', 'Select a file to verify');
      return;
    }
    if (input.mode === 'text' && !input.text.length) {
      showToast('warning', 'Enter plain text to verify');
      return;
    }
    if (!sigFile) {
      showToast('warning', 'Select a signature file (.qsig)');
      return;
    }
    if (inputPreview.status === 'loading' || signaturePreview.status === 'loading') {
      showToast('warning', 'Wait for review data to finish loading before verification');
      return;
    }
    if (inputPreview.status === 'error') {
      showToast('error', inputPreview.error || 'Cannot verify because input digest review failed');
      return;
    }
    if (signaturePreview.status === 'error') {
      showToast('error', signaturePreview.error || 'Cannot verify because .qsig review failed');
      return;
    }

    hideResultCard();
    verifyBtn.disabled = true;
    resetProgress(progressEl, progressLabelEl);
    showToast('info', 'Verifying...');

    try {
      const sigBytes = await readFileAsBytes(sigFile, { maxBytes: MAX_SIGNATURE_FILE_BYTES, field: 'sigFile' });
      const publicKeyFile = state.keys.public?.fileBytes || null;

      const result =
        input.mode === 'text'
          ? await workerClient.call(
              'VERIFY_TEXT',
              { text: input.text, sigFile: sigBytes, publicKeyFile },
              { timeoutMs: timeoutForMode('text') }
            )
          : await workerClient.call(
              'VERIFY_FILE',
              { file: input.file, sigFile: sigBytes, publicKeyFile },
              {
                timeoutMs: timeoutForMode('file'),
                onProgress: (progress) => setProgress(progressEl, progressLabelEl, progress.loaded, progress.total),
              }
            );

      renderResultCard(result);
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      updateVerifyButtonState();
      resetProgress(progressEl, progressLabelEl);
    }
  });

  modeFileEl.addEventListener('change', () => {
    applyInputModeUi();
    scheduleInputPreviewRefresh();
  });
  modeTextEl.addEventListener('change', () => {
    applyInputModeUi();
    scheduleInputPreviewRefresh();
  });

  fileInput.addEventListener('change', () => {
    scheduleInputPreviewRefresh();
  });

  textInput.addEventListener('input', () => {
    scheduleInputPreviewRefresh({ debounceText: true });
  });

  sigInput.addEventListener('change', () => {
    void refreshSignaturePreview();
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
      scheduleInputPreviewRefresh({ debounceText: true });
      showToast('success', `Pasted ${clipText.length} characters`);
    } catch (_err) {
      showToast('error', 'Cannot read clipboard. Paste manually with Ctrl/Cmd+V');
    }
  });

  window.addEventListener('keys:updated', () => {
    hideResultCard();
    if (signaturePreview.status === 'ready') {
      setSignaturePreview({
        ...signaturePreview,
        loadedKeyMatches: deriveLoadedKeyMatches(signaturePreview.embeddedFingerprintHex),
      });
      return;
    }
    renderReview();
  });

  applyInputModeUi();
  hideResultCard();
  renderReview();
}
