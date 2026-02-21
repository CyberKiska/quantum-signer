import { getSuiteName } from '../formats/containers.js';
import {
  byId,
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

function isSlowSuite(suiteId) {
  return getSuiteName(suiteId).startsWith('SLH-DSA');
}

function renderVerifyResult(result) {
  const lines = [];
  lines.push(`Valid: ${result.valid ? 'YES' : 'NO'}`);
  lines.push(`Input type: ${result.inputKind}`);
  lines.push(`Input size: ${result.inputLength} bytes`);

  if (result.suiteId) lines.push(`Algorithm: ${getSuiteName(result.suiteId)}`);
  if (result.hashAlgName) lines.push(`Hash: ${result.hashAlgName}`);
  if (typeof result.signatureLength === 'number') lines.push(`Signature size: ${result.signatureLength} bytes`);

  if (result.signerFingerprintHex) lines.push(`Verification key fingerprint (SHA3-256): ${result.signerFingerprintHex}`);
  if (result.signatureMetadataFingerprintHex) {
    lines.push(`Signature metadata fingerprint (SHA3-256): ${result.signatureMetadataFingerprintHex}`);
  }

  if (result.keyMismatch) {
    lines.push('');
    lines.push('--- KEY MISMATCH WARNING ---');
    lines.push('The loaded public key does not match the key embedded in .sig.');
    lines.push(`Loaded key fingerprint: ${result.loadedKeyFingerprintHex}`);
    lines.push(`Embedded key fingerprint: ${result.embeddedKeyFingerprintHex}`);
    lines.push(`Loaded key verifies: ${result.loadedKeyValid}`);
    lines.push(`Embedded key verifies: ${result.embeddedKeyValid}`);
  }

  if (result.computedHashHex) lines.push(`Computed hash: ${result.computedHashHex}`);
  if (result.providedHashHex) lines.push(`Computed hash: ${result.providedHashHex}`);
  if (result.signedHashHex) lines.push(`Signed hash:   ${result.signedHashHex}`);

  if (result.code) lines.push(`Error code: ${result.code}`);
  if (result.warning) lines.push(`Warning: ${result.warning}`);

  return lines.join('\n');
}

function isMismatchButCryptographicallyValid(result) {
  return result.keyMismatch && (result.loadedKeyValid === true || result.embeddedKeyValid === true);
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

  const resultCard = byId('verify-result-card');
  const resultIcon = byId('verify-icon');
  const resultHeading = byId('verify-heading');
  const resultMessage = byId('verify-message');
  const resultDetails = byId('verify-details');

  function getInputMode() {
    return modeTextEl.checked ? 'text' : 'file';
  }

  function applyInputModeUi() {
    const mode = getInputMode();
    fileGroupEl.classList.toggle('hidden', mode !== 'file');
    textGroupEl.classList.toggle('hidden', mode !== 'text');
  }

  function timeoutForMode(mode) {
    const suiteId = state.keys.public?.suiteId;
    const slow = suiteId !== undefined ? isSlowSuite(suiteId) : true;
    if (mode === 'text') {
      return slow ? VERIFY_TIMEOUT_MS.TEXT_SLH_DSA : VERIFY_TIMEOUT_MS.TEXT_ML_DSA;
    }
    return slow ? VERIFY_TIMEOUT_MS.FILE_SLH_DSA : VERIFY_TIMEOUT_MS.FILE_ML_DSA;
  }

  function renderResultCard(result) {
    resultCard.classList.remove('hidden');
    resultDetails.textContent = renderVerifyResult(result);

    if (isMismatchButCryptographicallyValid(result)) {
      resultIcon.textContent = '⚠️';
      resultHeading.textContent = 'Key Mismatch Warning';
      resultHeading.style.color = 'var(--accent-warning)';
      resultMessage.textContent =
        'Signature is valid, but loaded and embedded keys differ. Confirm trusted key identity before accepting.';
      resultCard.style.borderLeftColor = 'var(--accent-warning)';
      showToast('warning', 'Key mismatch detected');
      return;
    }

    if (result.valid) {
      resultIcon.textContent = '✅';
      resultHeading.textContent = 'Signature Valid';
      resultHeading.style.color = 'var(--accent-success)';
      resultMessage.textContent =
        result.inputKind === 'text'
          ? 'The signature is valid and matches the provided plain text.'
          : 'The signature is valid and matches the selected file.';
      resultCard.style.borderLeftColor = 'var(--accent-success)';
      showToast('success', 'Verification successful');
      return;
    }

    resultIcon.textContent = '❌';
    resultHeading.textContent = 'Verification Failed';
    resultHeading.style.color = 'var(--accent-danger)';
    resultMessage.textContent = result.keyMismatch
      ? 'Verification failed for both loaded and embedded keys.'
      : `The signature is invalid. Error: ${result.code || 'Unknown'}`;
    resultCard.style.borderLeftColor = 'var(--accent-danger)';
    showToast('error', 'Verification failed');
  }

  verifyBtn.addEventListener('click', async () => {
    const mode = getInputMode();
    const file = fileInput.files?.[0] ?? null;
    const text = textInput.value ?? '';
    const sigFile = sigInput.files?.[0] ?? null;

    if (mode === 'file' && !file) {
      showToast('warning', 'Select a file to verify');
      return;
    }
    if (mode === 'text' && !text.length) {
      showToast('warning', 'Enter plain text to verify');
      return;
    }
    if (!sigFile) {
      showToast('warning', 'Select a signature file (.sig)');
      return;
    }

    resultCard.classList.add('hidden');
    verifyBtn.disabled = true;
    resetProgress(progressEl, progressLabelEl);
    showToast('info', 'Verifying...');

    try {
      const sigBytes = await readFileAsBytes(sigFile);
      const publicKeyFile = state.keys.public?.fileBytes || null;

      let result;
      if (mode === 'text') {
        result = await workerClient.call(
          'VERIFY_TEXT',
          { text, sigFile: sigBytes, publicKeyFile },
          { timeoutMs: timeoutForMode('text') }
        );
      } else {
        result = await workerClient.call(
          'VERIFY_FILE',
          { file, sigFile: sigBytes, publicKeyFile },
          {
            timeoutMs: timeoutForMode('file'),
            onProgress: (p) => setProgress(progressEl, progressLabelEl, p.loaded, p.total),
          }
        );
      }

      renderResultCard(result);
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      verifyBtn.disabled = false;
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

  applyInputModeUi();
}
