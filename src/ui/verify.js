import { getSuiteName } from '../formats/containers.js';
import { MAX_SIGNATURE_FILE_BYTES } from '../crypto/policy.js';
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

  const resultCard = byId('verify-result-card');
  const resultIcon = byId('verify-icon');
  const resultHeading = byId('verify-heading');
  const resultBadge = byId('verify-result-badge');
  const resultMessage = byId('verify-message');
  const resultDetails = byId('verify-details');

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

    if (result.keyMismatch) {
      const loadedValid = result.loadedKeyValid === true;
      const embeddedValid = result.embeddedKeyValid === true;

      setResultTone('warning', 'WARNING');
      resultIcon.textContent = '⚠️';
      if (loadedValid && embeddedValid) {
        resultHeading.textContent = 'Key Mismatch Warning';
        resultMessage.textContent =
          'Both loaded and embedded keys verify this signature, but they are different keys. Confirm trusted key identity before accepting.';
        showToast('warning', 'Key mismatch detected');
        return;
      }

      if (result.valid) {
        resultHeading.textContent = 'Signature Valid (Loaded Key)';
        resultMessage.textContent =
          'Signature is valid with the loaded public key. Embedded key in .qsig differs and failed verification.';
        showToast('warning', 'Key mismatch detected');
        return;
      }

      setResultTone('invalid', 'INVALID');
      resultIcon.textContent = '❌';
      resultHeading.textContent = 'Verification Failed (Key Mismatch)';
      resultMessage.textContent = embeddedValid
        ? 'Loaded public key failed verification. Embedded key verifies, but this state is treated as invalid until key identity is trusted.'
        : 'Verification failed for both loaded and embedded keys.';
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
    resultMessage.textContent = result.keyMismatch
      ? 'Verification failed for both loaded and embedded keys.'
      : `The signature is invalid. Error: ${result.code || 'Unknown'}`;
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
      showToast('warning', 'Select a signature file (.qsig)');
      return;
    }

    resultCard.classList.add('hidden');
    verifyBtn.disabled = true;
    resetProgress(progressEl, progressLabelEl);
    showToast('info', 'Verifying...');

    try {
      const sigBytes = await readFileAsBytes(sigFile, { maxBytes: MAX_SIGNATURE_FILE_BYTES, field: 'sigFile' });
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
