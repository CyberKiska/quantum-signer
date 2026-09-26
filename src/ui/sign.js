import { equalsHex, wipeBytes } from '../crypto/bytes.js';
import { computeFingerprintHex } from '../crypto/fingerprint.js';
import { bytesToHexLower } from '../formats/encoding.js';
import { HashAlgId, QSIG_V2_CONTEXT, getHashName, getSuiteName, unpackSignatureV2 } from '../formats/containers.js';
import { createOperationGate } from '../core/operation-gate.js';
import { describeDeceptiveText } from './verify.js';
import {
  byId, downloadBytes, formatBytes, renderReviewGroups, resetProgress, safeReviewText, setProgress, showToast,
  workerFriendlyError,
} from './common.js';

// JavaScript SLH-DSA signing takes seconds per signature.
const SIGN_TIMEOUT_MS = Object.freeze({ ML_DSA: 300_000, SLH_DSA: 600_000 });
const PREVIEW_TIMEOUT_MS = Object.freeze({ FILE: 300_000, TEXT: 60_000 });
const TEXT_PREVIEW_DEBOUNCE_MS = 180;
const IDLE = Object.freeze({ status: 'idle', hashHex: null, inputLength: null, error: null });

function setBadge(badgeEl, tone, text) {
  badgeEl.className = `badge ${tone || 'neutral'}`;
  badgeEl.textContent = text;
}

export function setupSignTab(state, workerClient) {
  const modeFileEl = byId('sign-mode-file');
  const modeTextEl = byId('sign-mode-text');
  const fileGroupEl = byId('sign-file-group');
  const textGroupEl = byId('sign-text-group');
  const fileInput = byId('sign-file');
  const textInput = byId('sign-text');
  const executeBtn = byId('sign-execute');
  const downloadBtn = byId('sign-download');
  const reviewBadgeEl = byId('sign-review-badge');
  const reviewEl = byId('sign-review');
  const progressEl = byId('sign-progress');
  const progressLabelEl = byId('sign-progress-label');
  const resultEl = byId('sign-result');

  const signGate = createOperationGate();
  let previewSeq = 0;
  let previewTimer = null;
  let preview = IDLE;
  let lastSignature = null;

  const getInput = () => ({
    mode: modeTextEl.checked ? 'text' : 'file',
    file: fileInput.files?.[0] ?? null,
    text: textInput.value ?? '',
  });
  const hasInput = (input) => (input.mode === 'file' ? Boolean(input.file) : input.text.length > 0);

  function clearSignature() {
    wipeBytes(lastSignature?.bytes);
    lastSignature = null;
    downloadBtn.disabled = true;
    resultEl.textContent = 'No signature created yet.';
  }

  function render() {
    const input = getInput();
    const key = state.keys.secret;
    const digest = { ready: preview.hashHex, loading: 'Computing...', error: `Unavailable (${preview.error})` }[preview.status]
      ?? 'Waiting for input';
    const inputText = input.mode === 'file'
      ? (input.file ? `File: ${safeReviewText(input.file.name)} (${formatBytes(preview.inputLength ?? input.file.size)})` : 'Waiting for file')
      : (input.text.length ? `Plain text: ${input.text.length} characters${Number.isInteger(preview.inputLength) ? ` / ${formatBytes(preview.inputLength)}` : ''}` : 'Waiting for text');
    const deceptive = input.mode === 'text' ? describeDeceptiveText(input.text, 'signed') : null;
    renderReviewGroups(reviewEl, [
      {
        title: 'Reviewed input',
        rows: [
          { label: 'Input', value: inputText },
          { label: `Payload digest (${getHashName(HashAlgId.SHA3_512)})`, value: digest },
          ...(deceptive ? [{ label: 'Warning', value: deceptive, tone: 'warning' }] : []),
          ...(input.mode === 'text' ? [{ label: 'Note', value: 'Browsers submit line breaks as LF. Use File mode to sign an existing file byte-for-byte.' }] : []),
        ],
      },
      {
        title: 'Signing key',
        rows: key
          ? [{ label: 'Signer', value: `${getSuiteName(key.suiteId)} / ${key.fingerprintHex}` },
            { label: 'Context', value: QSIG_V2_CONTEXT }]
          : [{ label: 'Signer', value: 'Generate or unlock a signing key in the Keys tab', tone: 'warning' }],
      },
    ]);
    if (preview.status === 'error') setBadge(reviewBadgeEl, 'invalid', 'ERROR');
    else if (preview.status === 'loading') setBadge(reviewBadgeEl, 'neutral', 'HASHING');
    else if (preview.status === 'ready') setBadge(reviewBadgeEl, key ? 'valid' : 'warning', key ? 'READY' : 'NO KEY');
    else setBadge(reviewBadgeEl, 'neutral', hasInput(input) ? 'REVIEW' : 'WAITING');
    executeBtn.disabled = signGate.busy || state.keys.transitioning || !key || preview.status !== 'ready';
  }

  function setPreview(next) {
    preview = next;
    render();
  }

  async function refreshPreview() {
    const input = getInput();
    if (!hasInput(input)) return setPreview(IDLE);
    const token = ++previewSeq;
    const inputLength = input.mode === 'file' ? input.file.size : null;
    try {
      const result = input.mode === 'file'
        ? await workerClient.call('HASH_FILE', { file: input.file }, {
          timeoutMs: PREVIEW_TIMEOUT_MS.FILE,
          onProgress: (p) => { if (token === previewSeq) setProgress(progressEl, progressLabelEl, p.loaded, p.total); },
        })
        : await workerClient.call('HASH_TEXT', { text: input.text }, { timeoutMs: PREVIEW_TIMEOUT_MS.TEXT });
      if (token === previewSeq) setPreview({ status: 'ready', hashHex: result.hashHex, inputLength: result.inputLength, error: null });
    } catch (err) {
      if (token === previewSeq) setPreview({ status: 'error', hashHex: null, inputLength, error: workerFriendlyError(err) });
    } finally {
      if (token === previewSeq) resetProgress(progressEl, progressLabelEl);
    }
  }

  // Any input change invalidates the review, an in-flight signature and the last output.
  function inputChanged({ debounce = false } = {}) {
    previewSeq++;
    clearTimeout(previewTimer);
    resetProgress(progressEl, progressLabelEl);
    signGate.invalidate();
    clearSignature();
    const input = getInput();
    fileGroupEl.classList.toggle('hidden', input.mode !== 'file');
    textGroupEl.classList.toggle('hidden', input.mode !== 'text');
    if (!hasInput(input)) return setPreview(IDLE);
    setPreview({ status: 'loading', hashHex: null, inputLength: input.mode === 'file' ? input.file.size : null, error: null });
    if (debounce && input.mode === 'text') previewTimer = setTimeout(refreshPreview, TEXT_PREVIEW_DEBOUNCE_MS);
    else void refreshPreview();
  }

  executeBtn.addEventListener('click', async () => {
    const input = getInput();
    const key = state.keys.secret;
    if (!key || preview.status !== 'ready' || signGate.busy || state.keys.transitioning) return;
    const reviewed = { hashHex: preview.hashHex, inputLength: preview.inputLength, suiteId: key.suiteId, fingerprintHex: key.fingerprintHex };
    const token = signGate.begin();
    render();
    let signatureFile;
    try {
      const slow = getSuiteName(reviewed.suiteId).startsWith('SLH-DSA');
      showToast('info', slow ? 'Signing with SLH-DSA; this can take a minute...' : 'Signing...');
      const payload = { expectedDigestHex: reviewed.hashHex, expectedFingerprintHex: reviewed.fingerprintHex };
      if (input.mode === 'file') payload.file = input.file;
      else payload.text = input.text;
      const result = await workerClient.call('SIGN', payload, {
        timeoutMs: slow ? SIGN_TIMEOUT_MS.SLH_DSA : SIGN_TIMEOUT_MS.ML_DSA,
        onProgress: (p) => { if (signGate.isCurrent(token)) setProgress(progressEl, progressLabelEl, p.loaded, p.total); },
      });
      signatureFile = result.signatureFile;
      if (!signGate.isCurrent(token)) return;
      // Independently parse the container and bind it to what was reviewed.
      const parsed = unpackSignatureV2(signatureFile);
      if (!equalsHex(bytesToHexLower(parsed.payloadDigest), reviewed.hashHex) || parsed.suiteId !== reviewed.suiteId ||
          result.inputLength !== reviewed.inputLength ||
          !equalsHex(computeFingerprintHex(parsed.metadata.signerPublicKey), reviewed.fingerprintHex)) {
        throw new Error('Signature does not match the reviewed input or signer; it was discarded.');
      }
      lastSignature = { bytes: signatureFile, filename: input.mode === 'file' ? `${input.file.name}.qsig` : 'plain-text.qsig' };
      signatureFile = null;
      resultEl.textContent = [
        `Algorithm: ${getSuiteName(reviewed.suiteId)}`,
        `Input: ${input.mode} (${formatBytes(reviewed.inputLength)})`,
        `Payload digest (SHA3-512): ${reviewed.hashHex}`,
        `Signer fingerprint (SHA3-256): ${reviewed.fingerprintHex}`,
        `Signature file: ${formatBytes(lastSignature.bytes.length)}, verified before release`,
      ].join('\n');
      downloadBtn.disabled = false;
      window.dispatchEvent(new Event('signing-key:used'));
      showToast('success', 'Signature created. Save the .qsig file.');
    } catch (err) {
      if (signGate.isCurrent(token)) showToast('error', workerFriendlyError(err));
    } finally {
      wipeBytes(signatureFile);
      signGate.finish(token);
      resetProgress(progressEl, progressLabelEl);
      render();
    }
  });

  modeFileEl.addEventListener('change', () => inputChanged());
  modeTextEl.addEventListener('change', () => inputChanged());
  fileInput.addEventListener('change', () => inputChanged());
  textInput.addEventListener('input', () => inputChanged({ debounce: true }));

  byId('sign-text-paste').addEventListener('click', async () => {
    try {
      textInput.value = await navigator.clipboard.readText();
      modeTextEl.checked = true;
      inputChanged();
    } catch {
      showToast('error', 'Cannot read the clipboard. Paste manually with Ctrl/Cmd+V.');
    }
  });

  downloadBtn.addEventListener('click', () => {
    if (lastSignature) downloadBytes(lastSignature.filename, lastSignature.bytes);
  });

  byId('sign-reset').addEventListener('click', () => {
    modeFileEl.checked = true;
    fileInput.value = '';
    textInput.value = '';
    inputChanged();
  });

  // The worker and the parsed result bind every signature to the reviewed key;
  // a finished .qsig stays valid after the key is locked.
  window.addEventListener('keys:updated', render);

  inputChanged();
}
