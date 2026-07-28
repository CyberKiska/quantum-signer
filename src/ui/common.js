import { bytesToHexLower } from '../formats/encoding.js';
import { assertFileSizeLimit } from '../crypto/policy.js';

export function byId(id) {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing element #${id}`);
  return node;
}

export function showToast(type, message) {
  window.dispatchEvent(new CustomEvent('toast', { detail: { type, message } }));
}

export function readFileAsBytes(file, { maxBytes, field = 'file' } = {}) {
  if (!file) return Promise.resolve(null);
  if (Number.isInteger(maxBytes)) {
    assertFileSizeLimit(file, maxBytes, field);
  }
  return file.arrayBuffer().then((buf) => new Uint8Array(buf));
}

export function formatBytes(size) {
  if (typeof size !== 'number' || Number.isNaN(size)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let n = size;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

export function safeFileName(name, fallback = 'download.bin') {
  const trimmed = (name || '').trim();
  if (!trimmed) return fallback;
  return trimmed.replace(/[^a-zA-Z0-9._-]+/g, '_');
}

const UNSAFE_REVIEW_CODE_POINT =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060\u2066-\u2069\ufeff]/gu;

export function safeReviewText(value, maxCodePoints = 512) {
  const text = String(value ?? '').replace(UNSAFE_REVIEW_CODE_POINT, (char) => {
    const hex = char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
    return `<U+${hex}>`;
  });
  const codePoints = Array.from(text);
  if (codePoints.length <= maxCodePoints) return text;
  return `${codePoints.slice(0, maxCodePoints).join('')}…`;
}

export function buildLegacyDisplayMetadataReviewGroup(
  { filename = null, filesize = null, createdAt = null } = {},
  reviewedInputLength = null
) {
  const rows = [];

  if (filename !== null && filename !== '') {
    rows.push({ label: 'Filename hint', value: filename });
  }
  if (filesize !== null) {
    const value = String(filesize);
    rows.push({ label: 'File size hint', value: `${value} bytes` });
    if (Number.isInteger(reviewedInputLength) && String(reviewedInputLength) !== value) {
      rows.push({
        label: 'Mismatch warning',
        value: 'The unsigned file size hint does not match the reviewed input.',
        tone: 'warning',
      });
    }
  }
  if (createdAt !== null && createdAt !== '') {
    rows.push({ label: 'Creation-time hint', value: createdAt });
  }

  if (rows.length === 0) return null;
  return {
    title: 'Legacy unsigned hints — not covered by the signature',
    tone: 'untrusted',
    note: 'For compatibility only. Never use these values to identify the signed input or signer.',
    rows,
  };
}

export function renderReviewGroups(container, groups) {
  if (!container || typeof container.replaceChildren !== 'function') {
    throw new TypeError('Review container must support replaceChildren().');
  }
  const doc = container.ownerDocument;
  if (!doc || typeof doc.createElement !== 'function' || typeof doc.createDocumentFragment !== 'function') {
    throw new TypeError('Review container must belong to a document.');
  }

  const fragment = doc.createDocumentFragment();
  for (const group of groups) {
    if (!group || !Array.isArray(group.rows) || group.rows.length === 0) continue;

    const section = doc.createElement('section');
    section.className = `review-group${group.tone ? ` ${group.tone}` : ''}`;

    const heading = doc.createElement('h4');
    heading.className = 'review-group-title';
    heading.textContent = safeReviewText(group.title, 160);
    section.append(heading);

    if (group.note) {
      const note = doc.createElement('p');
      note.className = 'review-group-note';
      note.textContent = safeReviewText(group.note, 512);
      section.append(note);
    }

    const fields = doc.createElement('dl');
    fields.className = 'review-fields';
    for (const row of group.rows) {
      const field = doc.createElement('div');
      field.className = `review-field${row.tone ? ` ${row.tone}` : ''}`;

      const label = doc.createElement('dt');
      label.textContent = safeReviewText(row.label, 160);
      const value = doc.createElement('dd');
      value.textContent = safeReviewText(row.value, row.maxCodePoints ?? 2048);

      field.append(label, value);
      fields.append(field);
    }
    section.append(fields);
    fragment.append(section);
  }

  container.replaceChildren(fragment);
}

export function downloadBytes(filename, bytes, mime = 'application/octet-stream') {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.hidden = true;
  document.body.append(link);
  try {
    link.click();
  } finally {
    link.remove();
  }
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export function setProgress(progressEl, labelEl, loaded, total) {
  if (!progressEl) return;
  progressEl.classList.remove('hidden');
  const percent = total > 0 ? Math.round((loaded / total) * 100) : 100;
  progressEl.value = percent;
  if (labelEl) {
    labelEl.textContent = total > 0 ? `${percent}% (${formatBytes(loaded)} / ${formatBytes(total)})` : `${percent}%`;
  }
}

export function resetProgress(progressEl, labelEl) {
  if (!progressEl) return;
  progressEl.classList.add('hidden');
  progressEl.value = 0;
  if (labelEl) labelEl.textContent = '';
}

export function getBasePath() {
  const meta = document.querySelector('meta[name="base-path"]');
  const value = meta?.content || '/';
  return value.endsWith('/') ? value : `${value}/`;
}

export function shortHex(bytesOrHex, prefix = 8, suffix = 8) {
  const hex = typeof bytesOrHex === 'string' ? bytesOrHex.toLowerCase() : bytesToHexLower(bytesOrHex);
  if (hex.length <= prefix + suffix) return hex;
  return `${hex.slice(0, prefix)}...${hex.slice(hex.length - suffix)}`;
}

export function workerFriendlyError(error) {
  if (!error) return 'An unknown error occurred.';
  if (typeof error === 'string') return error;
  if (error.message) return error.message;
  return 'An unknown error occurred.';
}

export function createWorkerClient(
  workerUrl,
  {
    workerFactory = (url) => new Worker(url, { type: 'module' }),
    setTimer = (callback, delay) => globalThis.setTimeout(callback, delay),
    clearTimer = (timer) => globalThis.clearTimeout(timer),
  } = {}
) {
  let worker = null;
  let destroyed = false;
  let seq = 0;
  const pending = new Map();
  const invalidationListeners = new Set();
  const defaultTimeoutMs = 60_000;

  function clearPendingTimer(entry) {
    if (entry?.timer !== undefined && entry?.timer !== null) clearTimer(entry.timer);
  }

  function notifySecretSessionInvalidated(event) {
    for (const listener of invalidationListeners) {
      try {
        listener(event);
      } catch (_err) {
        // One UI subscriber must not prevent other subscribers from clearing
        // capabilities after a worker reset or expired secret session.
      }
    }
  }

  function rejectAllPending(message) {
    for (const entry of pending.values()) {
      clearPendingTimer(entry);
      entry.reject(new Error(message));
    }
    pending.clear();
  }

  function handleWorkerMessage(boundWorker, event) {
    if (worker !== boundWorker || destroyed) return;
    const msg = event.data || {};
    if (msg.type === 'SECRET_SESSION_INVALIDATED') {
      notifySecretSessionInvalidated({
        reason: msg.reason || 'session-invalidated',
        sessionHandle: typeof msg.secretSessionHandle === 'string' ? msg.secretSessionHandle : null,
      });
      return;
    }

    const p = pending.get(msg.id);
    if (!p) return;

    if (msg.type === 'PROGRESS') {
      if (typeof p.onProgress === 'function') p.onProgress(msg);
      return;
    }

    if (msg.type === 'RESULT') {
      pending.delete(msg.id);
      clearPendingTimer(p);
      p.resolve(msg.result);
      return;
    }

    if (msg.type === 'ERROR') {
      pending.delete(msg.id);
      clearPendingTimer(p);
      const err = new Error(msg.message || 'Worker error');
      err.code = msg.code;
      if (msg.code === 'E_SESSION_MISSING' && p.secretSessionHandle) {
        notifySecretSessionInvalidated({
          reason: 'session-missing',
          sessionHandle: p.secretSessionHandle,
        });
      }
      p.reject(err);
    }
  }

  function attachWorker(nextWorker) {
    worker = nextWorker;
    nextWorker.onmessage = (event) => handleWorkerMessage(nextWorker, event);
    nextWorker.onerror = () => {
      if (worker === nextWorker) failWorker('Cryptographic worker failed');
    };
    nextWorker.onmessageerror = () => {
      if (worker === nextWorker) failWorker('Cryptographic worker returned an unreadable message');
    };
  }

  function startWorker() {
    if (destroyed) throw new Error('Cryptographic worker client was destroyed');
    const nextWorker = workerFactory(workerUrl);
    if (!nextWorker || typeof nextWorker.postMessage !== 'function' || typeof nextWorker.terminate !== 'function') {
      throw new Error('Cryptographic worker factory returned an invalid worker');
    }
    attachWorker(nextWorker);
    return nextWorker;
  }

  function failWorker(reason) {
    const previous = worker;
    worker = null;
    if (previous) previous.terminate();
    rejectAllPending(reason);
    // Do not immediately construct another worker from an asynchronous error
    // callback. A broken URL, MIME type, CSP, or module would otherwise create
    // an unbounded crash/restart loop. The next explicit call makes one retry.
    notifySecretSessionInvalidated({ reason: 'worker-failed', sessionHandle: null, restarted: false });
  }

  startWorker();

  function call(type, payload, options = {}) {
    const id = `${Date.now()}-${seq++}`;
    const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 0x7fffffff) {
      return Promise.reject(new RangeError('timeoutMs must be a finite positive number no greater than 2147483647'));
    }

    return new Promise((resolve, reject) => {
      if (destroyed) {
        reject(new Error('Cryptographic worker client was destroyed'));
        return;
      }
      if (!worker) {
        try {
          startWorker();
        } catch (err) {
          reject(err);
          return;
        }
      }

      const timer = setTimer(() => {
        const p = pending.get(id);
        if (p) {
          pending.delete(id);
          reject(
            new Error(
              `Operation timed out after ${timeoutMs}ms. The worker was left running to preserve any in-memory private key; wait for it to become responsive before retrying.`
            )
          );
        }
      }, timeoutMs);

      pending.set(id, {
        resolve,
        reject,
        timer,
        onProgress: options.onProgress,
        secretSessionHandle:
          typeof payload?.secretSessionHandle === 'string' ? payload.secretSessionHandle : null,
      });

      try {
        worker.postMessage({ id, type, payload });
      } catch (err) {
        pending.delete(id);
        clearPendingTimer({ timer });
        reject(err);
      }
    });
  }

  function onSecretSessionInvalidated(listener) {
    if (typeof listener !== 'function') throw new TypeError('listener must be a function');
    invalidationListeners.add(listener);
    return () => invalidationListeners.delete(listener);
  }

  function destroy() {
    if (destroyed) return;
    destroyed = true;
    rejectAllPending('Cryptographic worker was terminated');
    if (worker) worker.terminate();
    worker = null;
    invalidationListeners.clear();
  }

  return { call, destroy, onSecretSessionInvalidated };
}
