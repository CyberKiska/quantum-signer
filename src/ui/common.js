import { bytesToHexLower } from '../formats/encoding.js';

export function byId(id) {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing element #${id}`);
  return node;
}

export function showToast(type, message) {
  window.dispatchEvent(new CustomEvent('toast', { detail: { type, message } }));
}

export function readFileAsBytes(file) {
  if (!file) return Promise.resolve(null);
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

export function downloadBytes(filename, bytes, mime = 'application/octet-stream') {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 100);
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

export function createWorkerClient(workerUrl) {
  const worker = new Worker(workerUrl, { type: 'module' });
  let seq = 0;
  const pending = new Map();
  const defaultTimeoutMs = 60_000;

  function clearPendingTimer(entry) {
    if (entry?.timer) clearTimeout(entry.timer);
  }

  worker.onmessage = (event) => {
    const msg = event.data || {};
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
      p.reject(err);
    }
  };

  function call(type, payload, options = {}) {
    const id = `${Date.now()}-${seq++}`;
    const timeoutMs = options.timeoutMs || defaultTimeoutMs;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const p = pending.get(id);
        if (p) {
          pending.delete(id);
          reject(new Error(`Operation timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);

      pending.set(id, {
        resolve,
        reject,
        timer,
        onProgress: options.onProgress,
      });

      worker.postMessage({ id, type, payload });
    });
  }

  function destroy() {
    worker.terminate();
  }

  return { call, destroy };
}
