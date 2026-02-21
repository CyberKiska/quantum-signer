import { DEFAULT_SUITE_ID, listSuites } from './crypto/algorithms.js';
import { wipeBytes } from './crypto/bytes.js';
import { byId, createWorkerClient, getBasePath, showToast, workerFriendlyError } from './ui/common.js';
import { setupLayout } from './ui/layout.js';
import { setupKeysTab } from './ui/keys.js';
import { setupSignTab } from './ui/sign.js';
import { setupVerifyTab } from './ui/verify.js';

const state = {
  locale: 'en',
  keys: {
    public: null,
    secret: null,
  },
  sign: {
    lastSignature: null,
  },
};

function wipeStateBytes(appState) {
  const pub = appState.keys.public;
  const sec = appState.keys.secret;
  if (pub?.keyBytes) wipeBytes(pub.keyBytes);
  if (pub?.fileBytes) wipeBytes(pub.fileBytes);
  if (sec?.keyBytes) wipeBytes(sec.keyBytes);
  if (sec?.fileBytes) wipeBytes(sec.fileBytes);
  if (appState.sign.lastSignature?.bytes) wipeBytes(appState.sign.lastSignature.bytes);
}

async function main() {
  const basePath = getBasePath();
  const workerUrl = `${basePath}assets/worker.js`;
  const workerClient = createWorkerClient(workerUrl);

  const suites = listSuites();

  setupLayout(state);
  setupKeysTab(state, workerClient, suites, DEFAULT_SUITE_ID);
  setupSignTab(state, workerClient);
  setupVerifyTab(state, workerClient);

  const selfTestBtn = byId('run-selftest');

  selfTestBtn.addEventListener('click', async () => {
    try {
      selfTestBtn.disabled = true;
      showToast('info', 'Running self-test...');

      const report = await workerClient.call(
        'SELFTEST',
        { full: false },
        {
          timeoutMs: 600_000,
        }
      );

      if (report.ok) {
        showToast('success', `Self-test passed (${report.passed}/${report.total}).`);
      } else {
        showToast('error', `Self-test failed (${report.failed}/${report.total}).`);
      }
    } catch (err) {
      showToast('error', workerFriendlyError(err));
    } finally {
      selfTestBtn.disabled = false;
    }
  });

  window.addEventListener('beforeunload', () => {
    wipeStateBytes(state);
    workerClient.destroy();
  });
}

main().catch((err) => {
  showToast('error', workerFriendlyError(err));
});
