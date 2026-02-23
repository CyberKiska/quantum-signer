/*
    Quantum Signer
    Copyright (C) 2026 CyberKiska

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

import { DEFAULT_SUITE_ID, listSuites } from './crypto/algorithms.js';
import { wipeBytes } from './crypto/bytes.js';
import { byId, createWorkerClient, getBasePath, showToast, workerFriendlyError } from './ui/common.js';
import { setupLayout } from './ui/layout.js';
import { setupKeysTab } from './ui/keys.js';
import { setupSignTab } from './ui/sign.js';
import { setupVerifyTab } from './ui/verify.js';

const state = {
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

  const selfTestBtn = byId('sidebar-selftest');

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
