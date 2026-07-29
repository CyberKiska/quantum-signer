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

const deploymentAllowsPrivateKeys =
  document.querySelector('meta[name="private-key-operations"]')?.content === 'enabled';

const state = {
  deliveryIsolated: globalThis.crossOriginIsolated === true,
  privateKeyOperationsAllowed:
    deploymentAllowsPrivateKeys && globalThis.crossOriginIsolated === true,
  keys: {
    public: null,
    secret: null,
    transitioning: false,
  },
  sign: {
    lastSignature: null,
  },
};

function wipeStateBytes(appState) {
  const pub = appState.keys.public;
  if (pub?.keyBytes) wipeBytes(pub.keyBytes);
  if (pub?.fileBytes) wipeBytes(pub.fileBytes);
  if (appState.sign.lastSignature?.bytes) wipeBytes(appState.sign.lastSignature.bytes);
  appState.keys.public = null;
  appState.keys.secret = null;
  appState.sign.lastSignature = null;
}

function enforceTopLevelBrowsingContext() {
  if (window.top === window.self) return;
  throw new Error('Embedded execution is not allowed');
}

function enforceSecureContext() {
  // Browsers classify HTTPS, localhost, and trustworthy local file contexts.
  // Rely on that platform decision instead of maintaining a URL allowlist.
  if (globalThis.isSecureContext === true) return;
  throw new Error('Quantum Signer requires a secure browser context. Open it over HTTPS or from a browser-trusted local context.');
}

function renderFatalStartupError(message) {
  document.body.replaceChildren();
  const container = document.createElement('main');
  container.setAttribute('role', 'alert');
  container.className = 'main-content';
  const heading = document.createElement('h1');
  heading.textContent = 'Quantum Signer cannot start';
  const detail = document.createElement('p');
  detail.textContent = message;
  container.append(heading, detail);
  document.body.append(container);
}

async function main() {
  enforceTopLevelBrowsingContext();
  enforceSecureContext();
  const basePath = getBasePath();
  const workerUrl = `${basePath}assets/worker.js`;
  const workerClient = createWorkerClient(workerUrl);

  const suites = listSuites();

  setupLayout(state);
  setupKeysTab(state, workerClient, suites, DEFAULT_SUITE_ID);
  setupSignTab(state, workerClient);
  setupVerifyTab(state, workerClient);

  const deliveryWarning = byId('delivery-warning');
  deliveryWarning.classList.toggle('hidden', state.privateKeyOperationsAllowed);
  if (!state.privateKeyOperationsAllowed) {
    showToast(
      'warning',
      deploymentAllowsPrivateKeys
        ? 'Expected isolation headers are missing. Private-key operations are disabled.'
        : 'This public demo is verification-only. Private-key operations are disabled.'
    );
  }

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

  let tornDown = false;
  const teardown = () => {
    if (tornDown) return;
    tornDown = true;
    wipeStateBytes(state);
    workerClient.destroy();
  };
  window.addEventListener('pagehide', teardown, { once: true });
  window.addEventListener('beforeunload', teardown, { once: true });
  window.addEventListener('pageshow', (event) => {
    // A page placed into the back/forward cache has already destroyed its
    // key-holding worker. Reload instead of restoring stale session handles.
    if (event.persisted) window.location.reload();
  });
}

main().catch((err) => {
  renderFatalStartupError(workerFriendlyError(err));
});
