import { byId } from './common.js';
import { getSuiteName } from '../formats/containers.js';

export function setupLayout(state) {
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.tab-panel');
  const pubKeyFpEl = byId('ctx-pub-fp');
  const secKeyFpEl = byId('ctx-sec-fp');
  const statusDot = byId('sys-status-dot');
  const statusText = byId('sys-status-text');

  function activateTab(tabName) {
    navItems.forEach((item) => item.classList.toggle('active', item.dataset.tab === tabName));
    panels.forEach((panel) => panel.classList.toggle('active', panel.id === `tab-${tabName}`));
  }

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      activateTab(item.dataset.tab);
    });
  });

  function setContextTone(el, tone) {
    el.classList.remove('status-success', 'status-warning', 'status-muted');
    el.classList.add(`status-${tone}`);
  }

  function updateSecurityContext() {
    const pub = state.keys.public;
    const sec = state.keys.secret;

    if (pub) {
      pubKeyFpEl.textContent = `${getSuiteName(pub.suiteId)} / ${pub.fingerprintShort}...`;
      pubKeyFpEl.title = `SHA3-256: ${pub.fingerprintHex}`;
      setContextTone(pubKeyFpEl, 'success');
    } else {
      pubKeyFpEl.textContent = 'Not Loaded';
      pubKeyFpEl.title = '';
      setContextTone(pubKeyFpEl, 'muted');
    }

    if (sec) {
      secKeyFpEl.textContent = `${getSuiteName(sec.suiteId)} / ${sec.fingerprintShort}...`;
      secKeyFpEl.title = 'Secret key loaded in memory';
      setContextTone(secKeyFpEl, 'warning');
    } else {
      secKeyFpEl.textContent = 'Not Loaded';
      secKeyFpEl.title = '';
      setContextTone(secKeyFpEl, 'muted');
    }

    if (sec) {
      statusDot.className = 'status-indicator warning';
      statusText.textContent = 'Armed';
      return;
    }

    if (pub) {
      statusDot.className = 'status-indicator secure';
      statusText.textContent = 'Verify-Ready';
      return;
    }

    statusDot.className = 'status-indicator';
    statusText.textContent = 'Ready';
  }

  const toastContainer = byId('toast-container');
  window.addEventListener('toast', (event) => {
    const { type, message } = event.detail;
    const toast = document.createElement('div');
    toast.className = `toast ${type || 'info'}`;
    toast.textContent = message;

    toastContainer.append(toast);

    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 220);
    }, 3500);
  });

  window.addEventListener('keys:updated', updateSecurityContext);
  updateSecurityContext();

  return {
    activateTab,
    updateSecurityContext,
  };
}
