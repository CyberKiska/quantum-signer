import { byId } from './common.js';
import { getSuiteName } from '../formats/containers.js';

export function setupLayout(state) {
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.tab-panel');
  const pubKeyFpEl = byId('ctx-pub-fp');
  const secKeyFpEl = byId('ctx-sec-fp');
  const statusDot = byId('sys-status-dot');
  const statusText = byId('sys-status-text');

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      const target = item.dataset.tab;

      navItems.forEach((n) => n.classList.toggle('active', n === item));

      panels.forEach((panel) => {
        panel.classList.toggle('active', panel.id === `tab-${target}`);
      });
    });
  });

  function updateSecurityContext() {
    const pub = state.keys.public;
    const sec = state.keys.secret;

    if (pub) {
      pubKeyFpEl.textContent = `${getSuiteName(pub.suiteId)} / ${pub.fingerprintShort}...`;
      pubKeyFpEl.style.color = 'var(--accent-success)';
      pubKeyFpEl.title = `SHA3-256: ${pub.fingerprintHex}`;
    } else {
      pubKeyFpEl.textContent = 'Not Loaded';
      pubKeyFpEl.style.color = 'var(--text-muted)';
      pubKeyFpEl.title = '';
    }

    if (sec) {
      secKeyFpEl.textContent = `${getSuiteName(sec.suiteId)} / ${sec.fingerprintShort}...`;
      secKeyFpEl.style.color = 'var(--accent-warning)';
      secKeyFpEl.title = 'Secret key loaded in memory';
    } else {
      secKeyFpEl.textContent = 'Not Loaded';
      secKeyFpEl.style.color = 'var(--text-muted)';
      secKeyFpEl.title = '';
    }

    if (sec) {
      statusDot.className = 'status-indicator warning';
      statusText.textContent = 'Armed';
    } else if (pub) {
      statusDot.className = 'status-indicator secure';
      statusText.textContent = 'Verify-Ready';
    } else {
      statusDot.className = 'status-indicator';
      statusText.textContent = 'Ready';
    }
  }

  const toastContainer = byId('toast-container');
  window.addEventListener('toast', (e) => {
    const { type, message } = e.detail;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(20px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  });

  window.addEventListener('keys:updated', updateSecurityContext);
  updateSecurityContext();
}
