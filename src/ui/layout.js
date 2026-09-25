import { byId } from './common.js';
import { getSuiteName } from '../formats/containers.js';

export function setupLayout(state) {
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.tab-panel');
  const pubKeyFpEl = byId('ctx-pub-fp');

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
    if (pub) {
      pubKeyFpEl.textContent = `${getSuiteName(pub.suiteId)} / ${pub.fingerprintShort}...`;
      pubKeyFpEl.title = `SHA3-256: ${pub.fingerprintHex}`;
      setContextTone(pubKeyFpEl, 'success');
    } else {
      pubKeyFpEl.textContent = 'Not Loaded';
      pubKeyFpEl.title = '';
      setContextTone(pubKeyFpEl, 'muted');
    }
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
