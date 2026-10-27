import { initI18n, t } from '../i18n';
import { initTheme } from '../theme';

void Promise.all([initI18n(), initTheme()]);

/**
 * Fenko Vault In-Page Notices
 *
 * Toast notifications for passkey operations, injected into web pages via
 * the content script. They are page DOM, so they never carry vault data:
 * the passkey picker and the create confirmation are the vault's own
 * dialog page (src/ui/vault-dialog.ts).
 */

// Styles for the UI components (will be injected into the page)
const UI_STYLES = `

  @keyframes pkv-toastIn {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }

  @keyframes pkv-toastOut {
    from { opacity: 1; transform: translateX(0); }
    to { opacity: 0; transform: translateX(20px); }
  }

  /* Toast Notification */
  .pkv-toast {
    position: fixed;
    top: 20%;
    right: 20px;
    background: #000000;
    color: #ffffff;
    padding: 14px 20px;
    border-radius: 0;
    border: 3px solid #FCD34D;
    z-index: 2147483647;
    display: flex;
    align-items: center;
    gap: 12px;
    font-family: 'Courier New', Courier, monospace;
    font-size: 14px;
    animation: pkv-toastIn 0.15s ease-out;
    max-width: 360px;
  }

  .pkv-toast.pkv-toast-out {
    animation: pkv-toastOut 0.15s ease-in forwards;
  }

  .pkv-toast-icon {
    font-size: 20px;
    flex-shrink: 0;
  }

  .pkv-toast-content {
    flex: 1;
  }

  .pkv-toast-title {
    font-weight: 700;
    margin-bottom: 2px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .pkv-toast-message {
    font-size: 13px;
    opacity: 0.9;
  }

  .pkv-toast-success {
    background: #000000;
    border-color: #10b981;
    color: #10b981;
  }

  .pkv-toast-error {
    background: #000000;
    border-color: #ef4444;
    color: #ef4444;
  }

  .pkv-toast-info {
    background: #000000;
    border-color: #FCD34D;
    color: #FCD34D;
  }

  .pkv-toast {
    border-radius: 14px;
  }

  .pkv-toast {
    background: #0D1117;
    border-color: #D4920A;
    color: #F5A623;
    box-shadow: 0 18px 48px rgba(13, 17, 23, 0.18);
  }

  .pkv-toast-success {
    background: #DAFBE1;
    border-color: rgba(26, 127, 55, 0.28);
    color: #1A7F37;
  }

  .pkv-toast-error {
    background: #FFEBE9;
    border-color: rgba(207, 34, 46, 0.28);
    color: #CF222E;
  }

  html[data-theme='dark'] .pkv-toast {
    background: #161B22;
    border-color: #30363D;
    color: #E6EDF3;
  }
`;

/**
 * Inject styles into the page
 */
function injectStyles(): void {
  if (document.getElementById('pkv-styles')) return;

  const style = document.createElement('style');
  style.id = 'pkv-styles';
  style.textContent = UI_STYLES;
  document.head.appendChild(style);
}

/**
 * Show a toast notification
 */
function showToast(
  title: string,
  message: string,
  type: 'success' | 'error' | 'info' = 'info',
  duration: number = 4000
): void {
  injectStyles();

  // Remove any existing toast
  const existingToast = document.querySelector('.pkv-toast');
  if (existingToast) {
    existingToast.remove();
  }

  const icons = {
    success: '&#10003;',
    error: '&#10007;',
    info: '&#128274;',
  };

  const toast = document.createElement('div');
  toast.className = `pkv-toast pkv-toast-${type}`;
  toast.innerHTML = `
    <div class="pkv-toast-icon">${icons[type]}</div>
    <div class="pkv-toast-content">
      <div class="pkv-toast-title">${escapeHtml(title)}</div>
      <div class="pkv-toast-message">${escapeHtml(message)}</div>
    </div>
  `;

  document.body.appendChild(toast);

  // Auto-remove after duration
  setTimeout(() => {
    toast.classList.add('pkv-toast-out');
    setTimeout(() => toast.remove(), 200);
  }, duration);
}

/**
 * Show passkey creation success notification
 */
function showPasskeyCreatedNotification(userName: string, rpId: string): void {
  showToast(
    t('pagePasskeyCreated'),
    t('pagePasskeyCreatedMsg', { user: userName, rp: rpId }),
    'success',
    4000
  );
}

/**
 * Show passkey used notification. It names the site, not the account: the
 * toast is in the page's DOM, where the page can read it.
 */
function showPasskeyUsedNotification(rpId: string): void {
  showToast(t('pageSignedIn'), t('pageSignedInSiteMsg', { rp: rpId }), 'success', 3000);
}

function showErrorNotification(title: string, message: string): void {
  showToast(title, message, 'error', 5000);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(str: string): string {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  // textContent->innerHTML does not encode quotes; escape them so values placed
  // inside quoted HTML attributes cannot break out of the attribute context.
  return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const w = window as unknown as Record<string, unknown>;
w.showPasskeyCreatedNotification = showPasskeyCreatedNotification;
w.showPasskeyUsedNotification = showPasskeyUsedNotification;
w.showErrorNotification = showErrorNotification;
