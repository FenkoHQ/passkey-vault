import { initI18n, t } from '../i18n';
import { initTheme } from '../theme';

void Promise.all([initI18n(), initTheme()]);

/**
 * Passkey Vault In-Page UI Components
 *
 * Provides toast notifications and modal dialogs for passkey operations.
 * These are injected into web pages via the content script.
 */

// Styles for the UI components (will be injected into the page)
const UI_STYLES = `
  /* Notification card container - upper right, 20% from top */
  .pkv-notification-container {
    position: fixed;
    top: 20%;
    right: 20px;
    z-index: 2147483647;
    font-family: 'Courier New', Courier, monospace;
    animation: pkv-slideInRight 0.15s ease-out;
  }

  @keyframes pkv-slideInRight {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }

  @keyframes pkv-slideOutRight {
    from { opacity: 1; transform: translateX(0); }
    to { opacity: 0; transform: translateX(20px); }
  }

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

  /* Card (non-modal dialog) */
  .pkv-card {
    background: #ffffff;
    border-radius: 0;
    border: 3px solid #000000;
    width: min(340px, calc(100vw - 40px));
    max-height: 70vh;
    overflow: hidden;
    font-family: 'Courier New', Courier, monospace;
  }

  .pkv-card-header {
    background: #ffffff;
    color: #000000;
    padding: 12px 16px;
    border-bottom: 2px solid #e0e0e0;
  }

  .pkv-card-title {
    font-size: 15px;
    font-weight: 700;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0;
    color: #000000;
  }

  .pkv-card-subtitle {
    font-size: 11px;
    opacity: 0.85;
    margin-top: 0;
  }

  .pkv-card-body {
    padding: 10px;
    max-height: 280px;
    overflow-y: auto;
    background: #ffffff;
  }

  .pkv-card-footer {
    padding: 10px 16px;
    border-top: 2px solid #000000;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
    background: #f5f5f5;
  }

  /* Passkey List */
  .pkv-passkey-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .pkv-passkey-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px;
    background: #ffffff;
    border: 2px solid #000000;
    border-radius: 0;
    cursor: pointer;
    transition: all 0.1s ease;
  }

  .pkv-passkey-item:hover {
    background: #f5f5f5;
  }

  .pkv-passkey-item.pkv-selected {
    background: #FCD34D;
    border-color: #000000;
  }

  .pkv-passkey-avatar {
    width: 28px;
    height: 28px;
    border-radius: 0;
    background: #000000;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .pkv-passkey-info {
    flex: 1;
    min-width: 0;
  }

  .pkv-passkey-name {
    font-weight: 700;
    font-size: 13px;
    color: #000000;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    text-transform: uppercase;
  }

  .pkv-passkey-detail {
    font-size: 11px;
    color: #333333;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .pkv-passkey-check {
    width: 20px;
    height: 20px;
    border-radius: 0;
    border: 3px solid #000000;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: all 0.1s ease;
    background: #ffffff;
  }

  .pkv-passkey-item.pkv-selected .pkv-passkey-check {
    background: #000000;
    border-color: #000000;
  }

  .pkv-passkey-check-icon {
    display: none;
    color: #FCD34D;
    font-size: 10px;
    font-weight: 700;
  }

  .pkv-passkey-item.pkv-selected .pkv-passkey-check-icon {
    display: block;
  }

  /* Buttons */
  .pkv-btn {
    flex: 1;
    min-width: 0;
    padding: 10px 16px;
    border: 3px solid #000000;
    border-radius: 0;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.1s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    line-height: 1.2;
    text-align: center;
    text-transform: uppercase;
    font-family: 'Courier New', Courier, monospace;
  }

  .pkv-card-footer .pkv-btn-primary {
    grid-column: 1 / -1;
  }

  .pkv-btn-primary {
    background: #FCD34D;
    color: #000000;
    border-color: #000000;
  }

  .pkv-btn-primary:hover {
    background: #000000;
    color: #FCD34D;
  }

  .pkv-btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    background: #cccccc;
    color: #666666;
  }

  .pkv-btn-secondary {
    background: #ffffff;
    color: #000000;
    border-color: #000000;
  }

  .pkv-btn-secondary:hover {
    background: #f5f5f5;
  }

  /* Empty state */
  .pkv-empty-state {
    text-align: center;
    padding: 20px;
    color: #000000;
    border: 3px solid #000000;
    background: #f5f5f5;
  }

  .pkv-empty-icon {
    font-size: 32px;
    margin-bottom: 8px;
  }

  .pkv-empty-text {
    font-size: 13px;
    text-transform: uppercase;
  }

  /* Fenko visual refresh */
  .pkv-toast,
  .pkv-card,
  .pkv-passkey-item,
  .pkv-empty-state,
  .pkv-btn,
  .pkv-passkey-check {
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

  .pkv-card {
    background: #FFFFFF;
    border: 1px solid #D1D9E0;
    box-shadow: 0 24px 60px rgba(13, 17, 23, 0.18);
  }

  .pkv-card-header {
    background: #F6F8FA;
    color: #1F2328;
    border-bottom-color: #E8ECEF;
  }

  .pkv-card-title,
  .pkv-passkey-name,
  .pkv-empty-text {
    color: #1F2328;
  }

  .pkv-card-subtitle,
  .pkv-passkey-detail {
    color: #59636E;
  }

  .pkv-card-body {
    background: #FFFFFF;
  }

  .pkv-card-footer {
    background: #F6F8FA;
    border-top-color: #E8ECEF;
  }

  .pkv-passkey-item {
    border: 1px solid #D1D9E0;
    background: #FFFFFF;
  }

  .pkv-passkey-item:hover,
  .pkv-passkey-item.pkv-selected {
    background: #FEF7E6;
    border-color: rgba(212, 146, 10, 0.45);
  }

  .pkv-passkey-avatar,
  .pkv-passkey-item.pkv-selected .pkv-passkey-check {
    background: #0D1117;
    border-color: #0D1117;
    color: #F5A623;
  }

  .pkv-passkey-check {
    border: 1px solid #D1D9E0;
  }

  .pkv-passkey-check-icon {
    color: #F5A623;
  }

  .pkv-btn {
    border: 1px solid #D1D9E0;
  }

  .pkv-btn-primary {
    background: #D4920A;
    color: #FFFFFF;
    border-color: #D4920A;
  }

  .pkv-btn-primary:hover {
    background: #B87D08;
    color: #FFFFFF;
  }

  .pkv-btn-secondary {
    background: #FFFFFF;
    color: #1F2328;
    border-color: #D1D9E0;
  }

  .pkv-btn-secondary:hover {
    background: #F0F2F4;
  }

  .pkv-empty-state {
    border: 1px solid #D1D9E0;
    background: #F6F8FA;
  }

  html[data-theme='dark'] .pkv-toast,
  html[data-theme='dark'] .pkv-card {
    background: #161B22;
    border-color: #30363D;
    color: #E6EDF3;
  }

  html[data-theme='dark'] .pkv-card-header,
  html[data-theme='dark'] .pkv-card-footer,
  html[data-theme='dark'] .pkv-empty-state {
    background: #0D1117;
    border-color: #30363D;
  }

  html[data-theme='dark'] .pkv-card-title,
  html[data-theme='dark'] .pkv-passkey-name,
  html[data-theme='dark'] .pkv-empty-text {
    color: #E6EDF3;
  }

  html[data-theme='dark'] .pkv-card-subtitle,
  html[data-theme='dark'] .pkv-passkey-detail {
    color: #8D96A0;
  }

  html[data-theme='dark'] .pkv-card-body,
  html[data-theme='dark'] .pkv-passkey-item,
  html[data-theme='dark'] .pkv-btn-secondary {
    background: #161B22;
    color: #E6EDF3;
    border-color: #30363D;
  }

  html[data-theme='dark'] .pkv-passkey-item:hover,
  html[data-theme='dark'] .pkv-passkey-item.pkv-selected,
  html[data-theme='dark'] .pkv-btn-secondary:hover {
    background: #21262D;
    border-color: rgba(245, 166, 35, 0.45);
  }

  html[data-theme='dark'] .pkv-btn-primary {
    background: #F5A623;
    color: #0D1117;
    border-color: #F5A623;
  }

  html[data-theme='dark'] .pkv-btn-primary:hover {
    background: #FFBA42;
    color: #0D1117;
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
 * Passkey data for selection
 */
interface PasskeyOption {
  id: string;
  credentialId: string;
  userName: string;
  userDisplayName: string;
  rpId: string;
  createdAt: number;
}

type PasskeySelectorResult =
  | { action: 'use'; id: string }
  | { action: 'cancel' }
  | { action: 'passthrough' };

/**
 * Show passkey selection modal
 * Returns one of: use selected passkey, cancel entirely, or pass through
 * to the next handler / native WebAuthn UI.
 */
function showPasskeySelector(
  passkeys: PasskeyOption[],
  rpId: string
): Promise<PasskeySelectorResult> {
  return new Promise((resolve) => {
    injectStyles();

    // Remove any existing card
    const existingCard = document.querySelector('.pkv-notification-container');
    if (existingCard) {
      existingCard.remove();
    }

    let selectedId = passkeys.length > 0 ? passkeys[0].id : null;

    const container = document.createElement('div');
    container.className = 'pkv-notification-container';

    const passkeyListHtml =
      passkeys.length > 0
        ? `<div class="pkv-passkey-list">
           ${passkeys
             .map(
               (pk, index) => `
             <div class="pkv-passkey-item ${index === 0 ? 'pkv-selected' : ''}" data-id="${escapeHtml(pk.id)}">
               <div class="pkv-passkey-avatar">
                 <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                   <rect x="3" y="11" width="18" height="11" rx="2"></rect>
                   <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                 </svg>
               </div>
               <div class="pkv-passkey-info">
                 <div class="pkv-passkey-name">${escapeHtml(pk.userDisplayName || pk.userName || t('commonUnknownUser'))}</div>
                 <div class="pkv-passkey-detail">${escapeHtml(pk.userName || pk.id.substring(0, 16) + '...')}</div>
               </div>
               <div class="pkv-passkey-check">
                 <span class="pkv-passkey-check-icon">&#10003;</span>
               </div>
             </div>
           `
             )
             .join('')}
        </div>`
        : `<div class="pkv-empty-state">
          <div class="pkv-empty-icon">&#128275;</div>
          <div class="pkv-empty-text">${escapeHtml(t('pageNoPasskeysSite'))}</div>
        </div>`;

    container.innerHTML = `
       <div class="pkv-card">
         <div class="pkv-card-header">
           <div class="pkv-card-header-content">
              <div>
                <span class="pkv-card-title">${escapeHtml(t('pageChoosePasskey'))}</span>
                <div class="pkv-card-subtitle">${escapeHtml(t('pageSignInTo', { rp: rpId }))}</div>
              </div>
           </div>
         </div>
         <div class="pkv-card-body">
           ${passkeyListHtml}
         </div>
         <div class="pkv-card-footer">
           <button class="pkv-btn pkv-btn-secondary" id="pkv-cancel">${escapeHtml(t('commonCancel'))}</button>
           <button class="pkv-btn pkv-btn-secondary" id="pkv-passthrough">${escapeHtml(t('pageUseOtherPasskey'))}</button>
           <button class="pkv-btn pkv-btn-primary" id="pkv-continue" ${passkeys.length === 0 ? 'disabled' : ''}>
             ${escapeHtml(t('pageContinue'))}
           </button>
         </div>
       </div>
     `;

    document.body.appendChild(container);

    // Handle passkey selection
    const items = container.querySelectorAll('.pkv-passkey-item');
    items.forEach((item) => {
      item.addEventListener('click', () => {
        items.forEach((i) => i.classList.remove('pkv-selected'));
        item.classList.add('pkv-selected');
        selectedId = item.getAttribute('data-id');
      });
    });

    // Cleanup function
    const cleanup = (result: PasskeySelectorResult) => {
      document.removeEventListener('keydown', handleEscape);
      container.style.animation = 'pkv-slideOutRight 0.2s ease-in forwards';
      setTimeout(() => {
        container.remove();
        resolve(result);
      }, 200);
    };

    // Handle cancel
    const cancelBtn = container.querySelector('#pkv-cancel');
    cancelBtn?.addEventListener('click', () => cleanup({ action: 'cancel' }));

    // Handle passthrough — let the next hook / native WebAuthn handle this
    const passthroughBtn = container.querySelector('#pkv-passthrough');
    passthroughBtn?.addEventListener('click', () => cleanup({ action: 'passthrough' }));

    // Handle continue
    const continueBtn = container.querySelector('#pkv-continue');
    continueBtn?.addEventListener('click', () => {
      if (!selectedId) return;
      cleanup({ action: 'use', id: selectedId });
    });

    // Handle escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        cleanup({ action: 'cancel' });
      }
    };
    document.addEventListener('keydown', handleEscape);
  });
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
 * Show passkey used notification
 */
function showPasskeyUsedNotification(userName: string, rpId: string): void {
  void rpId;
  showToast(t('pageSignedIn'), t('pageSignedInMsg', { user: userName }), 'success', 3000);
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
  return div.innerHTML;
}

const w = window as unknown as Record<string, unknown>;
w.showPasskeySelector = showPasskeySelector;
w.showPasskeyCreatedNotification = showPasskeyCreatedNotification;
w.showPasskeyUsedNotification = showPasskeyUsedNotification;
w.showErrorNotification = showErrorNotification;
