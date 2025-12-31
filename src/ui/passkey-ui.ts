/**
 * PassKey Vault In-Page UI Components
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
    width: 260px;
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
    display: flex;
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
    text-transform: uppercase;
    font-family: 'Courier New', Courier, monospace;
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

/**
 * Show passkey selection modal
 * Returns the selected passkey ID or null if cancelled
 */
function showPasskeySelector(passkeys: PasskeyOption[], rpId: string): Promise<string | null> {
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
                 <div class="pkv-passkey-name">${escapeHtml(pk.userDisplayName || pk.userName || 'Unknown User')}</div>
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
          <div class="pkv-empty-text">No passkeys found for this site</div>
        </div>`;

    container.innerHTML = `
       <div class="pkv-card">
         <div class="pkv-card-header">
           <div class="pkv-card-header-content">
              <div>
                <span class="pkv-card-title">Choose a Passkey</span>
                <div class="pkv-card-subtitle">Sign in to ${escapeHtml(rpId)}</div>
              </div>
           </div>
         </div>
         <div class="pkv-card-body">
           ${passkeyListHtml}
         </div>
         <div class="pkv-card-footer">
           <button class="pkv-btn pkv-btn-secondary" id="pkv-cancel">Cancel</button>
           <button class="pkv-btn pkv-btn-primary" id="pkv-continue" ${passkeys.length === 0 ? 'disabled' : ''}>
             Continue
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
    const cleanup = (result: string | null) => {
      document.removeEventListener('keydown', handleEscape);
      container.style.animation = 'pkv-slideOutRight 0.2s ease-in forwards';
      setTimeout(() => {
        container.remove();
        resolve(result);
      }, 200);
    };

    // Handle cancel
    const cancelBtn = container.querySelector('#pkv-cancel');
    cancelBtn?.addEventListener('click', () => cleanup(null));

    // Handle continue
    const continueBtn = container.querySelector('#pkv-continue');
    continueBtn?.addEventListener('click', () => {
      if (!selectedId) return;
      cleanup(selectedId);
    });

    // Handle escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        cleanup(null);
      }
    };
    document.addEventListener('keydown', handleEscape);
  });
}

/**
 * Show passkey creation success notification
 */
function showPasskeyCreatedNotification(userName: string, rpId: string): void {
  showToast('Passkey Created', `Saved passkey for ${userName} on ${rpId}`, 'success', 4000);
}

/**
 * Show passkey used notification
 */
function showPasskeyUsedNotification(userName: string, rpId: string): void {
  showToast('Signed In', `Used passkey for ${userName}`, 'success', 3000);
}

/**
 * Show error notification
 */
function showErrorNotification(title: string, message: string): void {
  showToast(title, message, 'error', 5000);
}

/**
 * Get initials from a name
 */
function getInitials(name: string): string {
  if (!name) return '?';
  const parts = name.trim().split(/\s+/);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
  return name.substring(0, 2).toUpperCase();
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
