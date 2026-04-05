/**
 * Popup UI for PassKey Vault
 *
 * Displays and manages stored passkeys with full export/import support
 */

(function () {
  'use strict';

  const POPUP_PASSKEY_STORAGE_KEY = 'passkeys';
  const EXPORT_VERSION = '1.0';
  const SETUP_SKIPPED_KEY = 'master_password_setup_skipped';

  // DOM elements
  let loadingEl: HTMLElement;
  let emptyStateEl: HTMLElement;
  let passkeyListEl: HTMLElement;
  let passkeyCountEl: HTMLElement;
  let refreshBtn: HTMLButtonElement;
  let exportFullBtn: HTMLButtonElement;
  let confirmModal: HTMLElement;
  let searchInput: HTMLInputElement;
  let searchClearBtn: HTMLButtonElement;

  // Screen elements
  let lockScreen: HTMLElement;
  let setupScreen: HTMLElement;
  let mainContainer: HTMLElement;

  let allPasskeys: Record<string, unknown>[] = [];

  // Initialize popup when DOM is loaded
  document.addEventListener('DOMContentLoaded', () => {
    lockScreen = document.getElementById('lock-screen') as HTMLElement;
    setupScreen = document.getElementById('setup-screen') as HTMLElement;
    mainContainer = document.getElementById('main-container') as HTMLElement;

    const optionsBtn = document.getElementById('options-btn');
    if (optionsBtn) {
      optionsBtn.addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
      });
    }

    checkSecureStorageState();
  });

  async function checkSecureStorageState(): Promise<void> {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'IS_SECURE_STORAGE_UNLOCKED' });
      if (!response.success) {
        showMainScreen();
        return;
      }

      if (response.isSetup && !response.isUnlocked) {
        // Master password exists but vault is locked
        showLockScreen();
      } else if (!response.isSetup) {
        // Check if user previously skipped setup
        const skipped = await chrome.storage.local.get(SETUP_SKIPPED_KEY);
        if (skipped[SETUP_SKIPPED_KEY]) {
          showMainScreen();
        } else {
          showSetupScreen();
        }
      } else {
        // Unlocked — show main
        showMainScreen();
      }
    } catch {
      // Can't reach background — just show main
      showMainScreen();
    }
  }

  function showLockScreen(): void {
    lockScreen.style.display = 'block';
    setupScreen.style.display = 'none';
    mainContainer.style.display = 'none';

    const passwordInput = document.getElementById('unlock-password') as HTMLInputElement;
    const unlockBtn = document.getElementById('unlock-btn') as HTMLButtonElement;
    const errorEl = document.getElementById('unlock-error') as HTMLElement;

    passwordInput.focus();

    const doUnlock = async () => {
      const password = passwordInput.value;
      if (!password) return;

      unlockBtn.disabled = true;
      unlockBtn.textContent = 'Unlocking...';
      errorEl.style.display = 'none';

      const response = await chrome.runtime.sendMessage({
        type: 'UNLOCK_SECURE_STORAGE',
        payload: { password },
      });

      if (response.success) {
        showMainScreen();
      } else {
        errorEl.textContent = 'Wrong password';
        errorEl.style.display = 'block';
        passwordInput.value = '';
        passwordInput.focus();
      }

      unlockBtn.disabled = false;
      unlockBtn.textContent = 'Unlock';
    };

    unlockBtn.onclick = doUnlock;
    passwordInput.onkeydown = (e) => {
      if (e.key === 'Enter') doUnlock();
    };
  }

  function showSetupScreen(): void {
    lockScreen.style.display = 'none';
    setupScreen.style.display = 'block';
    mainContainer.style.display = 'none';

    const passwordInput = document.getElementById('setup-password') as HTMLInputElement;
    const confirmInput = document.getElementById('setup-password-confirm') as HTMLInputElement;
    const setupBtn = document.getElementById('setup-btn') as HTMLButtonElement;
    const skipBtn = document.getElementById('skip-setup-btn') as HTMLButtonElement;
    const errorEl = document.getElementById('setup-error') as HTMLElement;

    passwordInput.focus();

    setupBtn.onclick = async () => {
      const password = passwordInput.value;
      const confirm = confirmInput.value;
      errorEl.style.display = 'none';

      if (password.length < 8) {
        errorEl.textContent = 'Password must be at least 8 characters';
        errorEl.style.display = 'block';
        return;
      }
      if (password !== confirm) {
        errorEl.textContent = 'Passwords do not match';
        errorEl.style.display = 'block';
        return;
      }

      setupBtn.disabled = true;
      setupBtn.textContent = 'Setting up...';

      const response = await chrome.runtime.sendMessage({
        type: 'SETUP_MASTER_PASSWORD',
        payload: { password },
      });

      if (response.success) {
        showMainScreen();
      } else {
        errorEl.textContent = response.error || 'Setup failed';
        errorEl.style.display = 'block';
      }

      setupBtn.disabled = false;
      setupBtn.textContent = 'Create Password';
    };

    skipBtn.onclick = async () => {
      await chrome.storage.local.set({ [SETUP_SKIPPED_KEY]: true });
      showMainScreen();
    };
  }

  function showMainScreen(): void {
    lockScreen.style.display = 'none';
    setupScreen.style.display = 'none';
    mainContainer.style.display = 'block';
    initializeElements();
    createConfirmModal();
    loadPasskeys();
    loadSyncStatus();
    setupEventListeners();
  }

  async function loadSyncStatus(): Promise<void> {
    const badge = document.getElementById('sync-status-badge') as HTMLElement;
    if (!badge) return;

    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_SYNC_STATUS' });
      if (!response.success || !response.status?.enabled) {
        badge.style.display = 'none';
        return;
      }

      const status = response.status;
      badge.style.display = 'inline-block';

      switch (status.connectionStatus) {
        case 'connected':
          badge.textContent = 'synced';
          badge.style.background = '#10b981';
          badge.style.color = '#fff';
          break;
        case 'connecting':
          badge.textContent = 'syncing...';
          badge.style.background = '#f59e0b';
          badge.style.color = '#000';
          break;
        case 'error':
          badge.textContent = 'sync error';
          badge.style.background = '#ef4444';
          badge.style.color = '#fff';
          badge.title = status.lastError || 'Unknown error';
          break;
        default:
          badge.textContent = 'offline';
          badge.style.background = '#666';
          badge.style.color = '#fff';
      }

      if (status.pendingChanges > 0) {
        badge.textContent += ` (${status.pendingChanges} pending)`;
      }
    } catch {
      badge.style.display = 'none';
    }
  }

  function initializeElements(): void {
    loadingEl = document.getElementById('loading') as HTMLElement;
    emptyStateEl = document.getElementById('empty-state') as HTMLElement;
    passkeyListEl = document.getElementById('passkey-list') as HTMLElement;
    passkeyCountEl = document.getElementById('passkey-count') as HTMLElement;
    refreshBtn = document.getElementById('refresh-btn') as HTMLButtonElement;
    exportFullBtn = document.getElementById('export-full-btn') as HTMLButtonElement;
    searchInput = document.getElementById('search-input') as HTMLInputElement;
    searchClearBtn = document.getElementById('search-clear') as HTMLButtonElement;
  }

  function createConfirmModal(): void {
    confirmModal = document.createElement('div');
    confirmModal.id = 'confirm-modal';
    confirmModal.className = 'modal-overlay';
    confirmModal.innerHTML = `
      <div class="modal-content">
        <div class="modal-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg></div>
        <h3 class="modal-title"></h3>
        <p class="modal-message"></p>
        <div class="modal-actions">
          <button class="btn btn-secondary modal-cancel">Cancel</button>
          <button class="btn btn-danger modal-confirm">Confirm</button>
        </div>
      </div>
    `;
    confirmModal.style.display = 'none';
    document.body.appendChild(confirmModal);

    // Close on overlay click
    confirmModal.addEventListener('click', (e) => {
      if (e.target === confirmModal) {
        hideConfirmModal();
      }
    });
  }

  function showConfirmModal(
    title: string,
    message: string,
    confirmText: string = 'Confirm',
    isDanger: boolean = true
  ): Promise<boolean> {
    return new Promise((resolve) => {
      const titleEl = confirmModal.querySelector('.modal-title') as HTMLElement;
      const messageEl = confirmModal.querySelector('.modal-message') as HTMLElement;
      const confirmBtn = confirmModal.querySelector('.modal-confirm') as HTMLButtonElement;
      const cancelBtn = confirmModal.querySelector('.modal-cancel') as HTMLButtonElement;

      titleEl.textContent = title;
      messageEl.textContent = message;
      confirmBtn.textContent = confirmText;
      confirmBtn.className = isDanger
        ? 'btn btn-danger modal-confirm'
        : 'btn btn-primary modal-confirm';

      confirmModal.style.display = 'flex';

      const cleanup = () => {
        confirmBtn.removeEventListener('click', onConfirm);
        cancelBtn.removeEventListener('click', onCancel);
        hideConfirmModal();
      };

      const onConfirm = () => {
        cleanup();
        resolve(true);
      };

      const onCancel = () => {
        cleanup();
        resolve(false);
      };

      confirmBtn.addEventListener('click', onConfirm);
      cancelBtn.addEventListener('click', onCancel);
    });
  }

  function hideConfirmModal(): void {
    confirmModal.style.display = 'none';
  }

  function setupEventListeners(): void {
    refreshBtn.addEventListener('click', loadPasskeys);
    exportFullBtn.addEventListener('click', exportPasskeysFull);

    searchInput.addEventListener('input', handleSearch);
    searchClearBtn.addEventListener('click', clearSearch);

    const importEmptyBtn = document.getElementById('import-btn-empty');
    if (importEmptyBtn) {
      importEmptyBtn.addEventListener('click', openImportPage);
    }
  }

  function handleSearch(): void {
    const query = searchInput.value.trim().toLowerCase();

    searchClearBtn.style.display = query ? 'block' : 'none';

    if (!query) {
      renderPasskeys(allPasskeys);
      return;
    }

    const filtered = filterAndSortPasskeys(allPasskeys, query);

    if (filtered.length === 0) {
      showNoResults(query);
    } else {
      renderPasskeys(filtered);
    }
  }

  function clearSearch(): void {
    searchInput.value = '';
    searchClearBtn.style.display = 'none';
    renderPasskeys(allPasskeys);
    searchInput.focus();
  }

  function filterAndSortPasskeys(passkeys: any[], query: string): any[] {
    const hasAtSymbol = query.includes('@');

    const scored = passkeys
      .map((passkey) => {
        const domain = (passkey.rpId || '').toLowerCase();
        const username = (passkey.user?.name || '').toLowerCase();

        const domainMatch = domain.includes(query);
        const usernameMatch = username.includes(query);

        if (!domainMatch && !usernameMatch) {
          return null;
        }

        let score = 0;

        if (hasAtSymbol) {
          if (usernameMatch) {
            score += username.startsWith(query) ? 100 : 50;
          }
          if (domainMatch) {
            score += domain.startsWith(query) ? 40 : 20;
          }
        } else {
          if (domainMatch) {
            score += domain.startsWith(query) ? 100 : 50;
          }
          if (usernameMatch) {
            score += username.startsWith(query) ? 40 : 20;
          }
        }

        return { passkey, score };
      })
      .filter((item): item is { passkey: any; score: number } => item !== null);

    scored.sort((a, b) => {
      if (b.score !== a.score) {
        return b.score - a.score;
      }
      return (b.passkey.createdAt || 0) - (a.passkey.createdAt || 0);
    });

    return scored.map((item) => item.passkey);
  }

  function showNoResults(query: string): void {
    passkeyListEl.innerHTML = `
      <div class="no-results">
        <div class="no-results-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><path d="m15 8-4 4-2-2"/></svg></div>
        <p>No passkeys found for "${popupEscapeHtml(query)}"</p>
      </div>
    `;
    passkeyListEl.style.display = 'flex';
  }

  function openImportPage(): void {
    window.open(chrome.runtime.getURL('import.html'));
  }

  async function loadPasskeys(): Promise<void> {
    try {
      loadingEl.style.display = 'flex';
      emptyStateEl.style.display = 'none';
      passkeyListEl.style.display = 'none';

      searchInput.value = '';
      searchClearBtn.style.display = 'none';

      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[POPUP_PASSKEY_STORAGE_KEY] || [];

      allPasskeys = passkeys;

      loadingEl.style.display = 'none';

      passkeyCountEl.textContent = `${passkeys.length} passkey${passkeys.length !== 1 ? 's' : ''}`;

      if (passkeys.length === 0) {
        emptyStateEl.style.display = 'block';
      } else {
        renderPasskeys(passkeys);
      }
    } catch (error) {
      console.error('Error loading passkeys:', error);
      loadingEl.innerHTML = `
        <div class="error-state">
          <div class="error-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg></div>
          <p>Failed to load passkeys</p>
          <button onclick="location.reload()" class="btn btn-secondary">Retry</button>
        </div>
      `;
    }
  }

  function renderPasskeys(passkeys: any[]): void {
    passkeyListEl.innerHTML = '';

    const sortedPasskeys = [...passkeys].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    sortedPasskeys.forEach((passkey) => {
      const item = createPasskeyItem(passkey);
      passkeyListEl.appendChild(item);
    });

    passkeyListEl.style.display = 'flex';
  }

  function createPasskeyItem(passkey: any): HTMLElement {
    const div = document.createElement('div');
    div.className = 'passkey-item';

    const createdAt = passkey.createdAt ? new Date(passkey.createdAt) : null;
    const dateStr = createdAt
      ? createdAt.toLocaleDateString() +
        ' ' +
        createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : 'Unknown';

    const credentialIdShort = passkey.id ? passkey.id.substring(0, 20) + '...' : 'Unknown';

    div.innerHTML = `
      <div class="passkey-header">
        <div class="passkey-info">
          <div class="passkey-rp">${popupEscapeHtml(passkey.rpId || 'Unknown Site')}</div>
          ${passkey.user?.name ? `<div class="passkey-username">${popupEscapeHtml(passkey.user.name)}</div>` : ''}
        </div>
        <div class="passkey-actions">
          <button class="copy-btn" title="Copy to clipboard">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2"></rect>
              <rect x="3" y="3" width="13" height="13" rx="2"></rect>
            </svg>
          </button>
          <button class="expand-btn" title="Details">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </button>
          <button class="delete-btn" data-id="${popupEscapeHtml(passkey.id)}">Del</button>
        </div>
      </div>
      <div class="passkey-details">
        <div class="passkey-detail-row">
          <span class="label">Added:</span>
          <span class="value">${popupEscapeHtml(dateStr)}</span>
        </div>
        <div class="passkey-detail-row">
          <span class="label">Key ID:</span>
          <span class="value">${popupEscapeHtml(credentialIdShort)}</span>
        </div>
      </div>
    `;

    const copyBtn = div.querySelector('.copy-btn') as HTMLButtonElement;
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyPasskeyToClipboard(passkey, copyBtn);
    });

    const expandBtn = div.querySelector('.expand-btn') as HTMLButtonElement;
    const details = div.querySelector('.passkey-details') as HTMLElement;
    expandBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isExpanded = details.classList.toggle('show');
      expandBtn.classList.toggle('expanded', isExpanded);
      div.classList.toggle('expanded', isExpanded);
    });

    const deleteBtn = div.querySelector('.delete-btn') as HTMLButtonElement;
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      deletePasskey(passkey.id, passkey.rpId || 'this site');
    });

    return div;
  }

  async function copyPasskeyToClipboard(passkey: any, btn: HTMLButtonElement): Promise<void> {
    const debugData = {
      id: passkey.id,
      credentialId: passkey.credentialId,
      type: passkey.type,
      rpId: passkey.rpId,
      origin: passkey.origin,
      user: passkey.user,
      publicKey: passkey.publicKey,
      createdAt: passkey.createdAt,
      counter: passkey.counter,
      lastUsed: passkey.lastUsed,
    };

    try {
      await navigator.clipboard.writeText(JSON.stringify(debugData, null, 2));
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1500);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      showNotification('Failed to copy', 'error');
    }
  }

  async function deletePasskey(credentialId: string, siteName: string): Promise<void> {
    const confirmed = await showConfirmModal(
      'Delete Passkey?',
      `You will no longer be able to sign in to ${siteName} using this passkey.`,
      'Delete',
      true
    );

    if (!confirmed) {
      return;
    }

    try {
      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[POPUP_PASSKEY_STORAGE_KEY] || [];

      const filtered = passkeys.filter((p) => p.id !== credentialId);

      if (filtered.length < passkeys.length) {
        await chrome.storage.local.set({ [POPUP_PASSKEY_STORAGE_KEY]: filtered });

        showNotification('Passkey deleted successfully');

        await loadPasskeys();
      } else {
        showNotification('Passkey not found', 'error');
      }
    } catch (error) {
      console.error('Error deleting passkey:', error);
      showNotification('Failed to delete passkey', 'error');
    }
  }

  async function clearAllPasskeys(): Promise<void> {
    const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
    const passkeys: any[] = result[POPUP_PASSKEY_STORAGE_KEY] || [];
    const passkeyCount = passkeys.length;

    if (passkeyCount === 0) {
      showNotification('No passkeys to clear', 'error');
      return;
    }

    const confirmed = await showConfirmModal(
      `Delete All ${passkeyCount} Passkeys?`,
      'This will permanently remove all your passkeys. You will lose access to any accounts that only have passkey authentication.',
      'Delete All',
      true
    );

    if (!confirmed) {
      return;
    }

    try {
      await chrome.storage.local.set({ [POPUP_PASSKEY_STORAGE_KEY]: [] });
      showNotification('All passkeys cleared');
      await loadPasskeys();
    } catch (error) {
      console.error('Error clearing passkeys:', error);
      showNotification('Failed to clear passkeys', 'error');
    }
  }

  async function exportPasskeysFull(): Promise<void> {
    const password = await showPasswordPrompt(
      'Encrypt Backup',
      'Choose a password to encrypt the backup file. You will need this password to import it later.'
    );
    if (password === null) return;

    try {
      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys: Record<string, unknown>[] = result[POPUP_PASSKEY_STORAGE_KEY] || [];

      if (passkeys.length === 0) {
        showNotification('No passkeys to export', 'error');
        return;
      }

      const exportData = {
        version: EXPORT_VERSION,
        exportType: 'full',
        exportedAt: new Date().toISOString(),
        passkeys: passkeys.map((p) => ({
          id: p.id,
          credentialId: p.credentialId,
          type: p.type,
          rpId: p.rpId,
          origin: p.origin,
          user: p.user,
          privateKey: p.privateKey,
          publicKey: p.publicKey,
          createdAt: p.createdAt,
          counter: p.counter,
          lastUsed: p.lastUsed,
          prfKey: p.prfKey,
        })),
      };

      const plaintext = JSON.stringify(exportData);

      const encResponse = await chrome.runtime.sendMessage({
        type: 'ENCRYPT_BACKUP',
        payload: { data: plaintext, password },
      });

      if (!encResponse.success) {
        showNotification('Encryption failed: ' + encResponse.error, 'error');
        return;
      }

      const encryptedBackup = {
        encrypted: true,
        version: EXPORT_VERSION,
        exportedAt: new Date().toISOString(),
        passkeyCount: passkeys.length,
        data: encResponse.encrypted.data,
        iv: encResponse.encrypted.iv,
        salt: encResponse.encrypted.salt,
        algorithm: encResponse.encrypted.algorithm,
      };

      downloadJson(encryptedBackup, `passkeys-backup-${getDateString()}.json`);
      showNotification(`Exported ${passkeys.length} passkeys (encrypted)`);
    } catch (error) {
      console.error('Error exporting passkeys:', error);
      showNotification('Failed to export passkeys', 'error');
    }
  }

  function showPasswordPrompt(title: string, message: string): Promise<string | null> {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';
      overlay.innerHTML = `
        <div class="modal-content">
          <h3 class="modal-title">${popupEscapeHtml(title)}</h3>
          <p class="modal-message">${popupEscapeHtml(message)}</p>
          <input type="password" id="prompt-password" placeholder="Password (min 8 chars)"
            style="width: 100%; padding: 8px; border: 1px solid #333; background: #1a1a1a; color: #fff; border-radius: 4px; font-size: 13px; box-sizing: border-box; margin-bottom: 8px" />
          <input type="password" id="prompt-password-confirm" placeholder="Confirm password"
            style="width: 100%; padding: 8px; border: 1px solid #333; background: #1a1a1a; color: #fff; border-radius: 4px; font-size: 13px; box-sizing: border-box; margin-bottom: 4px" />
          <div id="prompt-error" style="color: #ef4444; font-size: 12px; margin-bottom: 8px; display: none"></div>
          <div class="modal-actions">
            <button class="btn btn-secondary" id="prompt-cancel">Cancel</button>
            <button class="btn btn-primary" id="prompt-ok">Encrypt & Export</button>
          </div>
        </div>
      `;
      overlay.style.display = 'flex';
      document.body.appendChild(overlay);

      const pwInput = overlay.querySelector('#prompt-password') as HTMLInputElement;
      const confirmInput = overlay.querySelector('#prompt-password-confirm') as HTMLInputElement;
      const errorEl = overlay.querySelector('#prompt-error') as HTMLElement;
      const okBtn = overlay.querySelector('#prompt-ok') as HTMLButtonElement;
      const cancelBtn = overlay.querySelector('#prompt-cancel') as HTMLButtonElement;

      pwInput.focus();

      const cleanup = (result: string | null) => {
        overlay.remove();
        resolve(result);
      };

      okBtn.addEventListener('click', () => {
        const pw = pwInput.value;
        const confirm = confirmInput.value;
        errorEl.style.display = 'none';
        if (pw.length < 8) {
          errorEl.textContent = 'Password must be at least 8 characters';
          errorEl.style.display = 'block';
          return;
        }
        if (pw !== confirm) {
          errorEl.textContent = 'Passwords do not match';
          errorEl.style.display = 'block';
          return;
        }
        cleanup(pw);
      });

      cancelBtn.addEventListener('click', () => cleanup(null));
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) cleanup(null);
      });
    });
  }

  function downloadJson(data: any, filename: string): void {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function getDateString(): string {
    return new Date().toISOString().split('T')[0];
  }

  function showNotification(message: string, type: string = 'success'): void {
    const existing = document.querySelector('.popup-notification');
    if (existing) {
      existing.remove();
    }

    const notification = document.createElement('div');
    notification.className = `popup-notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      padding: 10px 16px;
      background: ${type === 'success' ? '#10b981' : '#ef4444'};
      color: white;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      z-index: 3000;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      animation: slideDown 0.3s ease-out;
      max-width: 90%;
      text-align: center;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.animation = 'slideUp 0.3s ease-out';
      setTimeout(() => notification.remove(), 300);
    }, 2500);
  }

  function popupEscapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
})();
