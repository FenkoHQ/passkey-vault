/**
 * Popup UI for PassKey Vault
 *
 * Displays and manages stored passkeys with full export/import support
 */

(function () {
  'use strict';

  const POPUP_PASSKEY_STORAGE_KEY = 'passkeys';
  const EXPORT_VERSION = '1.0';

  // DOM elements
  let loadingEl: HTMLElement;
  let emptyStateEl: HTMLElement;
  let passkeyListEl: HTMLElement;
  let passkeyCountEl: HTMLElement;
  let refreshBtn: HTMLButtonElement;
  let exportFullBtn: HTMLButtonElement;
  let importBtn: HTMLButtonElement;
  let clearBtn: HTMLButtonElement;
  let confirmModal: HTMLElement;
  let searchInput: HTMLInputElement;
  let searchClearBtn: HTMLButtonElement;

  // Store all passkeys for filtering
  let allPasskeys: any[] = [];

  // Initialize popup when DOM is loaded
  document.addEventListener('DOMContentLoaded', () => {
    initializeElements();
    createConfirmModal();
    loadPasskeys();
    setupEventListeners();
  });

  function initializeElements(): void {
    loadingEl = document.getElementById('loading') as HTMLElement;
    emptyStateEl = document.getElementById('empty-state') as HTMLElement;
    passkeyListEl = document.getElementById('passkey-list') as HTMLElement;
    passkeyCountEl = document.getElementById('passkey-count') as HTMLElement;
    refreshBtn = document.getElementById('refresh-btn') as HTMLButtonElement;
    exportFullBtn = document.getElementById('export-full-btn') as HTMLButtonElement;
    importBtn = document.getElementById('import-btn') as HTMLButtonElement;
    clearBtn = document.getElementById('clear-btn') as HTMLButtonElement;
    searchInput = document.getElementById('search-input') as HTMLInputElement;
    searchClearBtn = document.getElementById('search-clear') as HTMLButtonElement;
  }

  function createConfirmModal(): void {
    confirmModal = document.createElement('div');
    confirmModal.id = 'confirm-modal';
    confirmModal.className = 'modal-overlay';
    confirmModal.innerHTML = `
      <div class="modal-content">
        <div class="modal-icon">⚠️</div>
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
    importBtn.addEventListener('click', openImportPage);
    clearBtn.addEventListener('click', clearAllPasskeys);

    // Search functionality
    searchInput.addEventListener('input', handleSearch);
    searchClearBtn.addEventListener('click', clearSearch);

    // Also handle the import button in empty state
    const importEmptyBtn = document.getElementById('import-btn-empty');
    if (importEmptyBtn) {
      importEmptyBtn.addEventListener('click', openImportPage);
    }
  }

  function handleSearch(): void {
    const query = searchInput.value.trim().toLowerCase();

    // Toggle clear button visibility
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

  /**
   * Filter and sort passkeys based on search query
   * Priority: domain match > username match (unless username contains @)
   */
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

        // Calculate score
        let score = 0;

        if (hasAtSymbol) {
          // If query contains @, prefer username matches (likely searching for email)
          if (usernameMatch) {
            score += username.startsWith(query) ? 100 : 50;
          }
          if (domainMatch) {
            score += domain.startsWith(query) ? 40 : 20;
          }
        } else {
          // Default: prefer domain matches over username
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

    // Sort by score (highest first), then by creation date (newest first)
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
        <div class="no-results-icon">🔍</div>
        <p>No passkeys found for "${popupEscapeHtml(query)}"</p>
      </div>
    `;
    passkeyListEl.style.display = 'flex';
  }

  /**
   * Open import page in a new tab (file inputs don't work well in popups)
   */
  function openImportPage(): void {
    window.open(chrome.runtime.getURL('import.html'));
  }

  async function loadPasskeys(): Promise<void> {
    try {
      // Show loading state
      loadingEl.style.display = 'flex';
      emptyStateEl.style.display = 'none';
      passkeyListEl.style.display = 'none';

      // Clear search on reload
      searchInput.value = '';
      searchClearBtn.style.display = 'none';

      // Get passkeys from storage
      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[POPUP_PASSKEY_STORAGE_KEY] || [];

      // Store all passkeys for filtering
      allPasskeys = passkeys;

      // Hide loading state
      loadingEl.style.display = 'none';

      // Update count badge
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
          <div class="error-icon">⚠️</div>
          <p>Failed to load passkeys</p>
          <button onclick="location.reload()" class="btn btn-secondary">Retry</button>
        </div>
      `;
    }
  }

  function renderPasskeys(passkeys: any[]): void {
    passkeyListEl.innerHTML = '';

    // Sort by created date (newest first)
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
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
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

    // Add copy handler
    const copyBtn = div.querySelector('.copy-btn') as HTMLButtonElement;
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyPasskeyToClipboard(passkey, copyBtn);
    });

    // Add expand/collapse handler
    const expandBtn = div.querySelector('.expand-btn') as HTMLButtonElement;
    const details = div.querySelector('.passkey-details') as HTMLElement;
    expandBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isExpanded = details.classList.toggle('show');
      expandBtn.classList.toggle('expanded', isExpanded);
      div.classList.toggle('expanded', isExpanded);
    });

    // Add delete handler
    const deleteBtn = div.querySelector('.delete-btn') as HTMLButtonElement;
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      deletePasskey(passkey.id, passkey.rpId || 'this site');
    });

    return div;
  }

  async function copyPasskeyToClipboard(passkey: any, btn: HTMLButtonElement): Promise<void> {
    // Create a copy without private key for debugging
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

        // Show notification
        showNotification('Passkey deleted successfully');

        // Reload the list
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

  /**
   * Export passkeys WITH private keys (full backup)
   */
  async function exportPasskeysFull(): Promise<void> {
    // Show warning about sensitive data
    const confirmed = await showConfirmModal(
      'Export Full Backup?',
      'This will export ALL passkey data including private keys. Keep this file secure and never share it with anyone!',
      'Export Full Backup',
      false
    );

    if (!confirmed) {
      return;
    }

    try {
      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[POPUP_PASSKEY_STORAGE_KEY] || [];

      if (passkeys.length === 0) {
        showNotification('No passkeys to export', 'error');
        return;
      }

      // Create full export data WITH private keys
      const exportData = {
        version: EXPORT_VERSION,
        exportType: 'full',
        exportedAt: new Date().toISOString(),
        description: 'PassKey Vault FULL backup (contains private keys - KEEP SECURE!)',
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

      downloadJson(exportData, `passkeys-FULL-BACKUP-${getDateString()}.json`);
      showNotification(`Exported ${passkeys.length} passkeys (full backup)`);
    } catch (error) {
      console.error('Error exporting passkeys:', error);
      showNotification('Failed to export passkeys', 'error');
    }
  }

  /**
   * Download data as JSON file
   */
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

  /**
   * Get current date as string for filename
   */
  function getDateString(): string {
    return new Date().toISOString().split('T')[0];
  }

  function showNotification(message: string, type: string = 'success'): void {
    // Remove existing notification
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
