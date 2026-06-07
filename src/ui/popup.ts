/**
 * Popup UI for Passkey Vault
 *
 * Displays and manages stored passkeys with full export/import support
 */

import jsQR from 'jsqr';
import { formatCount, initAndLocalize, t } from '../i18n';
import { initTheme } from '../theme';

(function () {
  'use strict';

  interface PopupPasskey {
    id: string;
    credentialId?: string;
    type?: string;
    rpId?: string;
    origin?: string;
    user?: {
      name?: string;
      displayName?: string;
      [key: string]: unknown;
    };
    publicKey?: unknown;
    createdAt?: number | string;
    counter?: number;
    lastUsed?: number | string;
    [key: string]: unknown;
  }

  const POPUP_PASSKEY_STORAGE_KEY = 'passkeys';
  const POPUP_TOTP_STORAGE_KEY = 'totp_entries';
  const VAULT_WARNING_DISMISSED_KEY = 'vault_warning_dismissed';
  const EXPORT_VERSION = '1.0';
  const SETUP_SKIPPED_KEY = 'master_password_setup_skipped';

  interface PopupTotpEntry {
    id: string;
    type: 'totp' | 'hotp';
    issuer: string;
    account: string;
    secretB64: string;
    algorithm: 'SHA1' | 'SHA256' | 'SHA512';
    digits: number;
    period: number;
    counter: number;
    createdAt: number;
  }

  // DOM elements
  let loadingEl: HTMLElement;
  let emptyStateEl: HTMLElement;
  let vaultListEl: HTMLElement;
  let noResultsEl: HTMLElement;
  let noResultsTextEl: HTMLElement;
  let passkeyCountEl: HTMLElement;
  let refreshBtn: HTMLButtonElement;
  let exportFullBtn: HTMLButtonElement;
  let confirmModal: HTMLElement;
  let searchInput: HTMLInputElement;
  let searchClearBtn: HTMLButtonElement;
  let filterPasskeysBtn: HTMLButtonElement;
  let filterTotpBtn: HTMLButtonElement;
  let vaultWarningEl: HTMLElement;
  let vaultWarningDismissBtn: HTMLButtonElement;

  // Screen elements
  let lockScreen: HTMLElement;
  let setupScreen: HTMLElement;
  let mainContainer: HTMLElement;

  let allPasskeys: PopupPasskey[] = [];
  let allTotpEntries: PopupTotpEntry[] = [];
  const filters = { passkeys: true, totp: true };
  let totpTickInterval: number | null = null;
  const codeCache = new Map<string, { code: string; expiresAt: number }>();
  const VAULT_FILTERS_KEY = 'vault_filters';

  // Initialize popup when DOM is loaded
  document.addEventListener('DOMContentLoaded', async () => {
    await Promise.all([initAndLocalize(), initTheme()]);
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
      unlockBtn.textContent = t('popupUnlocking');
      errorEl.style.display = 'none';

      const response = await chrome.runtime.sendMessage({
        type: 'UNLOCK_SECURE_STORAGE',
        payload: { password },
      });

      if (response.success) {
        showMainScreen();
      } else {
        errorEl.textContent = t('popupWrongPassword');
        errorEl.style.display = 'block';
        passwordInput.value = '';
        passwordInput.focus();
      }

      unlockBtn.disabled = false;
      unlockBtn.textContent = t('popupUnlock');
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
        errorEl.textContent = t('popupPasswordMin');
        errorEl.style.display = 'block';
        return;
      }
      if (password !== confirm) {
        errorEl.textContent = t('popupPasswordsNoMatch');
        errorEl.style.display = 'block';
        return;
      }

      setupBtn.disabled = true;
      setupBtn.textContent = t('popupSettingUp');

      const response = await chrome.runtime.sendMessage({
        type: 'SETUP_MASTER_PASSWORD',
        payload: { password },
      });

      if (response.success) {
        showMainScreen();
      } else {
        errorEl.textContent = response.error || t('popupSetupFailed');
        errorEl.style.display = 'block';
      }

      setupBtn.disabled = false;
      setupBtn.textContent = t('popupCreatePassword');
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
    loadSyncStatus();
    setupEventListeners();
    startTotpTicker();
    initVaultWarning();
    initFilters().then(loadVault);
  }

  async function initFilters(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(VAULT_FILTERS_KEY);
      const stored = result[VAULT_FILTERS_KEY] as
        | { passkeys?: boolean; totp?: boolean }
        | undefined;
      if (stored) {
        filters.passkeys = stored.passkeys !== false;
        filters.totp = stored.totp !== false;
      }
    } catch (error) {
      console.error('Failed to read vault filters:', error);
    }
    syncFilterChips();
  }

  function syncFilterChips(): void {
    filterPasskeysBtn.classList.toggle('active', filters.passkeys);
    filterPasskeysBtn.setAttribute('aria-pressed', String(filters.passkeys));
    filterTotpBtn.classList.toggle('active', filters.totp);
    filterTotpBtn.setAttribute('aria-pressed', String(filters.totp));
  }

  async function toggleFilter(type: 'passkeys' | 'totp'): Promise<void> {
    filters[type] = !filters[type];
    syncFilterChips();
    renderVault();
    try {
      await chrome.storage.local.set({ [VAULT_FILTERS_KEY]: { ...filters } });
    } catch (error) {
      console.error('Failed to persist vault filters:', error);
    }
  }

  async function initVaultWarning(): Promise<void> {
    if (!vaultWarningEl) return;
    try {
      const result = await chrome.storage.local.get(VAULT_WARNING_DISMISSED_KEY);
      vaultWarningEl.hidden = result[VAULT_WARNING_DISMISSED_KEY] === true;
    } catch (error) {
      console.error('Failed to read vault warning state:', error);
      vaultWarningEl.hidden = false;
    }
  }

  async function dismissVaultWarning(): Promise<void> {
    vaultWarningEl.hidden = true;
    try {
      await chrome.storage.local.set({ [VAULT_WARNING_DISMISSED_KEY]: true });
    } catch (error) {
      console.error('Failed to persist vault warning dismissal:', error);
    }
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
          badge.textContent = t('popupSyncSynced');
          badge.style.background = '#10b981';
          badge.style.color = '#fff';
          break;
        case 'connecting':
          badge.textContent = t('popupSyncing');
          badge.style.background = '#f59e0b';
          badge.style.color = '#000';
          break;
        case 'error':
          badge.textContent = t('popupSyncError');
          badge.style.background = '#ef4444';
          badge.style.color = '#fff';
          badge.title = status.lastError || t('commonUnknown');
          break;
        default:
          badge.textContent = t('popupSyncOffline');
          badge.style.background = '#666';
          badge.style.color = '#fff';
      }

      if (status.pendingChanges > 0) {
        badge.textContent += ` (${t('popupSyncPending', { count: status.pendingChanges })})`;
      }
    } catch {
      badge.style.display = 'none';
    }
  }

  function initializeElements(): void {
    loadingEl = document.getElementById('loading') as HTMLElement;
    emptyStateEl = document.getElementById('empty-state') as HTMLElement;
    vaultListEl = document.getElementById('vault-list') as HTMLElement;
    noResultsEl = document.getElementById('no-results') as HTMLElement;
    noResultsTextEl = document.getElementById('no-results-text') as HTMLElement;
    passkeyCountEl = document.getElementById('passkey-count') as HTMLElement;
    refreshBtn = document.getElementById('refresh-btn') as HTMLButtonElement;
    exportFullBtn = document.getElementById('export-full-btn') as HTMLButtonElement;
    searchInput = document.getElementById('search-input') as HTMLInputElement;
    searchClearBtn = document.getElementById('search-clear') as HTMLButtonElement;
    filterPasskeysBtn = document.getElementById('filter-passkeys') as HTMLButtonElement;
    filterTotpBtn = document.getElementById('filter-totp') as HTMLButtonElement;
    vaultWarningEl = document.getElementById('vault-warning') as HTMLElement;
    vaultWarningDismissBtn = document.getElementById('vault-warning-dismiss') as HTMLButtonElement;
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
          <button class="btn btn-secondary modal-cancel">${t('commonCancel')}</button>
          <button class="btn btn-danger modal-confirm">${t('commonConfirm')}</button>
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
    confirmText: string = t('commonConfirm'),
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
    refreshBtn.addEventListener('click', loadVault);
    exportFullBtn.addEventListener('click', exportPasskeysFull);

    searchInput.addEventListener('input', handleSearch);
    searchClearBtn.addEventListener('click', clearSearch);

    const importEmptyBtn = document.getElementById('import-btn-empty');
    if (importEmptyBtn) {
      importEmptyBtn.addEventListener('click', openImportPage);
    }

    filterPasskeysBtn.addEventListener('click', () => toggleFilter('passkeys'));
    filterTotpBtn.addEventListener('click', () => toggleFilter('totp'));

    const addTotpEmpty = document.getElementById('add-totp-empty-btn');
    if (addTotpEmpty) {
      addTotpEmpty.addEventListener('click', showAddTotpDialog);
    }
    const addTotpBtn = document.getElementById('add-totp-btn');
    if (addTotpBtn) {
      addTotpBtn.addEventListener('click', showAddTotpDialog);
    }

    if (vaultWarningDismissBtn) {
      vaultWarningDismissBtn.addEventListener('click', dismissVaultWarning);
    }
  }

  function handleSearch(): void {
    searchClearBtn.style.display = searchInput.value.trim() ? 'block' : 'none';
    renderVault();
  }

  function clearSearch(): void {
    searchInput.value = '';
    searchClearBtn.style.display = 'none';
    renderVault();
    searchInput.focus();
  }

  function getCreatedAtTimestamp(passkey: PopupPasskey): number {
    if (typeof passkey.createdAt === 'number') {
      return passkey.createdAt;
    }
    if (typeof passkey.createdAt === 'string') {
      const timestamp = Date.parse(passkey.createdAt);
      return Number.isNaN(timestamp) ? 0 : timestamp;
    }
    return 0;
  }

  function filterAndSortPasskeys(passkeys: PopupPasskey[], query: string): PopupPasskey[] {
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
      .filter((item): item is { passkey: PopupPasskey; score: number } => item !== null);

    scored.sort((a, b) => {
      if (b.score !== a.score) {
        return b.score - a.score;
      }
      return getCreatedAtTimestamp(b.passkey) - getCreatedAtTimestamp(a.passkey);
    });

    return scored.map((item) => item.passkey);
  }

  function openImportPage(): void {
    window.open(chrome.runtime.getURL('import.html'));
  }

  // Load both passkeys and TOTP entries, then render the unified vault list.
  async function loadVault(): Promise<void> {
    try {
      loadingEl.style.display = 'flex';
      emptyStateEl.style.display = 'none';
      noResultsEl.hidden = true;
      vaultListEl.style.display = 'none';

      const [passkeyResult, totpResult] = await Promise.all([
        chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY),
        chrome.storage.local.get(POPUP_TOTP_STORAGE_KEY),
      ]);
      allPasskeys = (passkeyResult[POPUP_PASSKEY_STORAGE_KEY] || []) as PopupPasskey[];
      allTotpEntries = (totpResult[POPUP_TOTP_STORAGE_KEY] || []) as PopupTotpEntry[];

      loadingEl.style.display = 'none';
      renderVault();
    } catch (error) {
      console.error('Error loading vault:', error);
      loadingEl.innerHTML = `
        <div class="error-state">
          <div class="error-icon"><svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg></div>
          <p>${t('popupFailedLoad')}</p>
          <button onclick="location.reload()" class="btn btn-secondary">${t('commonRetry')}</button>
        </div>
      `;
    }
  }

  function filterTotpEntries(entries: PopupTotpEntry[], query: string): PopupTotpEntry[] {
    const matched = query
      ? entries.filter((e) => {
          const issuer = (e.issuer || '').toLowerCase();
          const account = (e.account || '').toLowerCase();
          return issuer.includes(query) || account.includes(query);
        })
      : [...entries];
    return matched.sort((a, b) =>
      (a.issuer || a.account || '')
        .toLowerCase()
        .localeCompare((b.issuer || b.account || '').toLowerCase())
    );
  }

  function updateVaultCount(): void {
    const parts: string[] = [];
    if (allPasskeys.length > 0) {
      parts.push(formatCount('popupPasskeyCount', allPasskeys.length));
    }
    if (allTotpEntries.length > 0) {
      parts.push(formatCount('popupTotpCount', allTotpEntries.length));
    }
    passkeyCountEl.textContent = parts.length
      ? parts.join(' · ')
      : formatCount('popupPasskeyCount', 0);
  }

  // Render the unified list from current data, search query, and filters.
  function renderVault(): void {
    if (!vaultListEl) return;
    updateVaultCount();

    const query = searchInput.value.trim().toLowerCase();
    const totalStored = allPasskeys.length + allTotpEntries.length;

    // Vault has nothing at all → onboarding empty state
    if (totalStored === 0) {
      emptyStateEl.style.display = 'block';
      noResultsEl.hidden = true;
      vaultListEl.style.display = 'none';
      vaultListEl.innerHTML = '';
      return;
    }
    emptyStateEl.style.display = 'none';

    const visibleTotp = filters.totp ? filterTotpEntries(allTotpEntries, query) : [];
    const visiblePasskeys = filters.passkeys
      ? query
        ? filterAndSortPasskeys(allPasskeys, query)
        : [...allPasskeys].sort((a, b) => getCreatedAtTimestamp(b) - getCreatedAtTimestamp(a))
      : [];

    if (visibleTotp.length === 0 && visiblePasskeys.length === 0) {
      vaultListEl.style.display = 'none';
      vaultListEl.innerHTML = '';
      noResultsTextEl.textContent = query
        ? t('popupNoResults', { query })
        : t('popupFilterAllHidden');
      noResultsEl.hidden = false;
      return;
    }
    noResultsEl.hidden = true;

    // 2FA codes first (time-sensitive), then passkeys
    vaultListEl.innerHTML = '';
    for (const entry of visibleTotp) {
      vaultListEl.appendChild(createTotpItem(entry));
    }
    for (const passkey of visiblePasskeys) {
      vaultListEl.appendChild(createPasskeyItem(passkey));
    }
    vaultListEl.style.display = 'flex';
    refreshTotpCodes();
  }

  function createPasskeyItem(passkey: PopupPasskey): HTMLElement {
    const div = document.createElement('div');
    div.className = 'passkey-item vault-item';

    const createdAt = passkey.createdAt ? new Date(passkey.createdAt) : null;
    const dateStr = createdAt
      ? createdAt.toLocaleDateString() +
        ' ' +
        createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : t('commonUnknown');

    const credentialIdShort = passkey.id ? passkey.id.substring(0, 20) + '...' : t('commonUnknown');

    div.innerHTML = `
      <div class="vault-item-icon vault-item-icon--passkey" title="${popupEscapeHtml(t('popupTabPasskeys'))}">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="7.5" cy="15.5" r="4.5"></circle>
          <path d="m10.7 12.3 8.3-8.3"></path>
          <path d="m17 6 2 2"></path>
          <path d="m13 10 2 2"></path>
        </svg>
      </div>
      <div class="vault-item-body">
      <div class="passkey-header">
        <div class="passkey-info">
          <div class="passkey-rp">${popupEscapeHtml(passkey.rpId || t('commonUnknownSite'))}</div>
          ${passkey.user?.name ? `<div class="passkey-username">${popupEscapeHtml(passkey.user.name)}</div>` : ''}
        </div>
        <div class="passkey-actions">
          <button class="copy-btn" title="${popupEscapeHtml(t('popupCopyClipboard'))}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2"></rect>
              <rect x="3" y="3" width="13" height="13" rx="2"></rect>
            </svg>
          </button>
          <button class="expand-btn" title="${popupEscapeHtml(t('popupDetails'))}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
          </button>
          <button class="delete-btn" data-id="${popupEscapeHtml(passkey.id)}">${t('popupDel')}</button>
        </div>
      </div>
      <div class="passkey-details">
        <div class="passkey-detail-row">
          <span class="label">${t('popupAdded')}</span>
          <span class="value">${popupEscapeHtml(dateStr)}</span>
        </div>
        <div class="passkey-detail-row">
          <span class="label">${t('popupKeyId')}</span>
          <span class="value">${popupEscapeHtml(credentialIdShort)}</span>
        </div>
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
      deletePasskey(passkey.id, passkey.rpId || t('commonUnknownSite'));
    });

    return div;
  }

  async function copyPasskeyToClipboard(
    passkey: PopupPasskey,
    btn: HTMLButtonElement
  ): Promise<void> {
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
      showNotification(t('popupFailedCopy'), 'error');
    }
  }

  async function deletePasskey(credentialId: string, siteName: string): Promise<void> {
    const confirmed = await showConfirmModal(
      t('popupDeletePasskeyTitle'),
      t('popupDeletePasskeyMessage', { site: siteName }),
      t('commonDelete'),
      true
    );

    if (!confirmed) {
      return;
    }

    try {
      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys = (result[POPUP_PASSKEY_STORAGE_KEY] || []) as PopupPasskey[];

      const filtered = passkeys.filter((p) => p.id !== credentialId);

      if (filtered.length < passkeys.length) {
        await chrome.storage.local.set({ [POPUP_PASSKEY_STORAGE_KEY]: filtered });

        showNotification(t('popupPasskeyDeleted'));

        await loadVault();
      } else {
        showNotification(t('popupPasskeyNotFound'), 'error');
      }
    } catch (error) {
      console.error('Error deleting passkey:', error);
      showNotification(t('popupFailedDelete'), 'error');
    }
  }

  async function exportPasskeysFull(): Promise<void> {
    const password = await showPasswordPrompt(
      t('popupEncryptBackup'),
      t('popupEncryptBackupMessage')
    );
    if (password === null) return;

    try {
      const result = await chrome.storage.local.get(POPUP_PASSKEY_STORAGE_KEY);
      const passkeys = (result[POPUP_PASSKEY_STORAGE_KEY] || []) as PopupPasskey[];

      if (passkeys.length === 0) {
        showNotification(t('popupNoPasskeysExport'), 'error');
        return;
      }

      const totpResult = await chrome.storage.local.get('totp_entries');
      const totpEntries = (totpResult['totp_entries'] || []) as unknown[];

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
        totpEntries,
      };

      const plaintext = JSON.stringify(exportData);

      const encResponse = await chrome.runtime.sendMessage({
        type: 'ENCRYPT_BACKUP',
        payload: { data: plaintext, password },
      });

      if (!encResponse.success) {
        showNotification(t('popupEncryptionFailed', { error: encResponse.error }), 'error');
        return;
      }

      const encryptedBackup = {
        encrypted: true,
        version: EXPORT_VERSION,
        exportedAt: new Date().toISOString(),
        passkeyCount: passkeys.length,
        totpCount: totpEntries.length,
        data: encResponse.encrypted.data,
        iv: encResponse.encrypted.iv,
        salt: encResponse.encrypted.salt,
        algorithm: encResponse.encrypted.algorithm,
      };

      downloadJson(encryptedBackup, `passkey-vault-backup-${getDateString()}.json`);
      showNotification(t('popupExportedPasskeys', { count: passkeys.length + totpEntries.length }));
    } catch (error) {
      console.error('Error exporting passkeys:', error);
      showNotification(t('popupFailedExport'), 'error');
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
          <input type="password" id="prompt-password" placeholder="${popupEscapeHtml(t('popupPromptPasswordPlaceholder'))}"
            style="width: 100%; padding: 8px; border: 1px solid #333; background: #1a1a1a; color: #fff; border-radius: 4px; font-size: 13px; box-sizing: border-box; margin-bottom: 8px" />
          <input type="password" id="prompt-password-confirm" placeholder="${popupEscapeHtml(t('popupConfirmPasswordPlaceholder'))}"
            style="width: 100%; padding: 8px; border: 1px solid #333; background: #1a1a1a; color: #fff; border-radius: 4px; font-size: 13px; box-sizing: border-box; margin-bottom: 4px" />
          <div id="prompt-error" style="color: #ef4444; font-size: 12px; margin-bottom: 8px; display: none"></div>
          <div class="modal-actions">
            <button class="btn btn-secondary" id="prompt-cancel">${t('commonCancel')}</button>
            <button class="btn btn-primary" id="prompt-ok">${t('popupEncryptAndExport')}</button>
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
          errorEl.textContent = t('popupPasswordMin');
          errorEl.style.display = 'block';
          return;
        }
        if (pw !== confirm) {
          errorEl.textContent = t('popupPasswordsNoMatch');
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

  function downloadJson(data: unknown, filename: string): void {
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

  // ==================== TOTP ====================

  function createTotpItem(entry: PopupTotpEntry): HTMLElement {
    const div = document.createElement('div');
    div.className = 'totp-item vault-item';
    div.dataset.id = entry.id;
    const issuerLabel = entry.issuer || entry.account || t('commonUnknown');
    const accountLabel = entry.account && entry.issuer ? entry.account : '';

    div.innerHTML = `
      <div class="vault-item-icon vault-item-icon--totp" title="${popupEscapeHtml(t('popupTabTotp'))}">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <polyline points="12 6 12 12 16 14"></polyline>
        </svg>
      </div>
      <div class="vault-item-body">
        <div class="totp-row">
          <div class="totp-info">
            <div class="totp-issuer">${popupEscapeHtml(issuerLabel)}</div>
            ${accountLabel ? `<div class="totp-account">${popupEscapeHtml(accountLabel)}</div>` : ''}
          </div>
          <div class="totp-code-wrap">
            <div class="totp-code" data-id="${popupEscapeHtml(entry.id)}" title="${popupEscapeHtml(t('popupTotpClickToCopy'))}">••••••</div>
            <button class="totp-copy-btn" data-id="${popupEscapeHtml(entry.id)}" title="${popupEscapeHtml(t('commonCopy'))}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2"></rect>
                <rect x="3" y="3" width="13" height="13" rx="2"></rect>
              </svg>
            </button>
            <button class="totp-delete" data-id="${popupEscapeHtml(entry.id)}" title="${popupEscapeHtml(t('commonDelete'))}">×</button>
          </div>
        </div>
        <div class="totp-progress-track">
          <div class="totp-progress"></div>
        </div>
      </div>
    `;

    const codeEl = div.querySelector('.totp-code') as HTMLElement;
    codeEl.addEventListener('click', () => copyCodeToClipboard(entry.id, codeEl));

    const copyBtn = div.querySelector('.totp-copy-btn') as HTMLButtonElement;
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyCodeToClipboard(entry.id, codeEl, copyBtn);
    });

    const deleteBtn = div.querySelector('.totp-delete') as HTMLButtonElement;
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteTotpEntry(entry);
    });

    return div;
  }

  async function refreshTotpCodes(): Promise<void> {
    if (!filters.totp || allTotpEntries.length === 0) return;
    const now = Date.now();
    for (const entry of allTotpEntries) {
      const period = entry.period || 30;
      const expiresAt = Math.ceil(now / (period * 1000)) * (period * 1000);
      const cached = codeCache.get(entry.id);
      if (cached && cached.expiresAt === expiresAt) {
        paintCode(entry, cached.code, now);
        continue;
      }
      try {
        const response = await chrome.runtime.sendMessage({
          type: 'GENERATE_TOTP_CODE',
          payload: { id: entry.id, timestamp: now },
        });
        if (response?.success) {
          codeCache.set(entry.id, { code: response.code, expiresAt });
          paintCode(entry, response.code, now);
        } else {
          paintCodeError(entry);
        }
      } catch (error) {
        console.error('Failed to generate code:', error);
        paintCodeError(entry);
      }
    }
  }

  function paintCode(entry: PopupTotpEntry, code: string, now: number): void {
    const el = vaultListEl.querySelector(
      `.totp-code[data-id="${CSS.escape(entry.id)}"]`
    ) as HTMLElement | null;
    if (!el) return;
    el.textContent = formatCodeDisplay(code, entry.digits);
    const period = entry.period || 30;
    const remaining = period - (Math.floor(now / 1000) % period);
    el.classList.remove('expiring', 'expired');
    const progress = vaultListEl.querySelector(
      `.totp-item[data-id="${CSS.escape(entry.id)}"] .totp-progress`
    ) as HTMLElement | null;
    if (progress) {
      progress.style.width = `${(remaining / period) * 100}%`;
      progress.classList.remove('expiring', 'expired');
      if (remaining <= 3) {
        el.classList.add('expiring');
        progress.classList.add('expiring');
      }
      if (remaining <= 0) {
        el.classList.add('expired');
        progress.classList.add('expired');
      }
    }
  }

  function paintCodeError(entry: PopupTotpEntry): void {
    const el = vaultListEl.querySelector(
      `.totp-code[data-id="${CSS.escape(entry.id)}"]`
    ) as HTMLElement | null;
    if (el) el.textContent = '------';
  }

  function formatCodeDisplay(code: string, digits: number): string {
    if (digits === 6) {
      return `${code.slice(0, 3)} ${code.slice(3)}`;
    }
    if (digits === 8) {
      return `${code.slice(0, 4)} ${code.slice(4)}`;
    }
    return code;
  }

  function startTotpTicker(): void {
    if (totpTickInterval) return;
    totpTickInterval = window.setInterval(() => {
      if (filters.totp && allTotpEntries.length > 0) {
        refreshTotpCodes();
      }
    }, 1000);
  }

  async function copyCodeToClipboard(
    id: string,
    codeEl: HTMLElement,
    btnEl?: HTMLButtonElement
  ): Promise<void> {
    let code: string | undefined;
    const cached = codeCache.get(id);
    if (cached && cached.expiresAt > Date.now()) {
      code = cached.code;
    } else {
      const response = await chrome.runtime.sendMessage({
        type: 'GENERATE_TOTP_CODE',
        payload: { id, timestamp: Date.now() },
      });
      if (response?.success) {
        code = response.code;
      }
    }
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code);
      const target = btnEl || codeEl;
      target.classList.add('copied');
      setTimeout(() => target.classList.remove('copied'), 1200);
    } catch (error) {
      console.error('Clipboard copy failed:', error);
      showNotification(t('popupFailedCopy'), 'error');
    }
  }

  async function deleteTotpEntry(entry: PopupTotpEntry): Promise<void> {
    const label = entry.issuer || entry.account || t('commonUnknown');
    const confirmed = await showConfirmModal(
      t('popupDeleteTotpTitle'),
      t('popupDeleteTotpMessage', { issuer: label }),
      t('commonDelete'),
      true
    );
    if (!confirmed) return;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'DELETE_TOTP_ENTRY',
        payload: { id: entry.id },
      });
      if (response.success) {
        codeCache.delete(entry.id);
        showNotification(t('popupTotpDeleted'));
        await loadVault();
      } else {
        showNotification(response.error || t('popupFailedDelete'), 'error');
      }
    } catch (error) {
      console.error('Failed to delete TOTP entry:', error);
      showNotification(t('popupFailedDelete'), 'error');
    }
  }

  // Decode a QR code from an image blob (pasted screenshot or uploaded file).
  // Returns the embedded text (an otpauth:// URI for authenticator QR codes),
  // or null if no QR code was found.
  async function decodeQrFromBlob(blob: Blob): Promise<string | null> {
    const bitmap = await createImageBitmap(blob);
    try {
      const canvas = document.createElement('canvas');
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;
      ctx.drawImage(bitmap, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const result = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth',
      });
      return result?.data ?? null;
    } finally {
      bitmap.close();
    }
  }

  function showAddTotpDialog(): void {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-content" style="max-width: 360px">
        <h3 class="modal-title">${popupEscapeHtml(t('popupAddTotpTitle'))}</h3>
        <p class="modal-message">${popupEscapeHtml(t('popupAddTotpHelp'))}</p>
        <textarea id="totp-uri-input" rows="3" placeholder="otpauth://totp/..."
          style="width: 100%; padding: 8px; border: 1px solid var(--border); background: var(--bg-elev); color: var(--text); border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 12px; box-sizing: border-box; resize: vertical"></textarea>
        <div class="totp-uri-import">
          <button type="button" class="btn btn-secondary" id="totp-upload-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
              <circle cx="8.5" cy="8.5" r="1.5"></circle>
              <polyline points="21 15 16 10 5 21"></polyline>
            </svg>
            <span>${popupEscapeHtml(t('popupTotpChooseImage'))}</span>
          </button>
          <input type="file" id="totp-image-input" accept="image/*" hidden />
        </div>
        <p class="totp-import-hint">${popupEscapeHtml(t('popupTotpImportHint'))}</p>
        <div id="totp-add-error" style="color: var(--danger); font-size: 12px; margin: 6px 0; display: none"></div>
        <div class="modal-actions">
          <button class="btn btn-secondary" id="totp-add-cancel">${popupEscapeHtml(t('commonCancel'))}</button>
          <button class="btn btn-primary" id="totp-add-save">${popupEscapeHtml(t('commonAdd'))}</button>
        </div>
      </div>
    `;
    overlay.style.display = 'flex';
    document.body.appendChild(overlay);

    const input = overlay.querySelector('#totp-uri-input') as HTMLTextAreaElement;
    const errorEl = overlay.querySelector('#totp-add-error') as HTMLElement;
    const saveBtn = overlay.querySelector('#totp-add-save') as HTMLButtonElement;
    const cancelBtn = overlay.querySelector('#totp-add-cancel') as HTMLButtonElement;
    const uploadBtn = overlay.querySelector('#totp-upload-btn') as HTMLButtonElement;
    const imageInput = overlay.querySelector('#totp-image-input') as HTMLInputElement;

    input.focus();

    const showError = (msg: string) => {
      errorEl.textContent = msg;
      errorEl.style.display = 'block';
    };

    const fillFromImage = async (blob: Blob) => {
      errorEl.style.display = 'none';
      try {
        const uri = await decodeQrFromBlob(blob);
        if (!uri) {
          showError(t('popupTotpNoQrFound'));
          return;
        }
        input.value = uri.trim();
      } catch (error) {
        console.error('QR decode failed:', error);
        showError(t('popupTotpDecodeFailed'));
      }
    };

    uploadBtn.addEventListener('click', () => imageInput.click());
    imageInput.addEventListener('change', () => {
      const file = imageInput.files?.[0];
      if (file) fillFromImage(file);
    });

    const onPaste = (e: ClipboardEvent) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (const item of items) {
        if (item.kind === 'file' && item.type.startsWith('image/')) {
          const file = item.getAsFile();
          if (file) {
            e.preventDefault();
            fillFromImage(file);
            return;
          }
        }
      }
    };
    overlay.addEventListener('paste', onPaste);

    const cleanup = () => {
      overlay.removeEventListener('paste', onPaste);
      overlay.remove();
    };

    saveBtn.addEventListener('click', async () => {
      const uri = input.value.trim();
      if (!uri) {
        errorEl.textContent = t('popupTotpUriRequired');
        errorEl.style.display = 'block';
        return;
      }
      saveBtn.disabled = true;
      const response = await chrome.runtime.sendMessage({
        type: 'ADD_TOTP_ENTRY',
        payload: { otpauthUri: uri },
      });
      if (response.success) {
        codeCache.clear();
        showNotification(t('popupTotpAdded'));
        cleanup();
        await loadVault();
      } else {
        errorEl.textContent = response.error || t('popupTotpAddFailed');
        errorEl.style.display = 'block';
        saveBtn.disabled = false;
      }
    });

    cancelBtn.addEventListener('click', cleanup);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) cleanup();
    });
  }
})();
