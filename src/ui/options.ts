// PassKey Vault — Options Page

import {
  SUPPORTED_LANGUAGES,
  getStoredLanguage,
  initAndLocalize,
  setStoredLanguage,
  t,
} from '../i18n';
import { SUPPORTED_THEMES, getStoredTheme, initTheme, setStoredTheme } from '../theme';

const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.nostr.band'];

interface DomainRules {
  mode: 'disabled' | 'all' | 'allowlist' | 'blocklist';
  domains: string[];
}

interface SyncStatusResponse {
  enabled: boolean;
  connectionStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  lastSyncAttempt: number | null;
  lastSyncSuccess: number | null;
  pendingChanges: number;
  localPasskeyCount: number;
  syncedPasskeyCount: number;
  lastError: string | null;
}

interface DebugLogEntry {
  timestamp: number;
  level: 'info' | 'warn' | 'error' | 'debug';
  category: string;
  message: string;
  data?: unknown;
}

// ==================== INIT ====================

document.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([initAndLocalize(), initTheme()]);
  setupNavigation();
  await setupGeneralSettings();
  loadInterceptionSettings();
  loadSyncSettings();
  loadSecuritySettings();
  loadDeveloperSettings();
  loadExtensionInfo();
});

// ==================== GENERAL ====================

async function setupGeneralSettings(): Promise<void> {
  await Promise.all([setupLanguageSettings(), setupThemeSettings()]);
}

async function setupLanguageSettings(): Promise<void> {
  const select = document.getElementById('language-select') as HTMLSelectElement | null;
  if (!select) return;

  const storedLanguage = await getStoredLanguage();
  select.innerHTML = SUPPORTED_LANGUAGES.map(
    (language) => `<option value="${language.code}">${language.label}</option>`
  ).join('');
  select.value = storedLanguage;

  select.addEventListener('change', async () => {
    await setStoredLanguage(select.value as (typeof SUPPORTED_LANGUAGES)[number]['code']);
    select.disabled = true;
    const hint = select
      .closest('.card')
      ?.querySelector('.card-hint:last-child') as HTMLElement | null;
    if (hint) hint.textContent = t('optionsLanguageSaved');
    window.setTimeout(() => window.location.reload(), 300);
  });
}

async function setupThemeSettings(): Promise<void> {
  const select = document.getElementById('theme-select') as HTMLSelectElement | null;
  if (!select) return;

  const storedTheme = await getStoredTheme();
  select.innerHTML = SUPPORTED_THEMES.map(
    (theme) => `<option value="${theme.code}">${t(theme.labelKey)}</option>`
  ).join('');
  select.value = storedTheme;

  select.addEventListener('change', async () => {
    await setStoredTheme(select.value as (typeof SUPPORTED_THEMES)[number]['code']);
  });
}

// ==================== NAVIGATION ====================

function setupNavigation(): void {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      const section = item.getAttribute('data-section');
      if (!section) return;

      navItems.forEach((n) => n.classList.remove('active'));
      item.classList.add('active');

      document.querySelectorAll('.section').forEach((s) => s.classList.remove('active'));
      document.getElementById(`section-${section}`)?.classList.add('active');
    });
  });
}

// ==================== INTERCEPTION ====================

async function loadInterceptionSettings(): Promise<void> {
  const result = await chrome.storage.local.get('domain_rules');
  const rules: DomainRules = result.domain_rules || { mode: 'all', domains: [] };

  // Set radio
  const radio = document.querySelector(
    `input[name="interception-mode"][value="${rules.mode}"]`
  ) as HTMLInputElement | null;
  if (radio) radio.checked = true;

  updateDomainListVisibility(rules.mode);
  renderDomainList(rules.domains);

  // Mode change
  document.querySelectorAll('input[name="interception-mode"]').forEach((input) => {
    input.addEventListener('change', async (e) => {
      const mode = (e.target as HTMLInputElement).value as DomainRules['mode'];
      const current = await chrome.storage.local.get('domain_rules');
      const updated: DomainRules = { ...(current.domain_rules || { domains: [] }), mode };
      await chrome.storage.local.set({ domain_rules: updated });
      updateDomainListVisibility(mode);
    });
  });

  // Add domain
  const addBtn = document.getElementById('add-domain-btn')!;
  const domainInput = document.getElementById('domain-input') as HTMLInputElement;

  addBtn.addEventListener('click', () => addDomain(domainInput));
  domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addDomain(domainInput);
  });
}

function updateDomainListVisibility(mode: string): void {
  const card = document.getElementById('domain-list-card')!;
  const title = document.getElementById('domain-list-title')!;

  if (mode === 'allowlist' || mode === 'blocklist') {
    card.style.display = 'block';
    title.textContent =
      mode === 'allowlist' ? t('optionsAllowedDomains') : t('optionsBlockedDomains');
  } else {
    card.style.display = 'none';
  }
}

async function addDomain(input: HTMLInputElement): Promise<void> {
  const domain = input.value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
  if (!domain) return;

  const result = await chrome.storage.local.get('domain_rules');
  const rules: DomainRules = result.domain_rules || { mode: 'all', domains: [] };

  if (rules.domains.includes(domain)) {
    input.value = '';
    return;
  }

  rules.domains.push(domain);
  await chrome.storage.local.set({ domain_rules: rules });
  input.value = '';
  renderDomainList(rules.domains);
}

async function removeDomain(domain: string): Promise<void> {
  const result = await chrome.storage.local.get('domain_rules');
  const rules: DomainRules = result.domain_rules || { mode: 'all', domains: [] };
  rules.domains = rules.domains.filter((d) => d !== domain);
  await chrome.storage.local.set({ domain_rules: rules });
  renderDomainList(rules.domains);
}

function renderDomainList(domains: string[]): void {
  const list = document.getElementById('domain-list')!;
  const empty = document.getElementById('domain-empty')!;

  if (domains.length === 0) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }

  empty.style.display = 'none';
  list.innerHTML = domains
    .map(
      (d) => `
    <div class="domain-item">
      <span>${escapeHtml(d)}</span>
      <button data-domain="${escapeHtml(d)}" title="Remove">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
        </svg>
      </button>
    </div>`
    )
    .join('');

  list.querySelectorAll('button[data-domain]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const domain = btn.getAttribute('data-domain')!;
      removeDomain(domain);
    });
  });
}

// ==================== SYNC ====================

async function loadSyncSettings(): Promise<void> {
  const response = await sendMessage('GET_SYNC_STATUS');
  const notConfigured = document.getElementById('sync-not-configured')!;
  const configured = document.getElementById('sync-configured')!;

  if (!response.enabled) {
    notConfigured.style.display = 'block';
    configured.style.display = 'none';
    return;
  }

  notConfigured.style.display = 'none';
  configured.style.display = 'block';

  updateSyncStatus(response as SyncStatusResponse);

  // Chain info
  const chainInfo = await sendMessage('GET_SYNC_CHAIN_INFO');
  if (chainInfo.success) {
    const chainIdEl = document.getElementById('sync-chain-id')!;
    chainIdEl.textContent = chainInfo.chainId ? chainInfo.chainId.substring(0, 16) + '...' : '--';

    const deviceNameEl = document.getElementById('sync-device-name')!;
    deviceNameEl.textContent = chainInfo.deviceName || '--';

    if (chainInfo.devices) {
      renderSyncDevices(chainInfo.devices, chainInfo.deviceId);
    }
  }

  // Relays
  loadRelayList();

  // Sync now
  document.getElementById('sync-now-btn')!.addEventListener('click', async () => {
    await sendMessage('TRIGGER_SYNC');
    setTimeout(() => loadSyncSettings(), 1000);
  });
}

function updateSyncStatus(status: SyncStatusResponse): void {
  const badge = document.getElementById('sync-connection-badge')!;
  badge.textContent = status.connectionStatus;
  badge.className = 'status-badge ' + status.connectionStatus;

  setText('sync-local-count', String(status.localPasskeyCount));
  setText('sync-synced-count', String(status.syncedPasskeyCount));
  setText('sync-pending', String(status.pendingChanges));
  setText('sync-last', status.lastSyncSuccess ? timeAgo(status.lastSyncSuccess) : t('commonNever'));
}

function renderSyncDevices(
  devices: Array<{ id: string; name: string; type?: string; lastSeen?: number }>,
  currentDeviceId: string
): void {
  const list = document.getElementById('sync-devices-list')!;
  if (!devices.length) {
    list.innerHTML = `<p class="empty-hint">${t('optionsNoDevices')}</p>`;
    return;
  }

  list.innerHTML = devices
    .map((d) => {
      const isCurrent = d.id === currentDeviceId;
      return `
      <div class="device-card ${isCurrent ? 'current' : ''}">
        <svg class="device-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect width="20" height="14" x="2" y="3" rx="2"/>
          <line x1="8" x2="16" y1="21" y2="21"/>
          <line x1="12" x2="12" y1="17" y2="21"/>
        </svg>
        <div class="device-info">
          <span class="device-name">${escapeHtml(d.name || t('commonUnknown'))}</span>
          <span class="device-meta">${d.lastSeen ? timeAgo(d.lastSeen) : t('commonUnknown')}</span>
        </div>
        ${isCurrent ? `<span class="device-badge">${t('optionsThisDevice')}</span>` : ''}
      </div>`;
    })
    .join('');
}

async function loadRelayList(): Promise<void> {
  const result = await chrome.storage.local.get('custom_relays');
  const relays: string[] = result.custom_relays || DEFAULT_RELAYS;

  // Get current connected relay from debug info
  const debugInfo = await sendMessage('GET_SYNC_DEBUG_INFO');
  const currentRelay = debugInfo.debugInfo?.currentRelay || '';

  renderRelayList(relays, currentRelay);

  const addBtn = document.getElementById('add-relay-btn')!;
  const relayInput = document.getElementById('relay-input') as HTMLInputElement;

  addBtn.addEventListener('click', () => addRelay(relayInput));
  relayInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addRelay(relayInput);
  });
}

function renderRelayList(relays: string[], currentRelay: string): void {
  const list = document.getElementById('relay-list')!;
  list.innerHTML = relays
    .map(
      (url) => `
    <div class="relay-item">
      <span class="relay-status ${url === currentRelay ? 'active' : ''}"></span>
      <span class="relay-url">${escapeHtml(url)}</span>
      <button data-relay="${escapeHtml(url)}" title="Remove">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
        </svg>
      </button>
    </div>`
    )
    .join('');

  list.querySelectorAll('button[data-relay]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const relay = btn.getAttribute('data-relay')!;
      const result = await chrome.storage.local.get('custom_relays');
      const current: string[] = result.custom_relays || DEFAULT_RELAYS;
      const updated = current.filter((r) => r !== relay);
      if (updated.length === 0) return; // keep at least one
      await chrome.storage.local.set({ custom_relays: updated });
      renderRelayList(updated, currentRelay);
    });
  });
}

async function addRelay(input: HTMLInputElement): Promise<void> {
  const url = input.value.trim();
  if (!url || !url.startsWith('wss://')) return;

  const result = await chrome.storage.local.get('custom_relays');
  const relays: string[] = result.custom_relays || DEFAULT_RELAYS;

  if (relays.includes(url)) {
    input.value = '';
    return;
  }

  relays.push(url);
  await chrome.storage.local.set({ custom_relays: relays });
  input.value = '';
  renderRelayList(relays, '');
}

// ==================== SECURITY ====================

async function loadSecuritySettings(): Promise<void> {
  const response = await sendMessage('IS_SECURE_STORAGE_UNLOCKED');
  const statusEl = document.getElementById('master-pw-status')!;

  if (response.isSetup === false) {
    statusEl.textContent = t('optionsNotSet');
    statusEl.className = 'status-badge not-set';
  } else if (response.isUnlocked) {
    statusEl.textContent = t('optionsUnlocked');
    statusEl.className = 'status-badge unlocked';
  } else {
    statusEl.textContent = t('optionsLocked');
    statusEl.className = 'status-badge locked';
  }

  // Lock now
  document.getElementById('lock-now-btn')!.addEventListener('click', async () => {
    await sendMessage('LOCK_SECURE_STORAGE');
    loadSecuritySettings();
  });

  // Auto-lock timeout
  const result = await chrome.storage.local.get('auto_lock_timeout');
  const timeout = result.auto_lock_timeout ?? 30;
  const select = document.getElementById('auto-lock-timeout') as HTMLSelectElement;
  select.value = String(timeout);

  select.addEventListener('change', async () => {
    const minutes = parseInt(select.value, 10);
    await chrome.storage.local.set({ auto_lock_timeout: minutes });
    // Notify background to update the timer
    await sendMessage('SET_AUTO_LOCK_TIMEOUT', { minutes });
  });
}

// ==================== DEVELOPER ====================

async function loadDeveloperSettings(): Promise<void> {
  // Debug toggle
  const debugToggle = document.getElementById('debug-toggle') as HTMLInputElement;
  const debugResponse = await sendMessage('GET_DEBUG_LOGGING');
  debugToggle.checked = debugResponse.enabled;

  debugToggle.addEventListener('change', async () => {
    await sendMessage('SET_DEBUG_LOGGING', { enabled: debugToggle.checked });
  });

  // Storage inspector
  document.getElementById('refresh-storage-btn')!.addEventListener('click', loadStorageInspector);

  // Sync log
  document.getElementById('refresh-sync-log-btn')!.addEventListener('click', loadSyncLog);
  document.getElementById('clear-sync-log-btn')!.addEventListener('click', async () => {
    await sendMessage('CLEAR_SYNC_DEBUG_LOGS');
    loadSyncLog();
  });

  // WebAuthn log
  document.getElementById('refresh-webauthn-log-btn')!.addEventListener('click', loadWebAuthnLog);
  document.getElementById('clear-webauthn-log-btn')!.addEventListener('click', async () => {
    await chrome.storage.local.set({ webauthn_log: [] });
    loadWebAuthnLog();
  });

  // Danger zone
  document.getElementById('export-all-btn')!.addEventListener('click', exportAllData);
  document.getElementById('import-all-btn')!.addEventListener('click', () => {
    document.getElementById('import-file-input')!.click();
  });
  document.getElementById('import-file-input')!.addEventListener('change', importAllData);
  document.getElementById('clear-passkeys-btn')!.addEventListener('click', clearPasskeys);
  document.getElementById('factory-reset-btn')!.addEventListener('click', factoryReset);
}

async function loadStorageInspector(): Promise<void> {
  const container = document.getElementById('storage-inspector')!;
  const totalEl = document.getElementById('storage-total')!;

  const data = await chrome.storage.local.get(null);
  const keys = Object.keys(data).sort();
  let totalBytes = 0;

  container.innerHTML = keys
    .map((key) => {
      const json = JSON.stringify(data[key], null, 2);
      const size = new Blob([json]).size;
      totalBytes += size;
      const sizeStr = size > 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`;

      return `
      <div class="storage-key">
        <div class="storage-key-header" data-key="${escapeHtml(key)}">
          <span class="storage-key-name">${escapeHtml(key)}</span>
          <span class="storage-key-size">${sizeStr}</span>
        </div>
        <div class="storage-key-value" id="storage-val-${escapeHtml(key)}">
          <pre>${escapeHtml(json)}</pre>
        </div>
      </div>`;
    })
    .join('');

  totalEl.textContent =
    totalBytes > 1024 ? `${(totalBytes / 1024).toFixed(1)} KB total` : `${totalBytes} B total`;

  // Toggle expand
  container.querySelectorAll('.storage-key-header').forEach((header) => {
    header.addEventListener('click', () => {
      const key = header.getAttribute('data-key')!;
      const valueEl = document.getElementById(`storage-val-${key}`)!;
      valueEl.classList.toggle('open');
    });
  });
}

async function loadSyncLog(): Promise<void> {
  const container = document.getElementById('sync-log')!;
  const response = await sendMessage('GET_SYNC_DEBUG_LOGS');

  if (!response.logs || response.logs.length === 0) {
    container.innerHTML = `<p class="empty-hint">${t('optionsNoSyncLogs')}</p>`;
    return;
  }

  const logs: DebugLogEntry[] = response.logs.slice(-100).reverse();
  container.innerHTML = logs
    .map(
      (entry) => `
    <div class="log-entry ${entry.level}">
      <span class="log-time">${formatTime(entry.timestamp)}</span>
      <span class="log-category">[${escapeHtml(entry.category)}]</span>
      <span class="log-message">${escapeHtml(entry.message)}${
        entry.data ? ' ' + escapeHtml(JSON.stringify(entry.data)) : ''
      }</span>
    </div>`
    )
    .join('');
}

async function loadWebAuthnLog(): Promise<void> {
  const container = document.getElementById('webauthn-log')!;
  const result = await chrome.storage.local.get('webauthn_log');
  const logs: DebugLogEntry[] = (result.webauthn_log || []).slice(-100).reverse();

  if (logs.length === 0) {
    container.innerHTML = `<p class="empty-hint">${t('optionsNoWebAuthnLogs')}</p>`;
    return;
  }

  container.innerHTML = logs
    .map(
      (entry) => `
    <div class="log-entry ${entry.level}">
      <span class="log-time">${formatTime(entry.timestamp)}</span>
      <span class="log-category">[${escapeHtml(entry.category)}]</span>
      <span class="log-message">${escapeHtml(entry.message)}</span>
    </div>`
    )
    .join('');
}

function loadExtensionInfo(): void {
  const manifest = chrome.runtime.getManifest();
  setText('version', `v${manifest.version_name || manifest.version}`);
  setText('ext-version', manifest.version_name || manifest.version);
  setText('ext-manifest-version', `MV${manifest.manifest_version}`);
  setText('ext-id', chrome.runtime.id);
  setText('ext-permissions', (manifest.permissions || []).join(', '));
}

// ==================== DANGER ZONE ====================

async function exportAllData(): Promise<void> {
  const data = await chrome.storage.local.get(null);
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `passkey-vault-export-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importAllData(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  if (!confirm(t('optionsImportConfirm'))) {
    input.value = '';
    return;
  }

  const text = await file.text();
  try {
    const data = JSON.parse(text);
    await chrome.storage.local.clear();
    await chrome.storage.local.set(data);
    alert(t('optionsImportSuccess'));
  } catch {
    alert(t('optionsInvalidJson'));
  }
  input.value = '';
}

async function clearPasskeys(): Promise<void> {
  if (!confirm(t('optionsClearConfirm'))) return;

  await chrome.storage.local.remove(['passkeys', 'passext_encrypted_passkeys']);
  alert(t('optionsClearSuccess'));
}

async function factoryReset(): Promise<void> {
  if (!confirm(t('optionsFactoryConfirm'))) return;
  if (!confirm(t('optionsFactoryConfirmAgain'))) return;

  await chrome.storage.local.clear();
  alert(t('optionsFactorySuccess'));
}

// ==================== HELPERS ====================

function sendMessage(
  type: string,
  payload?: Record<string, unknown>
): Promise<Record<string, unknown>> {
  return chrome.runtime.sendMessage({ type, payload });
}

function setText(id: string, text: string): void {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function escapeHtml(str: string): string {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function timeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return t('timeSecondsAgo', { count: seconds });
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return t('timeMinutesAgo', { count: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t('timeHoursAgo', { count: hours });
  const days = Math.floor(hours / 24);
  return t('timeDaysAgo', { count: days });
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
