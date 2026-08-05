// Fenko Vault — Options Page

import {
  SUPPORTED_LANGUAGES,
  getStoredLanguage,
  initAndLocalize,
  setStoredLanguage,
  t,
} from '../i18n';
import { SUPPORTED_THEMES, getStoredTheme, initTheme, setStoredTheme } from '../theme';

const DEFAULT_RELAYS = [
  'wss://vaultsync.fenko.nz',
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
];

interface DomainRules {
  mode: 'disabled' | 'all' | 'allowlist' | 'blocklist';
  domains: string[];
  passthroughOnNoPasskey?: boolean;
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

      // Re-read live state when entering the security section
      if (section === 'security') {
        refreshSecurityStatus();
      }
    });
  });
}

// ==================== INTERCEPTION ====================

async function loadInterceptionSettings(): Promise<void> {
  const result = await chrome.storage.local.get('domain_rules');
  const rules = getDomainRules(result.domain_rules);

  // Set radio
  const radio = document.querySelector(
    `input[name="interception-mode"][value="${rules.mode}"]`
  ) as HTMLInputElement | null;
  if (radio) radio.checked = true;

  const passthroughToggle = document.getElementById(
    'passthrough-missing-toggle'
  ) as HTMLInputElement | null;
  if (passthroughToggle) {
    passthroughToggle.checked = rules.passthroughOnNoPasskey !== false;
    passthroughToggle.addEventListener('change', async () => {
      const current = await chrome.storage.local.get('domain_rules');
      const updated = getDomainRules(current.domain_rules);
      updated.passthroughOnNoPasskey = passthroughToggle.checked;
      await chrome.storage.local.set({ domain_rules: updated });
    });
  }

  updateDomainListVisibility(rules.mode);
  renderDomainList(rules.domains);

  // Mode change
  document.querySelectorAll('input[name="interception-mode"]').forEach((input) => {
    input.addEventListener('change', async (e) => {
      const mode = (e.target as HTMLInputElement).value as DomainRules['mode'];
      const current = await chrome.storage.local.get('domain_rules');
      const updated: DomainRules = { ...getDomainRules(current.domain_rules), mode };
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
  const rules = getDomainRules(result.domain_rules);

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
  const rules = getDomainRules(result.domain_rules);
  rules.domains = rules.domains.filter((d) => d !== domain);
  await chrome.storage.local.set({ domain_rules: rules });
  renderDomainList(rules.domains);
}

function getDomainRules(value: unknown): DomainRules {
  const partial = (value || {}) as Partial<DomainRules>;
  return {
    mode: partial.mode || 'all',
    domains: Array.isArray(partial.domains) ? partial.domains : [],
    passthroughOnNoPasskey: partial.passthroughOnNoPasskey !== false,
  };
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
      <button data-domain="${escapeHtml(d)}" title="${escapeHtml(t('commonRemove'))}">
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

  // GET_SYNC_STATUS returns { success, status: { enabled, deviceId, ... } }.
  const status = (response.status as SyncStatusResponse & { deviceId?: string }) || undefined;

  if (!status?.enabled) {
    notConfigured.style.display = 'block';
    configured.style.display = 'none';
    const setupBtn = document.getElementById('sync-setup-btn');
    if (setupBtn && !setupBtn.dataset.wired) {
      setupBtn.dataset.wired = '1';
      setupBtn.addEventListener('click', () => {
        window.open(chrome.runtime.getURL('sync-setup.html'));
      });
    }
    return;
  }

  notConfigured.style.display = 'none';
  configured.style.display = 'block';

  updateSyncStatus(status);

  // Chain info: GET_SYNC_CHAIN_INFO returns { success, chainInfo: { id, devices } }.
  const chainResponse = await sendMessage('GET_SYNC_CHAIN_INFO');
  const chainInfo = chainResponse.chainInfo as {
    id?: string;
    devices?: Array<{ id: string; name: string; isThisDevice?: boolean; lastSeen?: number }>;
  } | null;
  if (chainResponse.success && chainInfo) {
    const chainIdEl = document.getElementById('sync-chain-id')!;
    chainIdEl.textContent = chainInfo.id ? chainInfo.id.substring(0, 16) + '...' : '--';

    const thisDevice = chainInfo.devices?.find((d) => d.isThisDevice);
    const deviceNameEl = document.getElementById('sync-device-name')!;
    deviceNameEl.textContent = thisDevice?.name || '--';

    if (chainInfo.devices) {
      renderSyncDevices(chainInfo.devices, status.deviceId || '');
    }
  }

  // Relays
  loadRelayList();

  // Sync now — guard against re-adding the listener each time this reloads.
  const syncNowBtn = document.getElementById('sync-now-btn')!;
  if (!syncNowBtn.dataset.wired) {
    syncNowBtn.dataset.wired = '1';
    syncNowBtn.addEventListener('click', async () => {
      await sendMessage('TRIGGER_SYNC');
      setTimeout(() => loadSyncSettings(), 1000);
    });
  }
}

function updateSyncStatus(status: SyncStatusResponse): void {
  const badge = document.getElementById('sync-connection-badge')!;
  badge.textContent = formatConnectionStatus(status.connectionStatus);
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

  // Mark relays with an open connection from debug info
  const debugInfo = await sendMessage('GET_SYNC_DEBUG_INFO');
  const relayStates: Array<{ url: string; state: string }> = debugInfo.debugInfo?.relays || [];
  const connectedRelays = new Set(relayStates.filter((r) => r.state === 'OPEN').map((r) => r.url));

  renderRelayList(relays, connectedRelays);

  const addBtn = document.getElementById('add-relay-btn')!;
  const relayInput = document.getElementById('relay-input') as HTMLInputElement;

  // Guard against re-adding listeners each time the relay list reloads.
  if (!addBtn.dataset.wired) {
    addBtn.dataset.wired = '1';
    addBtn.addEventListener('click', () => addRelay(relayInput));
    relayInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') addRelay(relayInput);
    });
  }
}

function renderRelayList(relays: string[], connectedRelays: Set<string>): void {
  const list = document.getElementById('relay-list')!;
  list.innerHTML = relays
    .map(
      (url) => `
    <div class="relay-item">
      <span class="relay-status ${connectedRelays.has(url) ? 'active' : ''}"></span>
      <span class="relay-url">${escapeHtml(url)}</span>
      <button data-relay="${escapeHtml(url)}" title="${escapeHtml(t('commonRemove'))}">
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
      renderRelayList(updated, connectedRelays);
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
  renderRelayList(relays, new Set());
}

// ==================== SECURITY ====================

let securityWired = false;

async function loadSecuritySettings(): Promise<void> {
  if (!securityWired) {
    securityWired = true;
    wireSecurityHandlers();
  }
  await refreshSecurityStatus();
}

async function refreshSecurityStatus(): Promise<void> {
  const response = await sendMessage('IS_SECURE_STORAGE_UNLOCKED');
  const statusEl = document.getElementById('master-pw-status')!;
  const setForm = document.getElementById('master-pw-set')!;
  const changeForm = document.getElementById('master-pw-change')!;
  const lockBtn = document.getElementById('lock-now-btn')!;

  if (response.isSetup === false) {
    statusEl.textContent = t('optionsNotSet');
    statusEl.className = 'status-badge not-set';
    setForm.hidden = false;
    changeForm.hidden = true;
  } else if (response.isUnlocked) {
    statusEl.textContent = t('optionsUnlocked');
    statusEl.className = 'status-badge unlocked';
    setForm.hidden = true;
    changeForm.hidden = false;
    lockBtn.hidden = false;
  } else {
    statusEl.textContent = t('optionsLocked');
    statusEl.className = 'status-badge locked';
    setForm.hidden = true;
    changeForm.hidden = false;
    lockBtn.hidden = true; // already locked
  }

  const result = await chrome.storage.local.get('auto_lock_timeout');
  const timeout = result.auto_lock_timeout ?? 30;
  (document.getElementById('auto-lock-timeout') as HTMLSelectElement).value = String(timeout);
}

function wireSecurityHandlers(): void {
  const val = (id: string): string => (document.getElementById(id) as HTMLInputElement).value;
  const clear = (...ids: string[]) =>
    ids.forEach((id) => ((document.getElementById(id) as HTMLInputElement).value = ''));
  const showErr = (id: string, msg: string) => {
    const el = document.getElementById(id)!;
    el.textContent = msg;
    el.hidden = false;
  };
  const hideErr = (id: string) => {
    document.getElementById(id)!.hidden = true;
  };

  // Set a new master password (when none exists)
  document.getElementById('set-pw-btn')!.addEventListener('click', async () => {
    hideErr('set-pw-error');
    const pw = val('set-pw');
    if (!/^\d{4,12}$/.test(pw)) {
      showErr('set-pw-error', t('optionsPasswordMin'));
      return;
    }
    if (pw !== val('set-pw-confirm')) {
      showErr('set-pw-error', t('optionsPasswordsNoMatch'));
      return;
    }
    const resp = await sendMessage('SETUP_MASTER_PASSWORD', { password: pw });
    if (resp.success) {
      clear('set-pw', 'set-pw-confirm');
      await chrome.storage.local.remove('master_password_setup_skipped');
      await refreshSecurityStatus();
    } else {
      showErr('set-pw-error', (resp.error as string) || t('optionsSetupFailed'));
    }
  });

  // Change the existing master password
  document.getElementById('change-pw-btn')!.addEventListener('click', async () => {
    hideErr('change-pw-error');
    const next = val('change-pw-new');
    if (!/^\d{4,12}$/.test(next)) {
      showErr('change-pw-error', t('optionsPasswordMin'));
      return;
    }
    if (next !== val('change-pw-confirm')) {
      showErr('change-pw-error', t('optionsPasswordsNoMatch'));
      return;
    }
    const resp = await sendMessage('CHANGE_MASTER_PASSWORD', {
      currentPassword: val('change-pw-current'),
      newPassword: next,
    });
    if (resp.success) {
      clear('change-pw-current', 'change-pw-new', 'change-pw-confirm');
      await refreshSecurityStatus();
    } else {
      showErr('change-pw-error', (resp.error as string) || t('optionsWrongPassword'));
    }
  });

  // Remove the master PIN entirely (requires the current PIN)
  document.getElementById('remove-pw-btn')!.addEventListener('click', async () => {
    hideErr('change-pw-error');
    const current = val('change-pw-current');
    if (!current) {
      showErr('change-pw-error', t('optionsRemoveNeedsCurrent'));
      return;
    }
    if (!window.confirm(t('optionsRemoveConfirm'))) {
      return;
    }
    const resp = await sendMessage('REMOVE_MASTER_PASSWORD', { currentPassword: current });
    if (resp.success) {
      clear('change-pw-current', 'change-pw-new', 'change-pw-confirm');
      // Don't nag to set one up again on the popup
      await chrome.storage.local.set({ master_password_setup_skipped: true });
      await refreshSecurityStatus();
    } else {
      showErr('change-pw-error', (resp.error as string) || t('optionsWrongPassword'));
    }
  });

  // Lock now
  document.getElementById('lock-now-btn')!.addEventListener('click', async () => {
    await sendMessage('LOCK_SECURE_STORAGE');
    await refreshSecurityStatus();
  });

  // Auto-lock timeout
  const select = document.getElementById('auto-lock-timeout') as HTMLSelectElement;
  select.addEventListener('change', async () => {
    const minutes = parseInt(select.value, 10);
    await chrome.storage.local.set({ auto_lock_timeout: minutes });
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
      const sizeStr = formatStorageSize(size);

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

  totalEl.textContent = formatStorageSize(totalBytes, true);

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
  setText('about-version', `v${manifest.version_name || manifest.version}`);
  setText('ext-version', manifest.version_name || manifest.version);
  setText('ext-manifest-version', `MV${manifest.manifest_version}`);
  setText('ext-id', chrome.runtime.id);
  setText('ext-permissions', (manifest.permissions || []).join(', '));
}

// ==================== DANGER ZONE ====================

async function exportAllData(): Promise<void> {
  const response = await sendMessage('EXPORT_VAULT');
  if (!response.success) {
    alert(String(response.error || 'Unlock the vault before exporting it.'));
    return;
  }
  const json = JSON.stringify(response, null, 2);
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
    // Validate BEFORE wiping anything — a parseable but non-object file (or a
    // failed set) must not leave the vault cleared with nothing restored.
    if (typeof data !== 'object' || data === null || Array.isArray(data)) {
      alert(t('optionsInvalidJson'));
      input.value = '';
      return;
    }
    if (!Array.isArray(data.passkeys)) {
      alert('Use the dedicated Vault Import page for this backup format.');
      input.value = '';
      return;
    }
    const result = await sendMessage('IMPORT_VAULT', {
      passkeys: data.passkeys as unknown as Record<string, unknown>,
      totpEntries: Array.isArray(data.totpEntries)
        ? (data.totpEntries as unknown as Record<string, unknown>)
        : [],
    });
    if (!result.success) throw new Error(String(result.error || 'Import failed'));
    alert(t('optionsImportSuccess'));
  } catch {
    alert(t('optionsInvalidJson'));
  }
  input.value = '';
}

async function clearPasskeys(): Promise<void> {
  if (!confirm(t('optionsClearConfirm'))) return;

  const result = await sendMessage('CLEAR_VAULT');
  if (!result.success) {
    alert(String(result.error || 'Unlock the vault before clearing it.'));
    return;
  }
  alert(t('optionsClearSuccess'));
}

async function factoryReset(): Promise<void> {
  if (!confirm(t('optionsFactoryConfirm'))) return;
  if (!confirm(t('optionsFactoryConfirmAgain'))) return;

  const result = await sendMessage('FACTORY_RESET');
  if (!result.success) {
    alert(String(result.error || 'Factory reset failed.'));
    return;
  }
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
  return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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

function formatConnectionStatus(status: string): string {
  const statusMap: Record<string, string> = {
    disconnected: t('syncDisconnected'),
    connecting: t('syncConnecting'),
    connected: t('syncConnected'),
    error: t('syncError'),
  };
  return statusMap[status] || status;
}

function formatStorageSize(bytes: number, total = false): string {
  if (bytes > 1024) {
    const kb = (bytes / 1024).toFixed(1);
    return t(total ? 'optionsStorageKilobytesTotal' : 'optionsStorageKilobytes', { count: kb });
  }
  return t(total ? 'optionsStorageBytesTotal' : 'optionsStorageBytes', { count: bytes });
}
