import { SyncDevice } from '../types';

const STORAGE_KEY = 'sync_config';

interface SyncConfig {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  seedHash: string | null;
}

interface SyncStatusResponse {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  lastSyncAttempt: number | null;
  lastSyncSuccess: number | null;
  pendingChanges: number;
  connectionStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  lastError: string | null;
  localPasskeyCount: number;
  syncedPasskeyCount: number;
}

interface DebugLogEntry {
  timestamp: number;
  level: 'info' | 'warn' | 'error' | 'debug';
  category: string;
  message: string;
  data?: unknown;
}

interface SyncDebugInfo {
  chainId?: string;
  deviceId?: string;
  deviceName?: string;
  seedHashPrefix?: string;
  isConnected?: boolean;
  currentRelay?: string;
  currentRelayIndex?: number;
  wsReadyState?: number;
  subId?: string;
  hasEncryptionKey?: boolean;
  hasSigningKey?: boolean;
  logsCount?: number;
}

let autoRefreshInterval: ReturnType<typeof setInterval> | null = null;

document.addEventListener('DOMContentLoaded', () => {
  loadSyncConfig();
  setupEventListeners();
  setupTabNavigation();

  // Auto-refresh sync status every 10s while on the status tab
  autoRefreshInterval = setInterval(() => {
    const statusTab = document.querySelector('[data-tab="status"].active');
    if (statusTab) {
      loadSyncStatus();
    }
  }, 10000);
});

function setupTabNavigation(): void {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const tabName = (btn as HTMLElement).dataset.tab;
      if (!tabName) return;

      // Update active button
      tabBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');

      // Update active content
      document.querySelectorAll('.tab-content').forEach((content) => {
        content.classList.remove('active');
      });
      const tabContent = document.getElementById(`tab-${tabName}`);
      if (tabContent) {
        tabContent.classList.add('active');
      }

      // Load debug data when switching to debug tab
      if (tabName === 'debug') {
        loadDebugInfo();
        startAutoRefresh();
      } else {
        stopAutoRefresh();
      }

      // Load devices when switching to devices tab
      if (tabName === 'devices') {
        loadDevicesList();
      }
    });
  });
}

function startAutoRefresh(): void {
  stopAutoRefresh();
  autoRefreshInterval = setInterval(() => {
    loadDebugInfo();
  }, 2000);
}

function stopAutoRefresh(): void {
  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
    autoRefreshInterval = null;
  }
}

function setupEventListeners(): void {
  const backBtn = document.getElementById('back-btn') as HTMLButtonElement;
  const addDeviceBtn = document.getElementById('add-device-btn') as HTMLButtonElement;
  const leaveChainBtn = document.getElementById('leave-chain-btn') as HTMLButtonElement;
  const setupSyncBtn = document.getElementById('setup-sync-btn') as HTMLButtonElement;
  const manualSyncBtn = document.getElementById('manual-sync-btn') as HTMLButtonElement;
  const refreshDebugBtn = document.getElementById('refresh-debug-btn') as HTMLButtonElement;
  const clearLogsBtn = document.getElementById('clear-logs-btn') as HTMLButtonElement;

  if (backBtn) {
    backBtn.addEventListener('click', () => {
      window.location.href = chrome.runtime.getURL('popup.html');
    });
  }

  if (addDeviceBtn) {
    addDeviceBtn.addEventListener('click', () => {
      window.open(chrome.runtime.getURL('sync-setup.html'));
    });
  }

  if (leaveChainBtn) {
    leaveChainBtn.addEventListener('click', confirmLeaveChain);
  }

  if (setupSyncBtn) {
    setupSyncBtn.addEventListener('click', () => {
      window.location.href = chrome.runtime.getURL('sync-setup.html');
    });
  }

  if (manualSyncBtn) {
    manualSyncBtn.addEventListener('click', triggerManualSync);
  }

  if (refreshDebugBtn) {
    refreshDebugBtn.addEventListener('click', loadDebugInfo);
  }

  if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', clearDebugLogs);
  }
}

async function confirmLeaveChain(): Promise<void> {
  const confirmed = confirm(
    'Are you sure you want to leave this sync chain?\n\n' +
      'This will:\n' +
      '• Remove this device from the sync chain\n' +
      '• Delete all synced passkeys from this device\n' +
      '• NOT affect passkeys on other devices in the chain\n\n' +
      'Make sure you have access to another device before continuing.'
  );

  if (!confirmed) return;

  try {
    const result = await chrome.runtime.sendMessage({
      type: 'LEAVE_SYNC_CHAIN',
    });

    if (result.success) {
      alert('You have left the sync chain.');
      window.location.reload();
    } else {
      alert(`Failed to leave sync chain: ${result.error}`);
    }
  } catch (error) {
    alert(`Error leaving sync chain: ${error}`);
  }
}

async function triggerManualSync(): Promise<void> {
  const btn = document.getElementById('manual-sync-btn') as HTMLButtonElement;
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Syncing...';
  }

  try {
    await chrome.runtime.sendMessage({ type: 'TRIGGER_SYNC' });
    await new Promise((resolve) => setTimeout(resolve, 1000));
    await loadSyncStatus();
  } catch (error) {
    console.error('Manual sync failed:', error);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Sync Now';
    }
  }
}

async function loadSyncConfig(): Promise<void> {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    const config = result[STORAGE_KEY] as SyncConfig | undefined;

    if (!config || !config.enabled) {
      showNotSynced();
    } else {
      showSynced(config);
    }
  } catch (error) {
    console.error('Failed to load sync config:', error);
    showNotSynced();
  }
}

function showNotSynced(): void {
  const notSyncedPanel = document.getElementById('not-synced');
  const syncedPanel = document.getElementById('synced-panel');

  if (notSyncedPanel) {
    notSyncedPanel.style.display = 'block';
  }

  if (syncedPanel) {
    syncedPanel.style.display = 'none';
  }
}

function showSynced(config: SyncConfig): void {
  const notSyncedPanel = document.getElementById('not-synced');
  const syncedPanel = document.getElementById('synced-panel');
  const chainIdEl = document.getElementById('chain-id');
  const devicesListEl = document.getElementById('devices-list');

  if (notSyncedPanel) {
    notSyncedPanel.style.display = 'none';
  }

  if (syncedPanel) {
    syncedPanel.style.display = 'block';
  }

  if (chainIdEl && config.chainId) {
    chainIdEl.textContent = config.chainId;
  }

  if (devicesListEl) {
    devicesListEl.innerHTML = '<p>Loading devices...</p>';
    loadDevicesList();
  }

  loadSyncStatus();
}

async function loadSyncStatus(): Promise<void> {
  try {
    const result = await chrome.runtime.sendMessage({ type: 'GET_SYNC_STATUS' });

    if (!result.success) {
      console.error('Failed to get sync status:', result.error);
      return;
    }

    const status: SyncStatusResponse = result.status;
    updateSyncStatusUI(status);
  } catch (error) {
    console.error('Failed to load sync status:', error);
  }
}

function updateSyncStatusUI(status: SyncStatusResponse): void {
  const connectionEl = document.getElementById('connection-status');
  const localCountEl = document.getElementById('local-count');
  const syncedCountEl = document.getElementById('synced-count');
  const pendingEl = document.getElementById('pending-changes');
  const lastSyncEl = document.getElementById('last-sync');
  const errorEl = document.getElementById('sync-error');

  if (connectionEl) {
    connectionEl.textContent = formatConnectionStatus(status.connectionStatus);
    connectionEl.className = `status-value status-${status.connectionStatus}`;
  }

  if (localCountEl) {
    localCountEl.textContent = String(status.localPasskeyCount);
  }

  if (syncedCountEl) {
    syncedCountEl.textContent = String(status.syncedPasskeyCount);
  }

  if (pendingEl) {
    pendingEl.textContent = String(status.pendingChanges);
    if (status.pendingChanges > 0) {
      pendingEl.classList.add('has-pending');
    } else {
      pendingEl.classList.remove('has-pending');
    }
  }

  if (lastSyncEl) {
    lastSyncEl.textContent = status.lastSyncSuccess
      ? formatLastSeen(status.lastSyncSuccess)
      : 'Never';
  }

  if (errorEl) {
    if (status.lastError) {
      errorEl.textContent = status.lastError;
      errorEl.style.display = 'block';
    } else {
      errorEl.style.display = 'none';
    }
  }

  // Show/hide retry button based on error state
  let retryBtn = document.getElementById('retry-sync-btn') as HTMLButtonElement | null;
  if (status.connectionStatus === 'error' || status.pendingChanges > 0) {
    if (!retryBtn) {
      retryBtn = document.createElement('button');
      retryBtn.id = 'retry-sync-btn';
      retryBtn.className = 'btn btn-primary';
      retryBtn.style.cssText = 'margin-top: 8px; width: 100%;';
      retryBtn.textContent = 'Retry Sync';
      retryBtn.addEventListener('click', async () => {
        retryBtn!.disabled = true;
        retryBtn!.textContent = 'Syncing...';
        await chrome.runtime.sendMessage({ type: 'TRIGGER_SYNC' });
        setTimeout(() => {
          loadSyncStatus();
          if (retryBtn) {
            retryBtn.disabled = false;
            retryBtn.textContent = 'Retry Sync';
          }
        }, 3000);
      });
      const statusSection = connectionEl?.closest('.status-grid') || errorEl?.parentElement;
      if (statusSection) {
        statusSection.appendChild(retryBtn);
      }
    }
  } else if (retryBtn) {
    retryBtn.remove();
  }
}

function formatConnectionStatus(status: string): string {
  const statusMap: Record<string, string> = {
    disconnected: 'Disconnected',
    connecting: 'Connecting...',
    connected: 'Connected',
    error: 'Error',
  };
  return statusMap[status] || status;
}

async function loadDevicesList(): Promise<void> {
  try {
    const result = await chrome.runtime.sendMessage({
      type: 'GET_SYNC_CHAIN_INFO',
    });

    if (result.success && result.chainInfo) {
      renderDevicesList(result.chainInfo.devices);
    } else {
      const devicesListEl = document.getElementById('devices-list');
      if (devicesListEl) {
        devicesListEl.innerHTML = '<p>Failed to load devices.</p>';
      }
    }
  } catch (error) {
    console.error('Failed to load devices:', error);
    const devicesListEl = document.getElementById('devices-list');
    if (devicesListEl) {
      devicesListEl.innerHTML = '<p>Failed to load devices.</p>';
    }
  }
}

function renderDevicesList(devices: SyncDevice[]): void {
  const devicesListEl = document.getElementById('devices-list');

  if (!devicesListEl) return;

  if (devices.length === 0) {
    devicesListEl.innerHTML = '<p>No devices in sync chain.</p>';
    return;
  }

  const listHtml = devices.map((device) => createDeviceCard(device)).join('');
  devicesListEl.innerHTML = listHtml;
}

function createDeviceCard(device: SyncDevice): string {
  const isThisDevice = device.isThisDevice;
  const deviceTypeIcon = getDeviceTypeIcon(device.deviceType);
  const lastSeenText = formatLastSeen(device.lastSeen);
  const badgeClass = isThisDevice ? 'badge this-device' : 'badge';

  return `
    <div class="device-card ${isThisDevice ? 'this-device' : ''}">
      <div class="device-header">
        <div class="device-icon">${deviceTypeIcon}</div>
        <div class="device-info">
          <div class="device-name">${escapeHtml(device.name)}</div>
          <div class="device-meta">
            <span class="device-type">${escapeHtml(device.deviceType)}</span>
            <span class="${badgeClass}">${isThisDevice ? 'This Device' : 'Other'}</span>
          </div>
        </div>
        ${
          !isThisDevice
            ? `<button class="device-remove-btn" data-device-id="${device.id}" title="Remove device">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>`
            : ''
        }
      </div>
      <div class="device-footer">
        <div class="device-status">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
            <circle cx="12" cy="12" r="6"></circle>
          </svg>
          <span>Active</span>
        </div>
        <div class="device-time">${lastSeenText}</div>
      </div>
    </div>
  `;
}

function getDeviceTypeIcon(deviceType: string): string {
  const icons: Record<string, string> = {
    desktop:
      '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>',
    laptop:
      '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"></rect><line x1="2" y1="20" x2="22" y2="20"></line></svg>',
    mobile:
      '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="7" y="2" width="10" height="20" rx="2"></rect><line x1="12" y1="18" x2="12" y2="18"></line></svg>',
    tablet:
      '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="2" width="16" height="20" rx="2"></rect><line x1="12" y1="18" x2="12" y2="18"></line></svg>',
  };

  return icons[deviceType.toLowerCase()] || icons.desktop;
}

function formatLastSeen(timestamp: number): string {
  if (!timestamp) return 'Unknown';

  const now = Date.now();
  const diff = now - timestamp;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${days}d ago`;
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function loadDebugInfo(): Promise<void> {
  const debugInfoEl = document.getElementById('debug-info');
  const debugLogsEl = document.getElementById('debug-logs');

  try {
    // Load debug info
    const infoResult = await chrome.runtime.sendMessage({ type: 'GET_SYNC_DEBUG_INFO' });
    if (debugInfoEl) {
      if (infoResult.success) {
        debugInfoEl.innerHTML = `<pre>${formatDebugInfo(infoResult.debugInfo)}</pre>`;
      } else {
        debugInfoEl.innerHTML = `<pre class="error">Error: ${infoResult.error}</pre>`;
      }
    }

    // Load debug logs
    const logsResult = await chrome.runtime.sendMessage({ type: 'GET_SYNC_DEBUG_LOGS' });
    if (debugLogsEl) {
      if (logsResult.success) {
        debugLogsEl.innerHTML = formatDebugLogs(logsResult.logs);
      } else {
        debugLogsEl.innerHTML = `<pre class="error">Error: ${logsResult.error}</pre>`;
      }
    }
  } catch (error) {
    if (debugInfoEl) {
      debugInfoEl.innerHTML = `<pre class="error">Failed to load debug info: ${error}</pre>`;
    }
  }
}

function formatDebugInfo(info: SyncDebugInfo): string {
  const wsStateMap: Record<number, string> = {
    0: 'CONNECTING',
    1: 'OPEN',
    2: 'CLOSING',
    3: 'CLOSED',
  };

  const lines = [
    `Chain ID:        ${info.chainId || 'Not set'}`,
    `Device ID:       ${info.deviceId || 'Not set'}`,
    `Device Name:     ${info.deviceName || 'Not set'}`,
    `Seed Hash:       ${info.seedHashPrefix || 'Not set'}`,
    ``,
    `Connected:       ${info.isConnected ? 'YES' : 'NO'}`,
    `Current Relay:   ${info.currentRelay || 'None'}`,
    `Relay Index:     ${info.currentRelayIndex}`,
    `WebSocket State: ${wsStateMap[info.wsReadyState] || info.wsReadyState}`,
    `Subscription ID: ${info.subId || 'None'}`,
    ``,
    `Encryption Key:  ${info.hasEncryptionKey ? 'Derived' : 'Not derived'}`,
    `Signing Key:     ${info.hasSigningKey ? 'Derived' : 'Not derived'}`,
    ``,
    `Total Logs:      ${info.logsCount}`,
  ];

  return lines.join('\n');
}

function formatDebugLogs(logs: DebugLogEntry[]): string {
  if (!logs || logs.length === 0) {
    return '<pre class="empty">No logs yet. Try clicking "Sync Now" to generate activity.</pre>';
  }

  const logLines = logs
    .slice(-100) // Last 100 logs
    .reverse() // Newest first
    .map((log) => {
      const time = new Date(log.timestamp).toLocaleTimeString();
      const levelClass = `log-${log.level}`;
      const dataStr = log.data ? ` ${JSON.stringify(log.data)}` : '';
      return `<div class="log-entry ${levelClass}"><span class="log-time">${time}</span> <span class="log-category">[${log.category}]</span> <span class="log-msg">${escapeHtml(log.message)}</span><span class="log-data">${escapeHtml(dataStr)}</span></div>`;
    })
    .join('');

  return `<div class="log-container">${logLines}</div>`;
}

async function clearDebugLogs(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({ type: 'CLEAR_SYNC_DEBUG_LOGS' });
    await loadDebugInfo();
  } catch (error) {
    console.error('Failed to clear logs:', error);
  }
}
