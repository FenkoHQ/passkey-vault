import { SyncDevice, SyncChain } from '../types';

const STORAGE_KEY = 'sync_config';

interface SyncConfig {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  seedHash: string | null;
}

document.addEventListener('DOMContentLoaded', () => {
  loadSyncConfig();
  setupEventListeners();
});

function setupEventListeners(): void {
  const backBtn = document.getElementById('back-btn') as HTMLButtonElement;
  const addDeviceBtn = document.getElementById('add-device-btn') as HTMLButtonElement;
  const leaveChainBtn = document.getElementById('leave-chain-btn') as HTMLButtonElement;
  const setupSyncBtn = document.getElementById('setup-sync-btn') as HTMLButtonElement;

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
