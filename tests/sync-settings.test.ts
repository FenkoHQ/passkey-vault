/**
 * The sync settings page, loaded from its HTML with the background mocked.
 * Device names, relay URLs and sync errors come from other devices and from
 * relays, so the page must show them as text.
 */

import { readFileSync } from 'fs';

type Message = { type: string; deviceId?: string };

const HOSTILE = '<img src=x onerror="window.__pwned=1">';
const chromeMock = (window as unknown as { chrome: Record<string, any> }).chrome;
let background: (message: Message) => unknown = () => ({ success: true });

const syncConfig = {
  enabled: true,
  chainId: 'c'.repeat(32),
  deviceId: 'this-device',
  deviceName: 'Laptop',
};

function debugInfo(overrides: Record<string, unknown> = {}) {
  return {
    success: true,
    debugInfo: {
      chainId: syncConfig.chainId,
      deviceId: 'this-device',
      deviceName: HOSTILE,
      seedHashPrefix: 'abcd',
      isConnected: true,
      relays: [{ url: `wss://relay.example/${HOSTILE}`, state: HOSTILE }],
      connectedRelayCount: 1,
      logsCount: 1,
      ...overrides,
    },
  };
}

const flush = async () => {
  for (let i = 0; i < 10; i++) await new Promise((resolve) => setTimeout(resolve, 0));
};

beforeAll(async () => {
  const html = readFileSync('src/ui/sync-settings.html', 'utf8');
  document.documentElement.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, '');
  jest.spyOn(window, 'setInterval').mockReturnValue(0 as unknown as ReturnType<typeof setInterval>);
  chromeMock.storage.onChanged = { addListener: jest.fn() };
  chromeMock.runtime.sendMessage.mockImplementation(async (message: Message) =>
    background(message)
  );
  chromeMock.storage.local.get.mockImplementation(async (key: string) =>
    key === 'sync_config' ? { sync_config: syncConfig } : {}
  );
  require('../src/ui/sync-settings');
  document.dispatchEvent(new Event('DOMContentLoaded'));
  await flush();
});

beforeEach(() => {
  (window as unknown as Record<string, unknown>).__pwned = undefined;
  chromeMock.runtime.sendMessage.mockClear();
});

function openTab(name: string): Promise<void> {
  (document.querySelector(`[data-tab="${name}"]`) as HTMLElement).click();
  return flush();
}

describe('sync debug panel', () => {
  it('shows device names and relay URLs as text', async () => {
    background = (message) => {
      if (message.type === 'GET_SYNC_DEBUG_INFO') return debugInfo();
      if (message.type === 'GET_SYNC_DEBUG_LOGS') {
        return {
          success: true,
          logs: [
            {
              timestamp: 1,
              level: `info ${HOSTILE}`,
              category: HOSTILE,
              message: HOSTILE,
              data: { deviceName: HOSTILE },
            },
          ],
        };
      }
      return { success: true };
    };

    await openTab('debug');

    const panel = document.getElementById('tab-debug')!;
    expect(panel.querySelector('img')).toBeNull();
    expect(document.getElementById('debug-info')!.textContent).toContain(HOSTILE);
    expect(document.getElementById('debug-info')!.textContent).toContain(
      `wss://relay.example/${HOSTILE}`
    );
    expect(document.getElementById('debug-logs')!.textContent).toContain(`[${HOSTILE}]`);
    expect(panel.querySelector('.log-entry')!.className).toBe('log-entry log-info');
  });

  it('shows errors from the background as text', async () => {
    background = (message) =>
      message.type.startsWith('GET_SYNC_DEBUG') ? { success: false, error: HOSTILE } : {};

    await openTab('debug');

    expect(document.getElementById('tab-debug')!.querySelector('img')).toBeNull();
    expect(document.getElementById('debug-info')!.textContent).toContain(HOSTILE);
    expect(document.getElementById('debug-logs')!.textContent).toContain(HOSTILE);
  });
});

describe('sync device list', () => {
  it('shows a device whose type is not a string', async () => {
    background = (message) =>
      message.type === 'GET_SYNC_CHAIN_INFO'
        ? {
            success: true,
            chainInfo: {
              devices: [
                { id: 'phone', name: HOSTILE, deviceType: 7, lastSeen: 1, isThisDevice: false },
              ],
            },
          }
        : { success: true };

    await openTab('devices');

    const list = document.getElementById('devices-list')!;
    expect(list.querySelector('img')).toBeNull();
    expect(list.querySelector('.device-name')!.textContent).toBe(HOSTILE);
  });
});
