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

describe('removing a sync device', () => {
  const chainInfo = (ids: string[]) => ({
    success: true,
    chainInfo: {
      devices: ids.map((id) => ({
        id,
        name: id === 'laptop' ? 'Laptop' : 'Old phone',
        deviceType: 'mobile',
        lastSeen: 1,
        isThisDevice: id === 'laptop',
      })),
    },
  });
  let listedIds: string[];
  const sent = () =>
    chromeMock.runtime.sendMessage.mock.calls.map(([message]: [Message]) => message.type);

  beforeEach(async () => {
    listedIds = ['laptop', 'phone'];
    background = (message) => {
      if (message.type === 'GET_SYNC_CHAIN_INFO') return chainInfo(listedIds);
      if (message.type === 'REMOVE_SYNC_DEVICE') {
        listedIds = listedIds.filter((id) => id !== message.deviceId);
        return { success: true };
      }
      return { success: true };
    };
    await openTab('devices');
    chromeMock.runtime.sendMessage.mockClear();
  });

  afterEach(() => {
    for (const fn of [window.confirm, window.alert, console.error]) {
      (fn as unknown as Partial<jest.SpyInstance>).mockRestore?.();
    }
  });

  const removeButton = () =>
    document.querySelector<HTMLButtonElement>('#devices-list .device-remove-btn')!;

  it('offers removal for other devices only', () => {
    const buttons = document.querySelectorAll<HTMLElement>('#devices-list .device-remove-btn');
    expect([...buttons].map((b) => b.dataset.deviceId)).toEqual(['phone']);
  });

  it('says plainly that the device can still read the vault', async () => {
    const confirm = jest.spyOn(window, 'confirm').mockReturnValue(false);

    removeButton().click();
    await flush();

    const text = confirm.mock.calls[0][0] as string;
    expect(text).toContain('Old phone');
    expect(text).toContain('does not disconnect it');
    expect(text).toContain('recovery phrase');
    expect(text).toContain('can still read and change this vault');
    expect(text).toContain('start a new sync chain');
    expect(sent()).not.toContain('REMOVE_SYNC_DEVICE');
  });

  it('removes it and refreshes the list, leaving the chain alone if not asked', async () => {
    const confirm = jest
      .spyOn(window, 'confirm')
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(false);

    removeButton().click();
    await flush();

    expect(chromeMock.runtime.sendMessage).toHaveBeenCalledWith({
      type: 'REMOVE_SYNC_DEVICE',
      deviceId: 'phone',
    });
    expect(document.querySelectorAll('#devices-list .device-card')).toHaveLength(1);
    expect(confirm.mock.calls[1][0]).toContain('Start a new sync chain now?');
    expect(sent()).not.toContain('LEAVE_SYNC_CHAIN');
  });

  it('leaves the chain to start a new one when the user asks', async () => {
    jest.spyOn(window, 'confirm').mockReturnValue(true);
    jest.spyOn(console, 'error').mockImplementation(() => undefined); // jsdom: no navigation

    removeButton().click();
    await flush();

    expect(sent()).toEqual(['REMOVE_SYNC_DEVICE', 'GET_SYNC_CHAIN_INFO', 'LEAVE_SYNC_CHAIN']);
  });

  it('reports a failed removal', async () => {
    background = (message) =>
      message.type === 'REMOVE_SYNC_DEVICE' ? { success: false, error: 'boom' } : {};
    jest.spyOn(window, 'confirm').mockReturnValue(true);
    const alert = jest.spyOn(window, 'alert').mockImplementation(() => undefined);

    removeButton().click();
    await flush();

    expect(alert).toHaveBeenCalledWith(expect.stringContaining('boom'));
    expect(sent()).not.toContain('LEAVE_SYNC_CHAIN');
  });
});
