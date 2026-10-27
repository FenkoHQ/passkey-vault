/**
 * The post-0.9.5 upgrade gate blocks vault changes until an encrypted backup
 * is exported. These tests drive the real background message router against
 * an in-memory chrome.storage.local and a fake unlocked vault.
 */

const UPGRADE_KEY = 'upgrade_backup_required_0_9_5';
const BLOCKED = 'Export an encrypted backup before changing this upgraded vault.';

const vault: { passkeys: Record<string, unknown>[]; totp: Record<string, unknown>[] } = {
  passkeys: [],
  totp: [],
};

jest.mock('../src/crypto/secure-storage', () => ({
  secureStorage: {
    isSetup: async () => true,
    isStorageUnlocked: () => true,
    restoreSession: async () => {},
    lock: jest.fn(),
    setAutoLockTimeout: jest.fn(),
    getSyncConfig: async () => null,
    getPasskeys: async () => vault.passkeys,
    storePasskeys: async (passkeys: Record<string, unknown>[]) => {
      vault.passkeys = passkeys;
    },
    getTotpEntries: async () => vault.totp,
    storeTotpEntries: async (entries: Record<string, unknown>[]) => {
      vault.totp = entries;
    },
  },
}));

jest.mock('../src/sync/sync-service', () => ({
  syncService: { initialize: jest.fn(), disconnect: jest.fn(async () => {}) },
}));

jest.mock('../src/utils/logger', () => ({
  logger: { init: async () => {}, info: jest.fn(), debug: jest.fn(), error: jest.fn() },
}));

type Listener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response: unknown) => void
) => boolean;

let store: Record<string, unknown> = {};
let listener: Listener;

function installChromeStorage(): void {
  const local = chrome.storage.local as unknown as Record<string, jest.Mock>;
  local.get.mockImplementation(async (keys?: string | string[] | null) => {
    if (keys == null) return { ...store };
    const wanted = Array.isArray(keys) ? keys : [keys];
    return Object.fromEntries(wanted.filter((key) => key in store).map((key) => [key, store[key]]));
  });
  local.set.mockImplementation(async (items: Record<string, unknown>) => {
    Object.assign(store, items);
  });
  local.remove.mockImplementation(async (keys: string | string[]) => {
    for (const key of Array.isArray(keys) ? keys : [keys]) delete store[key];
  });
  local.clear.mockImplementation(async () => {
    store = {};
  });
}

function send(type: string, payload?: unknown): Promise<{ success: boolean; error?: string }> {
  return new Promise((resolve) => {
    listener({ type, payload }, {}, resolve as (response: unknown) => void);
  });
}

const TOTP_ENTRY = {
  id: 'totp-1',
  type: 'totp',
  issuer: 'GitHub',
  account: 'ali',
  secretB64: 'SGk=',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  counter: 0,
  createdAt: 1750000000000,
};

beforeAll(() => {
  const runtime = chrome.runtime as unknown as Record<string, unknown>;
  for (const event of ['onInstalled', 'onStartup', 'onSuspend']) {
    runtime[event] = { addListener: jest.fn() };
  }
  installChromeStorage();
  jest.spyOn(console, 'error').mockImplementation(() => {});

  require('../src/background/background');
  const addListener = chrome.runtime.onMessage.addListener as jest.Mock;
  listener = addListener.mock.calls[addListener.mock.calls.length - 1][0];
});

beforeEach(() => {
  store = { [UPGRADE_KEY]: true };
  vault.passkeys = [];
  vault.totp = [];
});

describe('the upgrade backup gate', () => {
  it('blocks changes to a TOTP-only vault until the backup is exported', async () => {
    vault.totp = [{ ...TOTP_ENTRY }];

    expect(await send('GET_UPGRADE_BACKUP_STATUS')).toMatchObject({ required: true });
    expect(await send('DELETE_TOTP_ENTRY', { id: 'totp-1' })).toEqual({
      success: false,
      error: BLOCKED,
    });

    await send('COMPLETE_UPGRADE_BACKUP');

    expect(await send('DELETE_TOTP_ENTRY', { id: 'totp-1' })).toMatchObject({ success: true });
    expect(vault.totp).toHaveLength(0);
  });

  it('lifts itself once the vault holds nothing to back up', async () => {
    expect(await send('GET_UPGRADE_BACKUP_STATUS')).toMatchObject({ required: false });
    expect(store[UPGRADE_KEY]).toBeUndefined();

    store[UPGRADE_KEY] = true;
    expect(await send('ADD_TOTP_ENTRY', { entry: { ...TOTP_ENTRY } })).toMatchObject({
      success: true,
    });
    expect(store[UPGRADE_KEY]).toBeUndefined();
  });

  it('does not block factory reset of an emptied vault', async () => {
    expect(await send('FACTORY_RESET')).toEqual({ success: true });
  });
});
