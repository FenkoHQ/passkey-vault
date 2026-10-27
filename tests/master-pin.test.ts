/**
 * Master PIN lifecycle (set, change, remove) and its interaction with the
 * encrypted sync config. Runs the real background service and secure storage
 * against an in-memory chrome.storage.local; only the relay-facing sync
 * service is stubbed.
 */

jest.mock('../src/sync/sync-service', () => ({
  syncService: {
    initialize: jest.fn(async () => {}),
    disconnect: jest.fn(async () => {}),
    requestSync: jest.fn(async () => {}),
    broadcastPasskeyUpdate: jest.fn(async () => {}),
    getStatus: jest.fn(() => ({ connected: false })),
    getDebugLogs: jest.fn(() => []),
    clearDebugLogs: jest.fn(),
  },
}));

type StorageData = Record<string, unknown>;
type Reply = { success: boolean; [field: string]: unknown };
type Respond = (message: Record<string, unknown>) => Promise<Reply>;
type SecureStorageModule = typeof import('../src/crypto/secure-storage');
type SyncServiceModule = { syncService: Record<string, jest.Mock> };

const PIN = '1234';
const WRONG_PIN = '0000';

const passkey = {
  id: 'pk-1',
  credentialId: 'cred-1',
  type: 'public-key',
  rpId: 'example.com',
  origin: 'https://example.com',
  user: { id: 'u', name: 'user', displayName: 'User' },
  privateKey: 'private-key',
  publicKey: 'public-key',
  createdAt: 1,
  counter: 0,
};

// jsdom has no structuredClone; stored values are all JSON.
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

/** Back chrome.storage.local with a plain object, honouring every key form. */
function useFakeStorage(): StorageData {
  const data: StorageData = {};
  const keysOf = (keys: unknown): string[] =>
    keys == null ? Object.keys(data) : Array.isArray(keys) ? keys : [keys as string];
  const local = chrome.storage.local as unknown as Record<string, jest.Mock>;
  local.get.mockReset().mockImplementation(async (keys: unknown) => {
    const result: StorageData = {};
    for (const key of keysOf(keys)) {
      if (data[key] !== undefined) result[key] = clone(data[key]);
    }
    return result;
  });
  local.set.mockReset().mockImplementation(async (items: StorageData) => {
    for (const [key, value] of Object.entries(items)) data[key] = clone(value);
  });
  local.remove.mockReset().mockImplementation(async (keys: unknown) => {
    for (const key of keysOf(keys)) delete data[key];
  });
  local.clear.mockReset().mockImplementation(async () => {
    for (const key of Object.keys(data)) delete data[key];
  });
  return data;
}

/**
 * Load a fresh background service (and its secure storage singleton) and
 * return a function that sends it a runtime message.
 */
async function loadBackground(): Promise<{
  send: Respond;
  secure: SecureStorageModule['secureStorage'];
  sync: SyncServiceModule['syncService'];
}> {
  const runtime = chrome.runtime as unknown as Record<string, unknown>;
  const listeners: Array<(m: unknown, s: unknown, r: (v: unknown) => void) => void> = [];
  runtime.onMessage = { addListener: (fn: (typeof listeners)[number]) => listeners.push(fn) };
  for (const event of ['onInstalled', 'onStartup', 'onSuspend']) {
    runtime[event] = { addListener: jest.fn() };
  }

  let secure!: SecureStorageModule['secureStorage'];
  let sync!: SyncServiceModule['syncService'];
  await jest.isolateModulesAsync(async () => {
    await import('../src/background/background');
    secure = (await import('../src/crypto/secure-storage')).secureStorage;
    sync = ((await import('../src/sync/sync-service')) as unknown as SyncServiceModule).syncService;
  });

  const send: Respond = (message) =>
    new Promise((resolve) => listeners[0](message, {}, (v) => resolve(v as Reply)));
  return { send, secure, sync };
}

let storage: StorageData;

beforeEach(() => {
  storage = useFakeStorage();
});

afterEach(() => {
  jest.useRealTimers();
});

/** Lock, then report whether the given PIN unlocks the vault. */
async function unlocksWith(send: Respond, pin: string): Promise<boolean> {
  await send({ type: 'LOCK_SECURE_STORAGE' });
  return (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: pin } })).success;
}

describe('changing the master PIN', () => {
  it('rejects a wrong current PIN and keeps the old one', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    expect(
      (await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
    ).toBe(true);

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: WRONG_PIN, newPassword: '5678' },
    });

    expect(change.success).toBe(false);
    expect(await unlocksWith(send, '5678')).toBe(false);
    expect(await unlocksWith(send, PIN)).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('re-keys the vault when the current PIN is right', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: '5678' },
    });

    expect(change.success).toBe(true);
    expect(await unlocksWith(send, PIN)).toBe(false);
    expect(await unlocksWith(send, '5678')).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('does not set up a PIN on a vault that has none', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: '5678' },
    });

    expect(change.success).toBe(false);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isSetup).toBe(false);
    expect(storage.passkeys).toEqual([passkey]);
  });
});

describe('setting up a master PIN', () => {
  it('refuses a second setup instead of emptying the vault', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    const setup = { type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } };

    expect((await send(setup)).success).toBe(true);
    expect(storage.passkeys).toBeUndefined();
    const again = await send(setup);

    expect(again.success).toBe(false);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    expect(await unlocksWith(send, PIN)).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('survives a double-clicked setup', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    const setup = { type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } };

    const results = await Promise.all([send(setup), send(setup)]);

    expect(results.map((r) => r.success).sort()).toEqual([false, true]);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('does not let a reconcile wipe a migrated vault', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    expect((await send({ type: 'RECONCILE_STORAGE' })).success).toBe(true);

    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });
});
