/**
 * Master PIN lifecycle (set, change, remove) and its interaction with the
 * encrypted sync config. Runs the real background service and secure storage
 * against an in-memory chrome.storage.local; only the relay-facing sync
 * service is stubbed.
 */

import { generateMnemonic } from '../src/crypto/bip39';

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

type SyncConfigData = {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  seedHash?: string | null;
};

const chainA: SyncConfigData = {
  enabled: true,
  chainId: 'a'.repeat(32),
  deviceId: 'device-a',
  deviceName: 'Laptop',
  seedHash: 'a'.repeat(64),
};

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
  // Per-passkey backup flags, so the legacy stamp on unlock leaves it alone.
  backupEligible: true,
  backupState: true,
  backupSource: 'created',
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

const ENCRYPTED_VAULT_KEYS = [
  'passext_master_key_check',
  'passext_encryption_salt',
  'passext_encrypted_passkeys',
];

describe('removing the master PIN', () => {
  it('moves the vault back to cleartext storage', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });

    expect(removed.success).toBe(true);
    for (const key of ENCRYPTED_VAULT_KEYS) expect(storage[key]).toBeUndefined();
    expect(storage.passkeys).toEqual([passkey]);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isSetup).toBe(false);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('keeps the encrypted vault when the cleartext write fails', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    const local = chrome.storage.local as unknown as Record<string, jest.Mock>;
    const write = local.set.getMockImplementation()!;
    local.set.mockImplementation(async (items: StorageData) => {
      if ('passkeys' in items) throw new Error('QUOTA_BYTES quota exceeded');
      return write(items);
    });

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });

    expect(removed.success).toBe(false);
    for (const key of ENCRYPTED_VAULT_KEYS) expect(storage[key]).toBeDefined();
    local.set.mockImplementation(write);
    expect(await unlocksWith(send, PIN)).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('recovers on the next unlock when only the final removal fails', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    const local = chrome.storage.local as unknown as Record<string, jest.Mock>;
    const drop = local.remove.getMockImplementation()!;
    local.remove.mockImplementation(async (keys: string | string[]) => {
      if ([keys].flat().includes('passext_master_key_check')) throw new Error('IO error');
      return drop(keys);
    });

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });

    expect(removed.success).toBe(false);
    local.remove.mockImplementation(drop);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(false);
    expect(
      (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } })).success
    ).toBe(true);
    expect(storage.passkeys).toBeUndefined();
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('keeps the encrypted vault when a blob does not decrypt', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    const blob = storage.passext_encrypted_passkeys as { data: string };
    const damaged = { ...blob, data: blob.data.slice(4) + 'AAAA' };
    storage.passext_encrypted_passkeys = damaged;

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });

    expect(removed.success).toBe(false);
    expect(storage.passext_encrypted_passkeys).toEqual(damaged);
    expect(storage.passext_master_key_check).toBeDefined();
    expect(storage.passkeys).toBeUndefined();
  });
});

describe('a wrong PIN on an unlocked vault', () => {
  it('leaves the vault unlocked when removing the PIN', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: WRONG_PIN },
    });

    expect(removed.success).toBe(false);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
    expect(storage.passext_master_key_check).toBeDefined();
  });

  it('leaves the vault unlocked when unlocking again', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: WRONG_PIN } });

    expect(unlock.success).toBe(false);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([passkey]);
  });

  it('still refuses to unlock a locked vault', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    expect(await unlocksWith(send, WRONG_PIN)).toBe(false);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(false);
    expect((await send({ type: 'LIST_PASSKEYS' })).success).toBe(false);
  });
});

describe('the sync config when the PIN is removed', () => {
  async function pinnedOnChainA(): Promise<Respond> {
    storage.passkeys = [passkey];
    storage.sync_config = { ...chainA };
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    expect((storage.sync_config as SyncConfigData).seedHash).toBeUndefined();
    return send;
  }

  it('gives the current chain its seed back', async () => {
    const send = await pinnedOnChainA();

    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });

    expect(storage.sync_config).toEqual(chainA);
  });

  it('does not rejoin a chain the device left', async () => {
    const send = await pinnedOnChainA();
    expect((await send({ type: 'LEAVE_SYNC_CHAIN' })).success).toBe(true);
    expect(storage.passext_encrypted_sync_config).toBeUndefined();

    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });

    const config = storage.sync_config as SyncConfigData;
    expect(config.enabled).toBe(false);
    expect(config.chainId).toBeNull();
    expect(config.seedHash ?? null).toBeNull();
  });

  it('does not switch back from a chain joined afterwards', async () => {
    const send = await pinnedOnChainA();
    const mnemonic = await generateMnemonic(12);
    expect((await send({ type: 'JOIN_SYNC_CHAIN', deviceName: 'Laptop', mnemonic })).success).toBe(
      true
    );
    const chainB = (storage.sync_config as SyncConfigData).chainId;
    expect(chainB).not.toBe(chainA.chainId);

    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });

    const config = storage.sync_config as SyncConfigData;
    expect(config.enabled).toBe(true);
    expect(config.chainId).toBe(chainB);
    expect(config.seedHash?.startsWith(chainB as string)).toBe(true);
  });
});

describe('creating or joining a sync chain on a PIN-protected vault', () => {
  /** Everything outside the encrypted store, as it would sit on disk. */
  const cleartext = (): string =>
    JSON.stringify(Object.entries(storage).filter(([key]) => !key.startsWith('passext_')));

  async function pinned() {
    storage.passkeys = [passkey];
    const background = await loadBackground();
    await background.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    background.sync.initialize.mockClear();
    return background;
  }

  it('keeps the seed of a created chain in the encrypted store only', async () => {
    const { send, secure, sync } = await pinned();

    const created = await send({ type: 'CREATE_SYNC_CHAIN', deviceName: 'Laptop', wordCount: 12 });

    expect(created.success).toBe(true);
    const encrypted = await secure.getSyncConfig();
    expect(encrypted?.chainId).toBe(created.chainId);
    expect(encrypted?.seedHash).toMatch(/^[0-9a-f]{64}$/);
    expect(cleartext()).not.toContain(encrypted?.seedHash);
    expect((storage.sync_config as SyncConfigData).chainId).toBe(created.chainId);
    expect(sync.initialize).toHaveBeenCalledWith(
      created.chainId,
      created.deviceId,
      encrypted?.seedHash,
      'Laptop',
      expect.anything()
    );
  });

  it('keeps the seed of a joined chain in the encrypted store only', async () => {
    const { send, secure } = await pinned();
    const mnemonic = await generateMnemonic(12);

    const joined = await send({ type: 'JOIN_SYNC_CHAIN', deviceName: 'Laptop', mnemonic });

    expect(joined.success).toBe(true);
    const encrypted = await secure.getSyncConfig();
    expect(encrypted?.seedHash).toMatch(/^[0-9a-f]{64}$/);
    expect(cleartext()).not.toContain(encrypted?.seedHash);

    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });
    expect((storage.sync_config as SyncConfigData).seedHash).toBe(encrypted?.seedHash);
  });

  it('refuses while the vault is locked', async () => {
    const { send, sync } = await pinned();
    await send({ type: 'LOCK_SECURE_STORAGE' });
    const before = cleartext();

    const created = await send({ type: 'CREATE_SYNC_CHAIN', deviceName: 'Laptop', wordCount: 12 });
    const joined = await send({
      type: 'JOIN_SYNC_CHAIN',
      deviceName: 'Laptop',
      mnemonic: await generateMnemonic(12),
    });

    expect(created.success).toBe(false);
    expect(joined.success).toBe(false);
    expect(cleartext()).toBe(before);
    expect(storage.passext_encrypted_sync_config).toBeUndefined();
    expect(sync.initialize).not.toHaveBeenCalled();
  });

  it('still stores the seed in cleartext without a PIN', async () => {
    const { send } = await loadBackground();

    const created = await send({ type: 'CREATE_SYNC_CHAIN', deviceName: 'Laptop', wordCount: 12 });

    expect(created.success).toBe(true);
    const config = storage.sync_config as SyncConfigData;
    expect(config.chainId).toBe(created.chainId);
    expect(config.seedHash?.startsWith(created.chainId as string)).toBe(true);
  });
});

describe('the cleartext seed older builds left in the chain record', () => {
  type ChainRecord = { id: string; createdAt: number; devices: unknown[]; seedHash?: string };
  const recordFor = (config: SyncConfigData): ChainRecord => ({
    id: config.chainId as string,
    createdAt: 1,
    devices: [],
    seedHash: config.seedHash as string,
  });
  const chainB: SyncConfigData = {
    ...chainA,
    chainId: 'b'.repeat(32),
    seedHash: 'b'.repeat(64),
  };

  it('is stripped when a PIN is set up', async () => {
    storage.sync_config = { ...chainA };
    storage.sync_devices = recordFor(chainA);
    const { send, secure } = await loadBackground();

    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    expect((await secure.getSyncConfig())?.seedHash).toBe(chainA.seedHash);
    expect(storage.sync_devices).toEqual({ ...recordFor(chainA), seedHash: undefined });
    expect(JSON.stringify(storage)).not.toContain('"seedHash":"' + chainA.seedHash);
  });

  it('is stripped from an existing PIN vault on unlock, keeping the seed', async () => {
    storage.sync_config = { ...chainA };
    const { send, secure } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    await send({ type: 'LOCK_SECURE_STORAGE' });
    storage.sync_devices = recordFor(chainA);

    expect(await unlocksWith(send, PIN)).toBe(true);

    expect((storage.sync_devices as ChainRecord).seedHash).toBeUndefined();
    expect((await secure.getSyncConfig())?.seedHash).toBe(chainA.seedHash);
    await send({ type: 'REMOVE_MASTER_PASSWORD', payload: { currentPassword: PIN } });
    expect(storage.sync_config).toEqual(chainA);
  });

  it('moves the seed into the encrypted config when that is the only copy', async () => {
    const { send, secure, sync } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    await send({ type: 'LOCK_SECURE_STORAGE' });
    const publicConfig: SyncConfigData = { ...chainA };
    delete publicConfig.seedHash;
    storage.sync_config = publicConfig;
    storage.sync_devices = recordFor(chainA);

    expect(await unlocksWith(send, PIN)).toBe(true);

    expect((await secure.getSyncConfig())?.seedHash).toBe(chainA.seedHash);
    expect((storage.sync_devices as ChainRecord).seedHash).toBeUndefined();
    expect(sync.initialize).toHaveBeenLastCalledWith(
      chainA.chainId,
      chainA.deviceId,
      chainA.seedHash,
      chainA.deviceName,
      expect.anything()
    );
  });

  it('is left alone while locked and for a chain the device is not on', async () => {
    storage.sync_config = { ...chainA };
    const { send } = await loadBackground();
    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });
    await send({ type: 'LOCK_SECURE_STORAGE' });
    storage.sync_devices = recordFor(chainB);

    const restarted = await loadBackground();
    expect((storage.sync_devices as ChainRecord).seedHash).toBe(chainB.seedHash);
    expect(await unlocksWith(restarted.send, PIN)).toBe(true);

    expect((storage.sync_devices as ChainRecord).seedHash).toBe(chainB.seedHash);
    expect((await restarted.secure.getSyncConfig())?.seedHash).toBe(chainA.seedHash);
  });
});
