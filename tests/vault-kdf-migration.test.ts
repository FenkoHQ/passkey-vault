/**
 * Upgrading the key of a vault from before KDF records (PBKDF2-SHA256, 100k)
 * on its next unlock: every value is re-encrypted under the default KDF in
 * one storage write, and a stopped worker or a failed write at any point
 * leaves a vault that the same PIN still opens. The legacy vaults here are
 * built with Node's crypto (tests/helpers/legacy-vault.ts), not the code
 * under test.
 */

import { createDecipheriv, pbkdf2Sync } from 'crypto';
import {
  loadBackground,
  unlocksWith,
  useFakeStorage,
  type StorageData,
} from './helpers/pin-background';
import { ENCRYPTED_VAULT_VALUES, legacyVault, scryptVault } from './helpers/legacy-vault';

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

const PIN = '482916';

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
  backupEligible: true,
  backupState: true,
  backupSource: 'created',
};
const totp = {
  id: 'totp-1',
  type: 'totp',
  issuer: 'Example',
  account: 'user',
  secretB64: 'AAAAAAAAAAAAAAAAAAAA',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  counter: 0,
};
const chain = {
  enabled: true,
  chainId: 'a'.repeat(32),
  deviceId: 'device-a',
  deviceName: 'Laptop',
  seedHash: 'a'.repeat(64),
};

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const local = () => chrome.storage.local as unknown as Record<string, jest.Mock>;
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const vaultState = () =>
  clone(Object.fromEntries(Object.entries(storage).filter(([key]) => key.startsWith('passext_'))));
const isRekey = (items: StorageData) => 'passext_vault_kdf' in items;

let storage: StorageData;

beforeEach(() => {
  storage = useFakeStorage();
  // As a PIN'd vault leaves it: the seed only in the encrypted config.
  Object.assign(
    storage,
    legacyVault(PIN, { passkeys: [passkey], totpEntries: [totp], syncConfig: chain }),
    { sync_config: { ...chain, seedHash: undefined } }
  );
});

/** Unlock in a fresh worker and read everything back. */
async function contentsWith(pin: string) {
  const { send, secure } = await loadBackground();
  const unlocked = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: pin } });
  if (!unlocked.success) return null;
  return {
    passkeys: ((await send({ type: 'LIST_PASSKEYS' })).passkeys as Array<{ id: string }>).map(
      (p) => p.id
    ),
    totp: await secure.getTotpEntries(),
    seedHash: (await secure.getSyncConfig())?.seedHash,
  };
}

const EVERYTHING = { passkeys: [passkey.id], totp: [totp], seedHash: chain.seedHash };

/** Whether the legacy PBKDF2 key still opens the stored check value. */
function legacyKeyOpens(legacySalt: string): boolean {
  const key = pbkdf2Sync(PIN, Buffer.from(legacySalt, 'base64'), 100000, 32, 'sha256');
  const check = storage.passext_master_key_check as { data: string; iv: string };
  const sealed = Buffer.from(check.data, 'base64');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(check.iv, 'base64'));
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
    decipher.update(sealed.subarray(0, sealed.length - 16));
    decipher.final();
    return true;
  } catch {
    return false;
  }
}

describe('unlocking a vault from before KDF records', () => {
  it('re-encrypts every value under scrypt in one write and drops the legacy salt', async () => {
    const legacy = vaultState();
    const { send } = await loadBackground();
    local().set.mockClear();

    expect(
      (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } })).success
    ).toBe(true);

    const rekeys = local().set.mock.calls.filter(([items]) => isRekey(items));
    expect(rekeys).toHaveLength(1);
    expect(Object.keys(rekeys[0][0]).sort()).toEqual(
      ['passext_vault_kdf', ...ENCRYPTED_VAULT_VALUES].sort()
    );
    expect(storage.passext_vault_kdf).toMatchObject({ kdf: 'scrypt', params: { N: 1024 } });
    expect(storage.passext_encryption_salt).toBeUndefined();
    for (const key of ENCRYPTED_VAULT_VALUES) expect(storage[key]).not.toEqual(legacy[key]);
    expect(legacyKeyOpens(legacy.passext_encryption_salt as string)).toBe(false);
  });

  it('keeps every passkey, TOTP entry and the sync seed', async () => {
    const { send, secure } = await loadBackground();

    await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toEqual([
      expect.objectContaining({ id: passkey.id }),
    ]);
    expect(await secure.getTotpEntries()).toEqual([totp]);
    expect((await secure.getSyncConfig())?.seedHash).toBe(chain.seedHash);
    expect(await contentsWith(PIN)).toEqual(EVERYTHING);
  });

  it('starts sync with the seed from the re-encrypted config', async () => {
    const { send, sync } = await loadBackground();

    await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

    expect(sync.initialize).toHaveBeenLastCalledWith(
      chain.chainId,
      chain.deviceId,
      chain.seedHash,
      chain.deviceName,
      expect.anything()
    );
  });

  it('rejects a wrong PIN and leaves the vault untouched', async () => {
    const legacy = vaultState();
    const { send } = await loadBackground();

    expect(
      (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: '482917' } })).success
    ).toBe(false);
    expect(vaultState()).toEqual(legacy);
  });

  it('rejects a wrong PIN afterwards and does not re-key again', async () => {
    const { send } = await loadBackground();
    await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    const upgraded = vaultState();

    expect(await unlocksWith(send, '000000')).toBe(false);
    expect(await unlocksWith(send, PIN)).toBe(true);
    expect(vaultState()).toEqual(upgraded);
  });

  it('also upgrades a scrypt record weaker than the default', async () => {
    for (const key of Object.keys(storage)) delete storage[key];
    Object.assign(storage, scryptVault(PIN, { N: 512, r: 8, p: 1 }, { totpEntries: [totp] }));

    expect((await contentsWith(PIN))?.totp).toEqual([totp]);
    expect(storage.passext_vault_kdf).toMatchObject({ kdf: 'scrypt', params: { N: 1024 } });
    expect((await contentsWith(PIN))?.totp).toEqual([totp]);
  });
});

describe('an interrupted upgrade', () => {
  it('leaves the old vault when the worker dies before the write lands', async () => {
    const legacy = vaultState();
    const { send } = await loadBackground();
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation((items: StorageData) =>
      isRekey(items) ? new Promise(() => {}) : write(items)
    );

    void send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    while (!local().set.mock.calls.some(([items]) => isRekey(items))) await flush();
    local().set.mockImplementation(write);

    // The next worker finds the old vault, opens it and upgrades it.
    expect(vaultState()).toEqual(legacy);
    expect(await contentsWith(PIN)).toEqual(EVERYTHING);
    expect(storage.passext_vault_kdf).toMatchObject({ kdf: 'scrypt' });
    expect(storage.passext_encryption_salt).toBeUndefined();
  });

  it('still unlocks with the old key when the write fails, and retries next unlock', async () => {
    const legacy = vaultState();
    const { send, secure } = await loadBackground();
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation(async (items: StorageData) => {
      if (isRekey(items)) throw new Error('QUOTA_BYTES quota exceeded');
      return write(items);
    });

    const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    local().set.mockImplementation(write);

    expect(unlock.success).toBe(true);
    expect(vaultState()).toEqual(legacy);
    expect(await secure.getTotpEntries()).toEqual([totp]);
    // Saved while on the old key, and carried over by the retried upgrade.
    await secure.storeTotpEntries([totp, { ...totp, id: 'totp-2' }]);
    expect(legacyKeyOpens(legacy.passext_encryption_salt as string)).toBe(true);

    expect(await contentsWith(PIN)).toEqual({
      ...EVERYTHING,
      totp: [totp, { ...totp, id: 'totp-2' }],
    });
    expect(storage.passext_vault_kdf).toMatchObject({ kdf: 'scrypt' });
  });

  it('finishes when the worker died between the write and removing the old salt', async () => {
    const { send } = await loadBackground();
    const drop = local().remove.getMockImplementation()!;
    local().remove.mockImplementation((keys: string | string[]) =>
      [keys].flat().includes('passext_encryption_salt') ? new Promise(() => {}) : drop(keys)
    );

    void send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    // Wait for the salt removal itself: the worker removes other keys too.
    const removesSalt = (call: unknown[]) =>
      [call[0] as string | string[]].flat().includes('passext_encryption_salt');
    while (!local().remove.mock.calls.some(removesSalt)) await flush();
    local().remove.mockImplementation(drop);
    expect(storage.passext_vault_kdf).toBeDefined();
    expect(storage.passext_encryption_salt).toBeDefined();

    // The record wins over the stale salt, and the next unlock removes it.
    expect(await contentsWith(PIN)).toEqual(EVERYTHING);
    expect(storage.passext_encryption_salt).toBeUndefined();
  });

  it('keeps the old key in use when a value under it does not decrypt', async () => {
    const damaged = storage.passext_encrypted_totp_entries as { data: string };
    const bytes = Buffer.from(damaged.data, 'base64');
    bytes[0] ^= 0xff;
    damaged.data = bytes.toString('base64');
    const legacy = vaultState();
    const { send } = await loadBackground();

    const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

    // Unreadable data is not rewritten or dropped; the rest stays usable.
    expect(unlock.success).toBe(true);
    expect(vaultState()).toEqual(legacy);
    expect((await send({ type: 'LIST_PASSKEYS' })).passkeys).toHaveLength(1);
  });

  it('lands a write made during the upgrade under the new key, not lost or under the old one', async () => {
    const { send, secure } = await loadBackground();
    const write = local().set.getMockImplementation()!;
    // A failed first upgrade leaves the vault unlocked on the old key...
    local().set.mockImplementation(async (items: StorageData) => {
      if (isRekey(items)) throw new Error('QUOTA_BYTES quota exceeded');
      return write(items);
    });
    await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    // ...and the PIN typed again retries it while a sync merge saves.
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    local().set.mockImplementation(async (items: StorageData) => {
      if (isRekey(items)) await held;
      return write(items);
    });
    local().set.mockClear();
    const racing = [{ ...totp, id: 'racing' }];

    const unlock = send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    while (!local().set.mock.calls.some(([items]) => isRekey(items))) await flush();
    const save = secure.storeTotpEntries(racing);
    for (let i = 0; i < 5; i++) await flush();
    release();
    expect((await unlock).success).toBe(true);
    await save;
    local().set.mockImplementation(write);

    expect(storage.passext_vault_kdf).toMatchObject({ kdf: 'scrypt' });
    // Removing the PIN decrypts every value strictly, so it fails on any
    // value left under another key.
    const restarted = await loadBackground();
    await restarted.send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });
    const removed = await restarted.send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });
    expect(removed.success).toBe(true);
    expect(storage.totp_entries).toEqual(racing);
  });
});
