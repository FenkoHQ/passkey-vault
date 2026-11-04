/**
 * The vault key's KDF record: written with every new key, replaced in the
 * same storage write as the re-encrypted vault on a PIN change, removed with
 * the PIN, and reported as "newer version" rather than "wrong PIN" when this
 * build cannot read it. Real background and secure storage against an
 * in-memory chrome.storage.local, on the cheap test KDF profile.
 */

import {
  loadBackground,
  unlocksWith,
  useFakeStorage,
  type StorageData,
} from './helpers/pin-background';
import { ENCRYPTED_VAULT_VALUES, legacyVault } from './helpers/legacy-vault';

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

const PIN = '1234';
const NEW_PIN = '987654';

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
/** The encrypted vault as stored; start-up bookkeeping writes other keys at its own pace. */
const vaultState = () =>
  clone(Object.fromEntries(Object.entries(storage).filter(([key]) => key.startsWith('passext_'))));

let storage: StorageData;

beforeEach(() => {
  storage = useFakeStorage();
});

/** A PIN'd vault holding a passkey, a TOTP entry and a sync chain's seed. */
async function fullVault() {
  storage.passkeys = [passkey];
  storage.totp_entries = [totp];
  storage.sync_config = { ...chain };
  const background = await loadBackground();
  expect(
    (await background.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
  ).toBe(true);
  for (const key of ENCRYPTED_VAULT_VALUES) expect(storage[key]).toBeDefined();
  return background;
}

/** Unlock in a fresh worker and read everything back. */
async function contentsWith(pin: string) {
  const { send, secure } = await loadBackground();
  const unlocked = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: pin } });
  if (!unlocked.success) return null;
  return {
    passkeys: (await send({ type: 'LIST_PASSKEYS' })).passkeys as Array<{ id: string }>,
    totp: await secure.getTotpEntries(),
    seedHash: (await secure.getSyncConfig())?.seedHash,
  };
}

describe('a new PIN', () => {
  it('stores how the key was derived next to the vault', async () => {
    await fullVault();

    expect(storage.passext_vault_kdf).toEqual({
      kdf: 'scrypt',
      params: { N: 1024, r: 8, p: 1 },
      salt: expect.any(String),
    });
    const { salt } = storage.passext_vault_kdf as { salt: string };
    expect(Buffer.from(salt, 'base64')).toHaveLength(32);
    expect(storage.passext_encryption_salt).toBeUndefined();
  });

  it('writes the KDF record and the check value in one storage write', async () => {
    storage.passkeys = [passkey];
    const { send } = await loadBackground();
    local().set.mockClear();

    await send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } });

    const writes = local().set.mock.calls.map(([items]) => Object.keys(items));
    expect(writes).toContainEqual(
      expect.arrayContaining(['passext_vault_kdf', 'passext_master_key_check'])
    );
    expect(writes.filter((keys) => keys.includes('passext_vault_kdf'))).toHaveLength(1);
  });
});

describe('a vault from before KDF records', () => {
  it('still opens with its PIN, and only with its PIN', async () => {
    Object.assign(storage, legacyVault(PIN, { passkeys: [passkey], totpEntries: [totp] }));

    expect(await contentsWith('4321')).toBeNull();
    expect(await contentsWith(PIN)).toEqual({
      passkeys: [expect.objectContaining({ id: passkey.id })],
      totp: [totp],
      seedHash: undefined,
    });
  });

  it('moves to scrypt and drops the legacy salt when the PIN changes', async () => {
    Object.assign(storage, legacyVault(PIN, { passkeys: [passkey], totpEntries: [totp] }));
    const { send } = await loadBackground();
    await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: NEW_PIN },
    });

    expect(change.success).toBe(true);
    expect(storage.passext_vault_kdf).toMatchObject({ kdf: 'scrypt' });
    expect(storage.passext_encryption_salt).toBeUndefined();
    expect((await contentsWith(NEW_PIN))?.totp).toEqual([totp]);
  });
});

describe('changing the PIN', () => {
  it('records a fresh salt and re-encrypts every value in the same write', async () => {
    const { send } = await fullVault();
    const before = clone(storage);
    local().set.mockClear();

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: NEW_PIN },
    });

    expect(change.success).toBe(true);
    const rekeys = local().set.mock.calls.filter(([items]) => 'passext_vault_kdf' in items);
    expect(rekeys).toHaveLength(1);
    expect(Object.keys(rekeys[0][0]).sort()).toEqual(
      ['passext_vault_kdf', ...ENCRYPTED_VAULT_VALUES].sort()
    );
    expect((storage.passext_vault_kdf as { salt: string }).salt).not.toBe(
      (before.passext_vault_kdf as { salt: string }).salt
    );
    for (const key of ENCRYPTED_VAULT_VALUES) expect(storage[key]).not.toEqual(before[key]);

    expect(await contentsWith(PIN)).toBeNull();
    expect(await contentsWith(NEW_PIN)).toEqual({
      passkeys: [expect.objectContaining({ id: passkey.id })],
      totp: [totp],
      seedHash: chain.seedHash,
    });
  });

  it('leaves the vault as it was when a value under the key does not decrypt', async () => {
    const { send } = await fullVault();
    const damaged = storage.passext_encrypted_totp_entries as { data: string };
    const bytes = Buffer.from(damaged.data, 'base64');
    bytes[0] ^= 0xff;
    damaged.data = bytes.toString('base64');
    const before = vaultState();

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: NEW_PIN },
    });

    expect(change.success).toBe(false);
    expect(vaultState()).toEqual(before);
    expect((await send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
    expect(await unlocksWith(send, PIN)).toBe(true);
  });

  it('keeps the old PIN when the worker dies before the write lands', async () => {
    const { send } = await fullVault();
    const before = vaultState();
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation((items: StorageData) =>
      'passext_vault_kdf' in items ? new Promise(() => {}) : write(items)
    );

    void send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: NEW_PIN },
    });
    for (let i = 0; i < 20; i++) await flush();
    local().set.mockImplementation(write);

    expect(vaultState()).toEqual(before);
    expect(await contentsWith(NEW_PIN)).toBeNull();
    expect((await contentsWith(PIN))?.totp).toEqual([totp]);
  });

  it('keeps the old key in use when the write fails', async () => {
    const { send } = await fullVault();
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation(async (items: StorageData) => {
      if ('passext_vault_kdf' in items) throw new Error('QUOTA_BYTES quota exceeded');
      return write(items);
    });

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: NEW_PIN },
    });
    local().set.mockImplementation(write);

    expect(change.success).toBe(false);
    // Still unlocked, and what it writes now opens with the old PIN.
    const added = await send({
      type: 'ADD_TOTP_ENTRY',
      payload: { entry: { ...totp, id: 'totp-2' } },
    });
    expect(added.success).toBe(true);
    expect((await contentsWith(PIN))?.totp.map((entry) => entry.id)).toContain('totp-2');
  });

  it('switches to the new key when a write that reported failure landed anyway', async () => {
    const { send, secure } = await fullVault();
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation(async (items: StorageData) => {
      await write(items);
      if ('passext_vault_kdf' in items) throw new Error('reported late');
    });

    const change = await send({
      type: 'CHANGE_MASTER_PASSWORD',
      payload: { currentPassword: PIN, newPassword: NEW_PIN },
    });
    local().set.mockImplementation(write);
    await secure.storeTotpEntries([{ ...totp, id: 'totp-3' }]);

    expect(change.success).toBe(true);
    expect((await contentsWith(NEW_PIN))?.totp).toEqual([{ ...totp, id: 'totp-3' }]);
  });

  it('lands a write made during the change under the new key, not lost or under the old one', async () => {
    const { secure } = await fullVault();
    const racing = [{ ...totp, id: 'racing' }];
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const write = local().set.getMockImplementation()!;
    local().set.mockImplementation(async (items: StorageData) => {
      if ('passext_vault_kdf' in items) await held;
      return write(items);
    });

    local().set.mockClear();
    const change = secure.changeMasterPassword(PIN, NEW_PIN);
    while (!local().set.mock.calls.some(([items]) => 'passext_vault_kdf' in items)) await flush();
    // The re-encrypted vault is on its way to storage; a sync merge saves now.
    const save = secure.storeTotpEntries(racing);
    for (let i = 0; i < 5; i++) await flush();
    release();
    expect(await change).toBe(true);
    await save;
    local().set.mockImplementation(write);

    // Removing the PIN decrypts every value strictly, so it fails on any
    // value left under another key.
    const restarted = await loadBackground();
    await restarted.send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: NEW_PIN } });
    const removed = await restarted.send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: NEW_PIN },
    });
    expect(removed.success).toBe(true);
    expect(storage.totp_entries).toEqual(racing);
  });
});

describe('removing the PIN', () => {
  it('removes the KDF record along with the vault', async () => {
    const { send } = await fullVault();

    const removed = await send({
      type: 'REMOVE_MASTER_PASSWORD',
      payload: { currentPassword: PIN },
    });

    expect(removed.success).toBe(true);
    expect(Object.keys(storage).filter((key) => key.startsWith('passext_'))).toEqual([]);
    expect(storage.totp_entries).toEqual([totp]);
  });
});

describe('a vault from a newer version', () => {
  it('says the vault needs a newer version rather than that the PIN is wrong', async () => {
    await fullVault();
    storage.passext_vault_kdf = {
      kdf: 'argon2id',
      params: { m: 65536, t: 3, p: 1 },
      salt: (storage.passext_vault_kdf as { salt: string }).salt,
    };
    const before = vaultState();
    const { send } = await loadBackground();

    const unlock = await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: PIN } });

    expect(unlock).toMatchObject({ success: false, code: 'UNSUPPORTED_KDF' });
    expect(vaultState()).toEqual(before);
  });
});
