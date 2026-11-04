/**
 * Encrypted backups: the new format records its KDF, older files from the
 * extension and from the mobile apps still open, and a file from a newer
 * version is told apart from a wrong password. The older formats are built
 * here the way those builds built them, not with the code under test.
 */

import { createCipheriv, pbkdf2Sync, randomBytes } from 'crypto';
import {
  checkBackupPassword,
  decryptBackup,
  encryptBackup,
  isEncryptedBackup,
  BackupDecryptError,
  UnsupportedBackupError,
  type EncryptedBackupFields,
} from '../src/crypto/backup-crypto';
import { loadBackground, useFakeStorage } from './helpers/pin-background';

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

const PASSWORD = 'tangerine orbit velvet canyon';
const PLAINTEXT = JSON.stringify({ version: '1.0', passkeys: [{ id: 'p' }], totpEntries: [] });

/** What popup.ts and the mobile app wrote before KDF records: PBKDF2 over the raw password. */
function legacyBackup(plaintext: string, password: string): EncryptedBackupFields {
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    data: Buffer.concat([body, cipher.getAuthTag()]).toString('base64'),
    iv: iv.toString('base64'),
    salt: salt.toString('base64'),
    algorithm: 'AES-256-GCM',
  };
}

/** The mobile app's export before KDF records, verbatim: WebCrypto PBKDF2 and AES-GCM. */
async function legacyMobileBackup(plaintext: string, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    encrypted: true,
    version: '1.0',
    exportedAt: new Date().toISOString(),
    data: Buffer.from(encrypted).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    salt: Buffer.from(salt).toString('base64'),
    algorithm: 'AES-256-GCM',
  };
}

describe('a new encrypted backup', () => {
  it('records its KDF, parameters and salt in the header', async () => {
    const backup = await encryptBackup(PLAINTEXT, PASSWORD);

    expect(backup).toEqual({
      algorithm: 'AES-256-GCM',
      kdf: 'scrypt',
      kdfParams: { N: 1024, r: 8, p: 1 },
      salt: expect.any(String),
      iv: expect.any(String),
      data: expect.any(String),
    });
    expect(Buffer.from(backup.salt, 'base64')).toHaveLength(32);
    expect(Buffer.from(backup.iv, 'base64')).toHaveLength(12);
  });

  it('round-trips through a file', async () => {
    const file = JSON.stringify({ encrypted: true, ...(await encryptBackup(PLAINTEXT, PASSWORD)) });
    const parsed = JSON.parse(file);

    expect(isEncryptedBackup(parsed)).toBe(true);
    expect(await decryptBackup(parsed, PASSWORD)).toBe(PLAINTEXT);
  });

  it('round-trips a backup larger than the engine argument limit', async () => {
    const plaintext = JSON.stringify({ passkeys: 'x'.repeat(1_000_000) });
    expect(await decryptBackup(await encryptBackup(plaintext, PASSWORD), PASSWORD)).toBe(plaintext);
  });

  it('opens with the passphrase however its accents were typed', async () => {
    const backup = await encryptBackup(PLAINTEXT, 'crème brûlée au café');
    expect(await decryptBackup(backup, 'crème brûlée au café')).toBe(PLAINTEXT);
  });

  it('rejects a wrong password and a damaged file as such', async () => {
    const backup = await encryptBackup(PLAINTEXT, PASSWORD);
    await expect(decryptBackup(backup, `${PASSWORD}!`)).rejects.toBeInstanceOf(BackupDecryptError);

    const bytes = Buffer.from(backup.data, 'base64');
    bytes[3] ^= 1;
    const damaged = { ...backup, data: bytes.toString('base64') };
    await expect(decryptBackup(damaged, PASSWORD)).rejects.toBeInstanceOf(BackupDecryptError);
    await expect(decryptBackup({ ...backup, iv: 'AAAA' }, PASSWORD)).rejects.toBeInstanceOf(
      BackupDecryptError
    );
  });
});

describe('an older backup', () => {
  it('from the extension still imports', async () => {
    const backup = { encrypted: true, ...legacyBackup(PLAINTEXT, PASSWORD) };
    expect(isEncryptedBackup(backup)).toBe(true);
    expect(await decryptBackup(backup, PASSWORD)).toBe(PLAINTEXT);
  });

  it('from the mobile app still imports', async () => {
    const backup = await legacyMobileBackup(PLAINTEXT, 'short');
    expect(await decryptBackup(backup, 'short')).toBe(PLAINTEXT);
  });

  it('keeps hashing the password bytes as typed, without normalising them', async () => {
    const decomposed = 'café passphrase';
    const backup = legacyBackup(PLAINTEXT, decomposed);
    expect(await decryptBackup(backup, decomposed)).toBe(PLAINTEXT);
    await expect(decryptBackup(backup, decomposed.normalize('NFC'))).rejects.toBeInstanceOf(
      BackupDecryptError
    );
  });

  it('with a wrong password is still a wrong password', async () => {
    await expect(decryptBackup(legacyBackup(PLAINTEXT, PASSWORD), 'not it')).rejects.toBeInstanceOf(
      BackupDecryptError
    );
    await expect(
      decryptBackup({ ...legacyBackup(PLAINTEXT, PASSWORD), salt: 'AAAA' }, PASSWORD)
    ).rejects.toBeInstanceOf(BackupDecryptError);
  });
});

describe('a backup from a newer version', () => {
  const header = async () => encryptBackup(PLAINTEXT, PASSWORD);

  it.each([
    ['an unknown KDF', { kdf: 'argon2id', kdfParams: { m: 65536, t: 3, p: 1 } }],
    ['scrypt beyond the memory this build allows', { kdfParams: { N: 2 ** 22, r: 8, p: 1 } }],
    ['an unknown cipher', { algorithm: 'XChaCha20-Poly1305' }],
  ])('with %s fails as unsupported, not as a wrong password', async (_label, change) => {
    const backup = { ...(await header()), ...change };
    await expect(decryptBackup(backup, PASSWORD)).rejects.toBeInstanceOf(UnsupportedBackupError);
    await expect(decryptBackup(backup, PASSWORD)).rejects.toMatchObject({
      code: 'UNSUPPORTED_BACKUP',
      message: expect.stringMatching(/newer version/),
    });
  });
});

describe('backup passwords', () => {
  it('need 12 characters, counted as a person counts them', () => {
    expect(checkBackupPassword('elevenchars')).toBe('too-short');
    expect(checkBackupPassword('twelve chars')).toBeNull();
    expect(checkBackupPassword('🔑'.repeat(11))).toBe('too-short');
    expect(checkBackupPassword('🔑'.repeat(12))).toBeNull();
    expect(checkBackupPassword(undefined)).toBe('too-short');
  });
});

describe('the background', () => {
  beforeEach(() => {
    useFakeStorage();
  });

  it('encrypts with the KDF recorded and decrypts what it wrote', async () => {
    const { send } = await loadBackground();

    const encrypted = await send({
      type: 'ENCRYPT_BACKUP',
      payload: { data: PLAINTEXT, password: PASSWORD },
    });
    expect(encrypted.success).toBe(true);
    const fields = encrypted.encrypted as EncryptedBackupFields;
    expect(fields).toMatchObject({ kdf: 'scrypt', kdfParams: { N: 1024, r: 8, p: 1 } });

    // What the import page forwards from the file's header.
    const { data, iv, salt, algorithm, kdf, kdfParams } = fields;
    const decrypted = await send({
      type: 'DECRYPT_BACKUP',
      payload: { data, iv, salt, algorithm, kdf, kdfParams, password: PASSWORD },
    });
    expect(decrypted).toEqual({ success: true, data: PLAINTEXT });
  });

  it('refuses a backup password under 12 characters', async () => {
    const { send } = await loadBackground();
    const encrypted = await send({
      type: 'ENCRYPT_BACKUP',
      payload: { data: PLAINTEXT, password: 'eleven char' },
    });
    expect(encrypted).toMatchObject({ success: false, error: expect.stringMatching(/12/) });
  });

  it('still decrypts an older backup', async () => {
    const { send } = await loadBackground();
    const decrypted = await send({
      type: 'DECRYPT_BACKUP',
      payload: { ...legacyBackup(PLAINTEXT, 'old8char'), password: 'old8char' },
    });
    expect(decrypted).toEqual({ success: true, data: PLAINTEXT });
  });

  it('says a newer backup is unsupported, and a wrong password is wrong', async () => {
    const { send } = await loadBackground();
    const backup = await encryptBackup(PLAINTEXT, PASSWORD);

    const newer = await send({
      type: 'DECRYPT_BACKUP',
      payload: { ...backup, kdf: 'argon2id', password: PASSWORD },
    });
    const wrong = await send({
      type: 'DECRYPT_BACKUP',
      payload: { ...backup, password: 'not the password' },
    });

    expect(newer).toMatchObject({ success: false, code: 'UNSUPPORTED_BACKUP' });
    expect(wrong).toMatchObject({ success: false });
    expect(wrong.code).toBeUndefined();
  });
});
