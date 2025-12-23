import { StorageAgent } from '../src/agents/storage';
import type { PasskeyData } from '../src/types/index';

jest.mock('../src/crypto/encryption', () => ({
  encryptWithPassword: jest.fn(),
  decryptWithPassword: jest.fn(),
  createChecksum: jest.fn(),
  verifyChecksum: jest.fn(),
}));

const { encryptWithPassword, decryptWithPassword, createChecksum, verifyChecksum } =
  jest.requireMock('../src/crypto/encryption');

describe('StorageAgent', () => {
  let storageAgent: StorageAgent;
  let mockChromeStorage: any;

  const createMockPasskey = (): PasskeyData => ({
    id: 'test-passkey-id',
    name: 'Test Passkey',
    rpId: 'example.com',
    rpName: 'Example Site',
    userId: 'test-user-id',
    userName: 'test@example.com',
    publicKey: 'test-public-key',
    privateKey: 'test-private-key',
    counter: 0,
    createdAt: new Date('2024-01-01'),
    lastUsed: new Date('2024-01-01'),
    metadata: {
      deviceType: 'platform',
      backupEligible: true,
      backupState: true,
      transports: ['internal'],
      algorithm: 'ES256',
    },
  });

  const deserializePasskey = (data: any): PasskeyData => ({
    ...data,
    createdAt: new Date(data.createdAt),
    lastUsed: new Date(data.lastUsed),
  });

  beforeEach(async () => {
    jest.clearAllMocks();

    mockChromeStorage = {
      get: jest.fn(),
      set: jest.fn(),
      remove: jest.fn(),
      clear: jest.fn(),
    };

    (global.chrome as any) = {
      storage: {
        local: mockChromeStorage,
      },
    };

    encryptWithPassword.mockResolvedValue({
      data: 'encrypted-data',
      iv: 'test-iv',
      salt: 'test-salt',
      algorithm: 'AES-256-GCM',
    });

    const mockPasskey = createMockPasskey();
    decryptWithPassword.mockResolvedValue(JSON.stringify(mockPasskey));
    createChecksum.mockResolvedValue('test-checksum');
    verifyChecksum.mockResolvedValue(true);

    mockChromeStorage.get.mockImplementation((keys: any) => {
      if (typeof keys === 'string') {
        if (keys === 'passext_metadata') {
          return Promise.resolve({
            passext_metadata: {
              version: '1.0',
              createdAt: Date.now(),
              passkeys: [],
              settings: {
                autoBackup: false,
                biometricAuth: false,
                lockTimeout: 30,
              },
            },
          });
        }
        return Promise.resolve({});
      }
      return Promise.resolve({});
    });

    storageAgent = new StorageAgent();

    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  describe('encryptAndStore', () => {
    it('should store an encrypted passkey', async () => {
      const passkey = createMockPasskey();
      const masterPassword = 'test-password';

      await storageAgent.encryptAndStore(passkey, masterPassword);

      expect(encryptWithPassword).toHaveBeenCalledWith(JSON.stringify(passkey), masterPassword);
      expect(createChecksum).toHaveBeenCalledWith(JSON.stringify(passkey));
      expect(mockChromeStorage.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'passext_passkey_test-passkey-id': expect.objectContaining({
            data: 'encrypted-data',
            checksum: 'test-checksum',
          }),
        })
      );
    });

    it('should throw error on missing required field', async () => {
      const passkey = { ...createMockPasskey() };
      delete (passkey as any).id;

      await expect(storageAgent.encryptAndStore(passkey, 'password')).rejects.toThrow(
        'Missing required field: id'
      );
    });

    it('should throw error on invalid date fields', async () => {
      const passkey = createMockPasskey();
      (passkey as any).createdAt = 'invalid-date';

      await expect(storageAgent.encryptAndStore(passkey, 'password')).rejects.toThrow(
        'Invalid date fields'
      );
    });

    it('should throw error on invalid ID', async () => {
      const passkey = createMockPasskey();
      passkey.id = '';

      await expect(storageAgent.encryptAndStore(passkey, 'password')).rejects.toThrow(
        'Invalid passkey ID'
      );
    });
  });

  describe('retrieveAndDecrypt', () => {
    it('should retrieve and decrypt a passkey', async () => {
      const passkey = createMockPasskey();
      const masterPassword = 'test-password';

      mockChromeStorage.get.mockResolvedValue({
        'passext_passkey_test-passkey-id': {
          data: 'encrypted-data',
          iv: 'test-iv',
          salt: 'test-salt',
          checksum: 'test-checksum',
          createdAt: passkey.createdAt.getTime(),
          lastUsed: passkey.lastUsed.getTime(),
        },
      });

      const result = await storageAgent.retrieveAndDecrypt(passkey.id, masterPassword);

      expect(decryptWithPassword).toHaveBeenCalledWith(
        'encrypted-data',
        'test-iv',
        'test-salt',
        masterPassword
      );
      expect(verifyChecksum).toHaveBeenCalledWith(JSON.stringify(passkey), 'test-checksum');
      expect(result).toEqual(passkey);
    });

    it('should return null for non-existent passkey', async () => {
      mockChromeStorage.get.mockResolvedValue({});

      const result = await storageAgent.retrieveAndDecrypt('non-existent-id', 'password');

      expect(result).toBeNull();
    });

    it('should throw error on failed integrity check', async () => {
      const passkey = createMockPasskey();

      mockChromeStorage.get.mockResolvedValue({
        'passext_passkey_test-passkey-id': {
          data: 'encrypted-data',
          iv: 'test-iv',
          salt: 'test-salt',
          checksum: 'test-checksum',
        },
      });

      verifyChecksum.mockResolvedValue(false);

      await expect(storageAgent.retrieveAndDecrypt(passkey.id, 'password')).rejects.toThrow(
        'Invalid master password or corrupted data'
      );
    });

    it('should update last used timestamp', async () => {
      const passkey = createMockPasskey();

      mockChromeStorage.get.mockResolvedValue({
        'passext_passkey_test-passkey-id': {
          data: 'encrypted-data',
          iv: 'test-iv',
          salt: 'test-salt',
          checksum: 'test-checksum',
          lastUsed: passkey.lastUsed.getTime(),
        },
      });

      await storageAgent.retrieveAndDecrypt(passkey.id, 'password');

      expect(mockChromeStorage.set).toHaveBeenCalled();
    });
  });

  describe('listStoredPasskeys', () => {
    it('should return list of passkeys', async () => {
      const passkey1 = createMockPasskey();
      const passkey2 = { ...createMockPasskey(), id: 'test-passkey-id-2' };

      mockChromeStorage.get.mockImplementation((keys: any) => {
        if (keys === 'passext_metadata') {
          return Promise.resolve({
            passext_metadata: {
              passkeys: [
                { id: passkey1.id, rpId: passkey1.rpId, createdAt: passkey1.createdAt.getTime() },
                { id: passkey2.id, rpId: passkey2.rpId, createdAt: passkey2.createdAt.getTime() },
              ],
            },
          });
        }
        return Promise.resolve({});
      });

      const result = await storageAgent.listStoredPasskeys();

      expect(result).toHaveLength(2);
      expect(result[0].id).toBe(passkey1.id);
      expect(result[1].id).toBe(passkey2.id);
    });

    it('should return empty array when no passkeys exist', async () => {
      mockChromeStorage.get.mockImplementation((keys: any) => {
        if (keys === 'passext_metadata') {
          return Promise.resolve({ passext_metadata: { passkeys: [] } });
        }
        return Promise.resolve({});
      });

      const result = await storageAgent.listStoredPasskeys();

      expect(result).toEqual([]);
    });
  });

  describe('deletePasskey', () => {
    it('should delete a passkey', async () => {
      const passkeyId = 'test-passkey-id';

      mockChromeStorage.get.mockImplementation((keys: any) => {
        if (keys === 'passext_metadata') {
          return Promise.resolve({
            passext_metadata: {
              passkeys: [{ id: passkeyId, rpId: 'example.com', createdAt: Date.now() }],
            },
          });
        }
        return Promise.resolve({});
      });

      await storageAgent.deletePasskey(passkeyId);

      expect(mockChromeStorage.remove).toHaveBeenCalledWith('passext_passkey_test-passkey-id');
      expect(mockChromeStorage.set).toHaveBeenCalled();
    });
  });

  describe('exportEncryptedBackup', () => {
    it('should export encrypted backup', async () => {
      const passkey = createMockPasskey();

      mockChromeStorage.get.mockImplementation((keys: any) => {
        if (keys === 'passext_metadata') {
          return Promise.resolve({
            passext_metadata: {
              passkeys: [
                { id: passkey.id, rpId: passkey.rpId, createdAt: passkey.createdAt.getTime() },
              ],
            },
          });
        }
        if (keys === 'passext_passkey_test-passkey-id') {
          return Promise.resolve({
            'passext_passkey_test-passkey-id': {
              data: 'encrypted-data',
              iv: 'test-iv',
              salt: 'test-salt',
              checksum: 'test-checksum',
            },
          });
        }
        return Promise.resolve({});
      });

      const backup = await storageAgent.exportEncryptedBackup('password');

      expect(backup).toHaveProperty('version', '1.0');
      expect(backup).toHaveProperty('data');
      expect(backup).toHaveProperty('iv');
      expect(backup).toHaveProperty('salt');
      expect(mockChromeStorage.set).toHaveBeenCalledWith(
        expect.objectContaining({
          passext_backup: expect.any(Object),
        })
      );
    });
  });

  describe('importEncryptedBackup', () => {
    it('should import encrypted backup', async () => {
      const backup = {
        version: '1.0',
        algorithm: 'AES-256-GCM',
        data: 'encrypted-backup-data',
        iv: 'test-iv',
        salt: 'test-salt',
        checksum: 'test-checksum',
        timestamp: Date.now(),
      };

      const backupPayload = {
        version: '1.0',
        timestamp: Date.now(),
        passkeys: [createMockPasskey()],
        metadata: {
          passkeys: [{ id: 'test-passkey-id', rpId: 'example.com', createdAt: Date.now() }],
        },
      };

      decryptWithPassword.mockResolvedValueOnce(JSON.stringify(backupPayload));

      await storageAgent.importEncryptedBackup(backup, 'password');

      expect(decryptWithPassword).toHaveBeenCalledWith(
        'encrypted-backup-data',
        'test-iv',
        'test-salt',
        'password'
      );
      expect(encryptWithPassword).toHaveBeenCalled();
      expect(mockChromeStorage.set).toHaveBeenCalled();
    });

    it('should throw error on invalid backup format', async () => {
      const invalidBackup = {
        version: '1.0',
        algorithm: 'AES-256-GCM',
        data: 'encrypted-data',
        iv: 'test-iv',
        salt: 'test-salt',
        checksum: 'test-checksum',
        timestamp: Date.now(),
      };

      decryptWithPassword.mockResolvedValueOnce(JSON.stringify({ invalid: 'format' }));

      await expect(storageAgent.importEncryptedBackup(invalidBackup, 'password')).rejects.toThrow(
        'Invalid backup format'
      );
    });
  });

  describe('getStorageStats', () => {
    it('should return storage statistics', async () => {
      mockChromeStorage.get.mockResolvedValue({
        'passext_passkey_test-id': { data: 'test-data' },
        passext_metadata: { passkeys: [] },
      });

      const stats = await storageAgent.getStorageStats();

      expect(stats).toHaveProperty('usedBytes');
      expect(stats).toHaveProperty('totalBytes', 5242880);
      expect(stats).toHaveProperty('passkeyCount', 0);
      expect(stats.usedBytes).toBeGreaterThan(0);
    });

    it('should handle errors gracefully', async () => {
      mockChromeStorage.get.mockRejectedValue(new Error('Storage error'));

      const stats = await storageAgent.getStorageStats();

      expect(stats).toEqual({
        usedBytes: 0,
        totalBytes: 5242880,
        passkeyCount: 0,
      });
    });
  });

  describe('emergencyWipe', () => {
    it('should wipe all stored data', async () => {
      mockChromeStorage.get.mockResolvedValue({
        'passext_passkey_test-id': { data: 'test-data' },
        passext_backup: { data: 'backup-data' },
        passext_metadata: { passkeys: [] },
        passext_settings: { settings: {} },
      });

      await storageAgent.emergencyWipe();

      expect(mockChromeStorage.remove).toHaveBeenCalledWith(
        expect.arrayContaining([
          'passext_passkey_test-id',
          'passext_backup',
          'passext_metadata',
          'passext_settings',
        ])
      );
    });
  });
});
