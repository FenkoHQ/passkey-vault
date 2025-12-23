import {
  encrypt,
  decrypt,
  encryptWithPassword,
  decryptWithPassword,
  deriveKey,
  createChecksum,
  verifyChecksum,
  generateSecureRandom,
  secureWipe,
  SessionKeyManager,
} from '../src/crypto/encryption';

describe('Encryption Module', () => {
  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const plaintext = 'Hello, World!';
      const key = new Uint8Array(32).fill(1);

      const encrypted = await encrypt(plaintext, key);
      expect(encrypted).toHaveProperty('data');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted.algorithm).toBe('AES-256-GCM');

      const decrypted = await decrypt(
        encrypted.data,
        key,
        new Uint8Array(
          atob(encrypted.iv)
            .split('')
            .map((c) => c.charCodeAt(0))
        )
      );
      expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with wrong key', async () => {
      const plaintext = 'Secret data';
      const correctKey = new Uint8Array(32).fill(1);
      const wrongKey = new Uint8Array(32).fill(2);

      const encrypted = await encrypt(plaintext, correctKey);
      await expect(
        decrypt(
          encrypted.data,
          wrongKey,
          new Uint8Array(
            atob(encrypted.iv)
              .split('')
              .map((c) => c.charCodeAt(0))
          )
        )
      ).rejects.toThrow('Decryption failed');
    });

    it('should fail to decrypt with corrupted data', async () => {
      const plaintext = 'Secret data';
      const key = new Uint8Array(32).fill(1);

      const encrypted = await encrypt(plaintext, key);
      const corruptedData = 'corrupted' + encrypted.data;

      await expect(
        decrypt(
          corruptedData,
          key,
          new Uint8Array(
            atob(encrypted.iv)
              .split('')
              .map((c) => c.charCodeAt(0))
          )
        )
      ).rejects.toThrow('Decryption failed');
    });

    it('should handle empty strings', async () => {
      const plaintext = '';
      const key = new Uint8Array(32).fill(1);

      const encrypted = await encrypt(plaintext, key);
      const decrypted = await decrypt(
        encrypted.data,
        key,
        new Uint8Array(
          atob(encrypted.iv)
            .split('')
            .map((c) => c.charCodeAt(0))
        )
      );

      expect(decrypted).toBe('');
    });

    it('should handle Unicode characters', async () => {
      const plaintext = 'Hello 🌍 世界 👋';
      const key = new Uint8Array(32).fill(1);

      const encrypted = await encrypt(plaintext, key);
      const decrypted = await decrypt(
        encrypted.data,
        key,
        new Uint8Array(
          atob(encrypted.iv)
            .split('')
            .map((c) => c.charCodeAt(0))
        )
      );

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('encryptWithPassword and decryptWithPassword', () => {
    it('should encrypt and decrypt with password', async () => {
      const plaintext = 'My secret password';
      const password = 'master-password';

      const encrypted = await encryptWithPassword(plaintext, password);
      expect(encrypted).toHaveProperty('data');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('salt');
      expect(encrypted.algorithm).toBe('AES-256-GCM');

      const decrypted = await decryptWithPassword(
        encrypted.data,
        encrypted.iv,
        encrypted.salt,
        password
      );
      expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with wrong password', async () => {
      const plaintext = 'My secret password';
      const correctPassword = 'master-password';
      const wrongPassword = 'wrong-password';

      const encrypted = await encryptWithPassword(plaintext, correctPassword);
      await expect(
        decryptWithPassword(encrypted.data, encrypted.iv, encrypted.salt, wrongPassword)
      ).rejects.toThrow('Failed to decrypt data');
    });
  });

  describe('deriveKey', () => {
    it('should derive a key with provided salt', async () => {
      const password = 'test-password';
      const salt = new Uint8Array(32).fill(1);

      const result = await deriveKey(password, salt);
      expect(result.key).toBeInstanceOf(Uint8Array);
      expect(result.key.length).toBe(32);
      expect(result.salt).toEqual(salt);
    });

    it('should generate random salt if not provided', async () => {
      const password = 'test-password';

      const result1 = await deriveKey(password);
      const result2 = await deriveKey(password);

      expect(result1.salt).not.toEqual(result2.salt);
      expect(result1.key.length).toBe(32);
      expect(result2.key.length).toBe(32);
    });

    it('should derive same key with same password and salt', async () => {
      const password = 'test-password';
      const salt = new Uint8Array(32).fill(1);

      const result1 = await deriveKey(password, salt);
      const result2 = await deriveKey(password, salt);

      expect(result1.key).toEqual(result2.key);
    });
  });

  describe('createChecksum and verifyChecksum', () => {
    it('should create checksum for data', async () => {
      const data = 'test data';
      const checksum = await createChecksum(data);

      expect(typeof checksum).toBe('string');
      expect(checksum.length).toBeGreaterThan(0);
      expect(checksum).not.toContain('=');
      expect(checksum).not.toContain('+');
      expect(checksum).not.toContain('/');
    });

    it('should verify correct checksum', async () => {
      const data = 'test data';
      const checksum = await createChecksum(data);

      const isValid = await verifyChecksum(data, checksum);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect checksum', async () => {
      const data1 = 'test data 1';
      const data2 = 'test data 2';
      const checksum = await createChecksum(data1);

      const isValid = await verifyChecksum(data2, checksum);
      expect(isValid).toBe(false);
    });

    it('should produce same checksum for same data', async () => {
      const data = 'test data';
      const checksum1 = await createChecksum(data);
      const checksum2 = await createChecksum(data);

      expect(checksum1).toBe(checksum2);
    });
  });

  describe('generateSecureRandom', () => {
    it('should generate random string of default length', () => {
      const random = generateSecureRandom();
      expect(random.length).toBe(32);
      expect(typeof random).toBe('string');
    });

    it('should generate random string of specified length', () => {
      const random = generateSecureRandom(16);
      expect(random.length).toBe(16);
    });

    it('should generate different values on multiple calls', () => {
      const random1 = generateSecureRandom();
      const random2 = generateSecureRandom();

      expect(random1).not.toBe(random2);
    });
  });

  describe('secureWipe', () => {
    it('should wipe Uint8Array data', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      secureWipe(data);

      expect(data.every((byte) => byte === 0)).toBe(true);
    });

    it('should handle string gracefully', () => {
      expect(() => secureWipe('test')).not.toThrow();
    });

    it('should overwrite with random data first', () => {
      const data = new Uint8Array(100);
      for (let i = 0; i < data.length; i++) {
        data[i] = 42;
      }
      secureWipe(data);

      expect(data.every((byte) => byte === 0)).toBe(true);
    });
  });

  describe('SessionKeyManager', () => {
    let manager: SessionKeyManager;

    beforeEach(() => {
      manager = new SessionKeyManager();
    });

    afterEach(() => {
      manager.destroy();
    });

    it('should create and retrieve session key', async () => {
      const sessionId = 'test-session';
      const password = 'test-password';

      await manager.createSessionKey(sessionId, password, 60000);
      const key = manager.getSessionKey(sessionId);

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key).not.toBeNull();
      expect(key?.length).toBe(32);
    });

    it('should return null for non-existent session', () => {
      const key = manager.getSessionKey('non-existent');
      expect(key).toBeNull();
    });

    it('should expire session after TTL', async () => {
      const sessionId = 'test-session';
      const password = 'test-password';

      await manager.createSessionKey(sessionId, password, 100);

      const keyBefore = manager.getSessionKey(sessionId);
      expect(keyBefore).not.toBeNull();

      await new Promise((resolve) => setTimeout(resolve, 150));

      const keyAfter = manager.getSessionKey(sessionId);
      expect(keyAfter).toBeNull();
    });

    it('should remove session key', async () => {
      const sessionId = 'test-session';
      const password = 'test-password';

      await manager.createSessionKey(sessionId, password);
      expect(manager.getSessionKey(sessionId)).not.toBeNull();

      manager.removeSessionKey(sessionId);
      expect(manager.getSessionKey(sessionId)).toBeNull();
    });

    it('should handle multiple sessions', async () => {
      const session1 = 'session-1';
      const session2 = 'session-2';
      const password = 'test-password';

      await manager.createSessionKey(session1, password);
      await manager.createSessionKey(session2, password);

      const key1 = manager.getSessionKey(session1);
      const key2 = manager.getSessionKey(session2);

      expect(key1).not.toBeNull();
      expect(key2).not.toBeNull();
      expect(key1).not.toEqual(key2);
    });

    it('should destroy all keys on destroy', async () => {
      const session1 = 'session-1';
      const session2 = 'session-2';
      const password = 'test-password';

      await manager.createSessionKey(session1, password);
      await manager.createSessionKey(session2, password);

      manager.destroy();

      expect(manager.getSessionKey(session1)).toBeNull();
      expect(manager.getSessionKey(session2)).toBeNull();
    });
  });
});
