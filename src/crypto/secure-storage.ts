/**
 * Secure Storage Module for PassKey Vault
 * Provides encrypted storage for sensitive data like seed hashes and passkeys
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';
import { uint8ArrayToBase64, base64ToUint8Array } from '../utils/base64';

const ENCRYPTION_CONFIG = {
  algorithm: 'AES-256-GCM',
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits for GCM
  saltLength: 32, // 256 bits
  iterations: 100000,
} as const;

const STORAGE_KEYS = {
  MASTER_KEY_CHECK: 'passext_master_key_check',
  ENCRYPTED_SYNC_CONFIG: 'passext_encrypted_sync_config',
  ENCRYPTED_PASSKEYS: 'passext_encrypted_passkeys',
  ENCRYPTION_SALT: 'passext_encryption_salt',
} as const;

export interface SecureStorageConfig {
  seedHash: string;
  chainId: string;
  deviceId: string;
  deviceName: string;
  enabled: boolean;
  syncSalt: string | null;
}

export interface EncryptedData {
  data: string;
  iv: string;
  salt: string;
  version: string;
}

async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const key = pbkdf2(sha256, new TextEncoder().encode(password), salt, {
    c: ENCRYPTION_CONFIG.iterations,
    dkLen: ENCRYPTION_CONFIG.keyLength,
  });
  return new Uint8Array(key);
}

function encryptData(data: string, key: Uint8Array): EncryptedData {
  const iv = randomBytes(ENCRYPTION_CONFIG.ivLength);
  const cipher = gcm(key, iv);
  const encrypted = cipher.encrypt(new TextEncoder().encode(data));

  return {
    data: uint8ArrayToBase64(encrypted),
    iv: uint8ArrayToBase64(iv),
    salt: '',
    version: '2.0',
  };
}

function decryptData(encryptedData: EncryptedData, key: Uint8Array): string {
  const iv = base64ToUint8Array(encryptedData.iv);
  const encrypted = base64ToUint8Array(encryptedData.data);

  const cipher = gcm(key, iv);
  const decrypted = cipher.decrypt(encrypted);

  return new TextDecoder().decode(decrypted);
}

function secureWipe(arr: Uint8Array): void {
  crypto.getRandomValues(arr);
  arr.fill(0);
}

/**
 * SecureStorage class for managing encrypted sensitive data
 */
export class SecureStorage {
  private encryptionKey: Uint8Array | null = null;
  private salt: Uint8Array | null = null;
  private isUnlocked = false;
  private lockTimeout: ReturnType<typeof setTimeout> | null = null;
  private autoLockMs = 30 * 60 * 1000; // 30 minutes default

  /**
   * Initialize secure storage with a master password
   * This must be called before any other operations
   */
  async initialize(masterPassword: string): Promise<boolean> {
    try {
      // Load or create salt
      const saltResult = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTION_SALT);
      if (saltResult[STORAGE_KEYS.ENCRYPTION_SALT]) {
        this.salt = base64ToUint8Array(saltResult[STORAGE_KEYS.ENCRYPTION_SALT]);
      } else {
        // First time setup - generate new salt
        this.salt = randomBytes(ENCRYPTION_CONFIG.saltLength);
        await chrome.storage.local.set({
          [STORAGE_KEYS.ENCRYPTION_SALT]: uint8ArrayToBase64(this.salt),
        });
      }

      // Derive encryption key
      this.encryptionKey = await deriveKeyFromPassword(masterPassword, this.salt);

      // Verify password is correct (if we have existing data)
      const checkResult = await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK);
      if (checkResult[STORAGE_KEYS.MASTER_KEY_CHECK]) {
        try {
          const decrypted = decryptData(
            checkResult[STORAGE_KEYS.MASTER_KEY_CHECK],
            this.encryptionKey
          );
          if (decrypted !== 'passkey-vault-check') {
            this.lock();
            return false;
          }
        } catch {
          this.lock();
          return false;
        }
      } else {
        // First time - store check value
        const checkData = encryptData('passkey-vault-check', this.encryptionKey);
        await chrome.storage.local.set({
          [STORAGE_KEYS.MASTER_KEY_CHECK]: checkData,
        });
      }

      this.isUnlocked = true;
      this.resetAutoLock();
      return true;
    } catch (error) {
      console.error('SecureStorage initialization failed:', error);
      this.lock();
      return false;
    }
  }

  /**
   * Check if secure storage is unlocked
   */
  isStorageUnlocked(): boolean {
    return this.isUnlocked && this.encryptionKey !== null;
  }

  /**
   * Check if a master password has been set up
   */
  async isSetup(): Promise<boolean> {
    const result = await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK);
    return !!result[STORAGE_KEYS.MASTER_KEY_CHECK];
  }

  /**
   * Lock the secure storage, wiping encryption key from memory
   */
  lock(): void {
    if (this.encryptionKey) {
      secureWipe(this.encryptionKey);
      this.encryptionKey = null;
    }
    this.isUnlocked = false;
    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
      this.lockTimeout = null;
    }
  }

  /**
   * Reset the auto-lock timer
   */
  private resetAutoLock(): void {
    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
    }
    this.lockTimeout = setTimeout(() => {
      this.lock();
    }, this.autoLockMs);
  }

  /**
   * Set auto-lock timeout in milliseconds
   */
  setAutoLockTimeout(ms: number): void {
    this.autoLockMs = ms;
    if (this.isUnlocked) {
      this.resetAutoLock();
    }
  }

  /**
   * Store sync configuration securely
   */
  async storeSyncConfig(config: SecureStorageConfig): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(config), this.encryptionKey!);
    await chrome.storage.local.set({
      [STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG]: encrypted,
    });

    this.resetAutoLock();
  }

  /**
   * Retrieve sync configuration
   */
  async getSyncConfig(): Promise<SecureStorageConfig | null> {
    this.ensureUnlocked();

    const result = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG);
    if (!result[STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG]) {
      return null;
    }

    try {
      const decrypted = decryptData(
        result[STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG],
        this.encryptionKey!
      );
      this.resetAutoLock();
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to decrypt sync config:', error);
      return null;
    }
  }

  /**
   * Delete sync configuration
   */
  async deleteSyncConfig(): Promise<void> {
    await chrome.storage.local.remove(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG);
  }

  async storePasskeys(passkeys: Record<string, unknown>[]): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(passkeys), this.encryptionKey!);
    await chrome.storage.local.set({
      [STORAGE_KEYS.ENCRYPTED_PASSKEYS]: encrypted,
    });

    this.resetAutoLock();
  }

  async getPasskeys(): Promise<Record<string, unknown>[]> {
    this.ensureUnlocked();

    const result = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTED_PASSKEYS);
    if (!result[STORAGE_KEYS.ENCRYPTED_PASSKEYS]) {
      return [];
    }

    try {
      const decrypted = decryptData(result[STORAGE_KEYS.ENCRYPTED_PASSKEYS], this.encryptionKey!);
      this.resetAutoLock();
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to decrypt passkeys:', error);
      return [];
    }
  }

  async upsertPasskey(passkey: Record<string, unknown>): Promise<void> {
    const passkeys = await this.getPasskeys();
    const index = passkeys.findIndex((p) => p.id === passkey.id);

    if (index >= 0) {
      passkeys[index] = passkey;
    } else {
      passkeys.push(passkey);
    }

    await this.storePasskeys(passkeys);
  }

  async deletePasskey(passkeyId: string): Promise<boolean> {
    const passkeys = await this.getPasskeys();
    const filtered = passkeys.filter((p) => p.id !== passkeyId && p.credentialId !== passkeyId);

    if (filtered.length < passkeys.length) {
      await this.storePasskeys(filtered);
      return true;
    }
    return false;
  }

  async getPasskeysForRp(rpId: string): Promise<Record<string, unknown>[]> {
    const passkeys = await this.getPasskeys();
    return passkeys.filter((p) => p.rpId === rpId);
  }

  /**
   * Change the master password
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<boolean> {
    // Verify current password
    if (!this.isUnlocked) {
      const verified = await this.initialize(currentPassword);
      if (!verified) {
        return false;
      }
    }

    try {
      // Get all existing data
      const syncConfig = await this.getSyncConfig();
      const passkeys = await this.getPasskeys();

      // Generate new salt
      const newSalt = randomBytes(ENCRYPTION_CONFIG.saltLength);
      const newKey = await deriveKeyFromPassword(newPassword, newSalt);

      // Re-encrypt everything with new key
      await chrome.storage.local.set({
        [STORAGE_KEYS.ENCRYPTION_SALT]: uint8ArrayToBase64(newSalt),
      });

      // Update internal state
      if (this.encryptionKey) {
        secureWipe(this.encryptionKey);
      }
      this.encryptionKey = newKey;
      this.salt = newSalt;

      // Store new check value
      const checkData = encryptData('passkey-vault-check', this.encryptionKey);
      await chrome.storage.local.set({
        [STORAGE_KEYS.MASTER_KEY_CHECK]: checkData,
      });

      // Re-encrypt and store data
      if (syncConfig) {
        await this.storeSyncConfig(syncConfig);
      }
      if (passkeys.length > 0) {
        await this.storePasskeys(passkeys);
      }

      this.resetAutoLock();
      return true;
    } catch (error) {
      console.error('Failed to change master password:', error);
      return false;
    }
  }

  /**
   * Wipe all secure data (emergency reset)
   */
  async emergencyWipe(): Promise<void> {
    this.lock();
    await chrome.storage.local.remove([
      STORAGE_KEYS.MASTER_KEY_CHECK,
      STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
      STORAGE_KEYS.ENCRYPTED_PASSKEYS,
      STORAGE_KEYS.ENCRYPTION_SALT,
    ]);
  }

  /**
   * Ensure storage is unlocked before operations
   */
  private ensureUnlocked(): void {
    if (!this.isUnlocked || !this.encryptionKey) {
      throw new Error('Secure storage is locked. Please unlock with master password.');
    }
  }

  /**
   * Generate a random salt for sync PBKDF2 operations
   */
  generateSyncSalt(): string {
    const salt = randomBytes(ENCRYPTION_CONFIG.saltLength);
    return uint8ArrayToBase64(salt);
  }
}

// Export singleton instance
export const secureStorage = new SecureStorage();
