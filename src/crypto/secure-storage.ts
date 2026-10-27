import { cleanSyncConfig } from '../sync/config';
/**
 * Secure Storage Module for Fenko Vault
 * Provides encrypted storage for sensitive data like seed hashes and passkeys
 */

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
  ENCRYPTED_TOTP_ENTRIES: 'passext_encrypted_totp_entries',
  ENCRYPTION_SALT: 'passext_encryption_salt',
} as const;

export interface SecureStorageConfig {
  seedHash: string;
  chainId: string;
  deviceId: string;
  deviceName: string;
  enabled: boolean;
}

/** The decrypted vault handed over when the master password is removed. */
export interface DecryptedVault {
  passkeys: Record<string, unknown>[];
  totpEntries: Record<string, unknown>[];
  syncConfig: SecureStorageConfig | null;
}

export interface EncryptedData {
  data: string;
  iv: string;
  salt: string;
  version: string;
}

async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const key = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: new Uint8Array(salt),
      iterations: ENCRYPTION_CONFIG.iterations,
    },
    material,
    ENCRYPTION_CONFIG.keyLength * 8
  );
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

function opensVault(check: EncryptedData, key: Uint8Array): boolean {
  try {
    return decryptData(check, key) === 'passkey-vault-check';
  } catch {
    return false;
  }
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
    // The candidate key stays local until it has opened the check value. A
    // wrong PIN then leaves an unlocked vault unlocked with its own key, and
    // concurrent readers never decrypt with an unverified key.
    let key: Uint8Array | null = null;
    try {
      // Load or create salt
      let salt: Uint8Array;
      const saltResult = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTION_SALT);
      if (saltResult[STORAGE_KEYS.ENCRYPTION_SALT]) {
        salt = base64ToUint8Array(saltResult[STORAGE_KEYS.ENCRYPTION_SALT]);
      } else {
        // First time setup - generate new salt
        salt = randomBytes(ENCRYPTION_CONFIG.saltLength);
        await chrome.storage.local.set({
          [STORAGE_KEYS.ENCRYPTION_SALT]: uint8ArrayToBase64(salt),
        });
      }

      // Derive encryption key
      key = await deriveKeyFromPassword(masterPassword, salt);

      // Verify password is correct (if we have existing data)
      const checkResult = await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK);
      if (checkResult[STORAGE_KEYS.MASTER_KEY_CHECK]) {
        if (!opensVault(checkResult[STORAGE_KEYS.MASTER_KEY_CHECK], key)) {
          secureWipe(key);
          return false;
        }
      } else {
        // First time - store check value
        const checkData = encryptData('passkey-vault-check', key);
        await chrome.storage.local.set({
          [STORAGE_KEYS.MASTER_KEY_CHECK]: checkData,
        });
      }

      if (this.encryptionKey) {
        secureWipe(this.encryptionKey);
      }
      this.encryptionKey = key;
      this.salt = salt;
      this.isUnlocked = true;
      this.resetAutoLock();
      return true;
    } catch (error) {
      console.error('SecureStorage initialization failed:', error);
      if (key) secureWipe(key);
      return false;
    }
  }

  /**
   * Check a PIN against the stored check value without touching the unlock
   * state: the candidate key is derived locally and wiped afterwards. False
   * when no PIN is set up.
   */
  private async verifyPassword(password: string): Promise<boolean> {
    const salt = (await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTION_SALT))[
      STORAGE_KEYS.ENCRYPTION_SALT
    ];
    const check = (await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK))[
      STORAGE_KEYS.MASTER_KEY_CHECK
    ];
    if (!salt || !check) return false;
    const key = await deriveKeyFromPassword(password, base64ToUint8Array(salt));
    try {
      return opensVault(check, key);
    } finally {
      secureWipe(key);
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
   * Store sync configuration securely. `alongside` holds other keys to write
   * in the same storage operation, so the two land together or not at all.
   */
  async storeSyncConfig(
    config: SecureStorageConfig,
    alongside: Record<string, unknown> = {}
  ): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(cleanSyncConfig(config)), this.encryptionKey!);
    await chrome.storage.local.set({
      ...alongside,
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
      const stored = JSON.parse(decrypted);
      const config = cleanSyncConfig(stored);
      if (JSON.stringify(stored) !== JSON.stringify(config)) {
        await this.storeSyncConfig(config);
      }
      return config;
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

  async storeTotpEntries(entries: Record<string, unknown>[]): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(entries), this.encryptionKey!);
    await chrome.storage.local.set({
      [STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES]: encrypted,
    });

    this.resetAutoLock();
  }

  async getTotpEntries(): Promise<Record<string, unknown>[]> {
    this.ensureUnlocked();

    const result = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES);
    if (!result[STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES]) {
      return [];
    }

    try {
      const decrypted = decryptData(
        result[STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES],
        this.encryptionKey!
      );
      this.resetAutoLock();
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Failed to decrypt TOTP entries:', error);
      return [];
    }
  }

  async upsertTotpEntry(entry: Record<string, unknown>): Promise<void> {
    const entries = await this.getTotpEntries();
    const index = entries.findIndex((e) => e.id === entry.id);

    if (index >= 0) {
      entries[index] = entry;
    } else {
      entries.push(entry);
    }

    await this.storeTotpEntries(entries);
  }

  async deleteTotpEntry(id: string): Promise<boolean> {
    const entries = await this.getTotpEntries();
    const filtered = entries.filter((e) => e.id !== id);

    if (filtered.length < entries.length) {
      await this.storeTotpEntries(filtered);
      return true;
    }
    return false;
  }

  /**
   * Change the master password
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<boolean> {
    // Always check the current PIN. The background only routes this message
    // while unlocked, so a check that ran only when locked never ran at all.
    if (!(await this.verifyPassword(currentPassword))) {
      return false;
    }
    if (!this.isStorageUnlocked() && !(await this.initialize(currentPassword))) {
      return false;
    }

    try {
      // Get all existing data (decrypted with the current key)
      const syncConfig = await this.getSyncConfig();
      const passkeys = await this.getPasskeys();
      const totpEntries = await this.getTotpEntries();

      // Generate new salt and key
      const newSalt = randomBytes(ENCRYPTION_CONFIG.saltLength);
      const newKey = await deriveKeyFromPassword(newPassword, newSalt);

      // Re-encrypt everything with the new key IN MEMORY first, then commit
      // salt, check value, and all blobs in a single atomic set(). Writing the
      // salt separately before the re-encrypted data risks a crash leaving the
      // stored salt out of sync with the blobs, which would lock the user out
      // of both the old and new PIN.
      const batch: Record<string, unknown> = {
        [STORAGE_KEYS.ENCRYPTION_SALT]: uint8ArrayToBase64(newSalt),
        [STORAGE_KEYS.MASTER_KEY_CHECK]: encryptData('passkey-vault-check', newKey),
      };
      if (syncConfig) {
        batch[STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG] = encryptData(JSON.stringify(syncConfig), newKey);
      }
      if (passkeys.length > 0) {
        batch[STORAGE_KEYS.ENCRYPTED_PASSKEYS] = encryptData(JSON.stringify(passkeys), newKey);
      }
      if (totpEntries.length > 0) {
        batch[STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES] = encryptData(
          JSON.stringify(totpEntries),
          newKey
        );
      }

      await chrome.storage.local.set(batch);

      // Only after the atomic commit succeeds, swap the in-memory key.
      if (this.encryptionKey) {
        secureWipe(this.encryptionKey);
      }
      this.encryptionKey = newKey;
      this.salt = newSalt;

      this.resetAutoLock();
      return true;
    } catch (error) {
      console.error('Failed to change master password:', error);
      return false;
    }
  }

  /**
   * Remove the master password: verify the current one, hand the decrypted
   * vault to `persistPlaintext` to write the cleartext copy, and only once that
   * write has succeeded drop the encrypted layer (check value, salt, blobs).
   * A failure or a stopped worker before then leaves the PIN'd vault intact.
   * If only the final removal fails, the vault stays PIN'd and locked, and the
   * next unlock folds the cleartext copy back in and deletes it.
   */
  async removeMasterPassword(
    currentPassword: string,
    persistPlaintext: (vault: DecryptedVault) => Promise<void>
  ): Promise<boolean> {
    // A side-effect-free check: initialize() here used to lock the vault on a
    // mistyped PIN without disconnecting sync.
    if (!(await this.verifyPassword(currentPassword))) {
      return false;
    }
    // Strict reads: a blob that fails to decrypt aborts the removal rather
    // than being replaced by an empty cleartext list and then deleted.
    const syncConfig = await this.readEncrypted<SecureStorageConfig>(
      STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG
    );
    await persistPlaintext({
      passkeys: (await this.readEncrypted(STORAGE_KEYS.ENCRYPTED_PASSKEYS)) || [],
      totpEntries: (await this.readEncrypted(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES)) || [],
      syncConfig: syncConfig ? cleanSyncConfig(syncConfig) : null,
    });
    this.lock();
    await chrome.storage.local.remove([
      STORAGE_KEYS.MASTER_KEY_CHECK,
      STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
      STORAGE_KEYS.ENCRYPTED_PASSKEYS,
      STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES,
      STORAGE_KEYS.ENCRYPTION_SALT,
    ]);
    return true;
  }

  /** Decrypt a stored blob; null when absent, throws when it does not decrypt. */
  private async readEncrypted<T = Record<string, unknown>[]>(
    storageKey: string
  ): Promise<T | null> {
    this.ensureUnlocked();
    const stored = (await chrome.storage.local.get(storageKey))[storageKey];
    if (!stored) return null;
    return JSON.parse(decryptData(stored, this.encryptionKey!)) as T;
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
      STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES,
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
