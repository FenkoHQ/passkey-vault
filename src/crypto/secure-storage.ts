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

/** chrome.storage.local key holding the auto-lock timeout in minutes; 0 means never. */
export const AUTO_LOCK_SETTING_KEY = 'auto_lock_timeout';
export const AUTO_LOCK_ALARM = 'passext-auto-lock';
const UNLOCKED_SESSION_KEY = 'passext_unlocked_session';
// Activity extends the deadline in memory at once but reaches session storage
// at most this often, so a restarted worker may lock up to this much early.
const SESSION_WRITE_INTERVAL_MS = 15 * 1000;

interface UnlockedSession {
  key: string;
  salt: string;
  activeAt: number;
}

/**
 * Memory-only storage that outlives the service worker until the browser
 * quits. Content scripts cannot read it at its default access level. Absent
 * before Firefox 115, where an unlock lasts only as long as the worker.
 */
function sessionArea(): chrome.storage.StorageArea | null {
  return typeof chrome !== 'undefined' && chrome.storage?.session ? chrome.storage.session : null;
}

function alarms(): typeof chrome.alarms | null {
  return typeof chrome !== 'undefined' && chrome.alarms ? chrome.alarms : null;
}

export interface SecureStorageConfig {
  seedHash: string;
  chainId: string;
  deviceId: string;
  deviceName: string;
  enabled: boolean;
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
  private autoLockMs = 30 * 60 * 1000; // 30 minutes default; 0 never locks
  private activeAt = 0;
  private sessionSavedAt = 0;
  /** Called when the vault locks itself after the timeout. */
  onAutoLock: (() => void) | null = null;

  /**
   * Pick up an unlock made by an earlier instance of the service worker.
   * Chrome stops an idle MV3 service worker after about 30 seconds, and the
   * key used to go with it, locking the vault long before the timeout.
   * Drops the session instead when it has expired or no longer opens the
   * vault (the PIN changed). Returns whether the vault is unlocked.
   */
  async restoreSession(): Promise<boolean> {
    const setting = (await chrome.storage.local.get(AUTO_LOCK_SETTING_KEY))[AUTO_LOCK_SETTING_KEY];
    if (typeof setting === 'number') this.autoLockMs = setting * 60 * 1000;

    const area = sessionArea();
    if (this.isStorageUnlocked() || !area) return this.isStorageUnlocked();
    const session = (await area.get(UNLOCKED_SESSION_KEY))[UNLOCKED_SESSION_KEY] as
      | UnlockedSession
      | undefined;
    if (!session) return false;

    const key = base64ToUint8Array(session.key);
    const check = (await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK))[
      STORAGE_KEYS.MASTER_KEY_CHECK
    ];
    if (this.isIdle(session.activeAt) || !check || !opensVault(check, key)) {
      secureWipe(key);
      await this.clearSession();
      return false;
    }
    if (this.isStorageUnlocked()) {
      // An unlock finished while this was reading; keep its key.
      secureWipe(key);
      return true;
    }

    this.encryptionKey = key;
    this.salt = base64ToUint8Array(session.salt);
    this.isUnlocked = true;
    this.activeAt = session.activeAt;
    this.sessionSavedAt = session.activeAt;
    this.scheduleAutoLock();
    return true;
  }

  /**
   * Lock when the timeout has passed. The alarm calls this, since neither the
   * in-memory timer nor the key survives a stopped service worker.
   */
  async lockIfIdle(): Promise<void> {
    if (!(await this.restoreSession())) return;
    if (this.isIdle(this.activeAt)) this.autoLock();
  }

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
      this.resetAutoLock(true);
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
    void this.clearSession();
  }

  private autoLock(): void {
    this.lock();
    this.onAutoLock?.();
  }

  private isIdle(activeAt: number): boolean {
    return this.autoLockMs > 0 && Date.now() >= activeAt + this.autoLockMs;
  }

  /**
   * Record activity: push the deadline back and, at most every
   * SESSION_WRITE_INTERVAL_MS unless forced, save it with the key.
   */
  private resetAutoLock(forceSave = false): void {
    this.activeAt = Date.now();
    this.scheduleAutoLock();
    if (forceSave || this.activeAt - this.sessionSavedAt >= SESSION_WRITE_INTERVAL_MS) {
      void this.saveSession();
    }
  }

  private scheduleAutoLock(): void {
    if (this.lockTimeout) {
      clearTimeout(this.lockTimeout);
      this.lockTimeout = null;
    }
    if (this.autoLockMs <= 0) return;
    const delay = Math.max(0, this.activeAt + this.autoLockMs - Date.now());
    this.lockTimeout = setTimeout(() => this.autoLock(), delay);
  }

  private async saveSession(): Promise<void> {
    const area = sessionArea();
    if (!area || !this.encryptionKey || !this.salt) return;
    this.sessionSavedAt = this.activeAt;
    await area.set({
      [UNLOCKED_SESSION_KEY]: {
        key: uint8ArrayToBase64(this.encryptionKey),
        salt: uint8ArrayToBase64(this.salt),
        activeAt: this.activeAt,
      } satisfies UnlockedSession,
    });
    await this.scheduleAlarm();
  }

  private async scheduleAlarm(): Promise<void> {
    const api = alarms();
    if (!api) return;
    if (this.autoLockMs > 0) {
      await api.create(AUTO_LOCK_ALARM, { when: this.activeAt + this.autoLockMs });
    } else {
      await api.clear(AUTO_LOCK_ALARM);
    }
  }

  private async clearSession(): Promise<void> {
    this.sessionSavedAt = 0;
    await sessionArea()?.remove(UNLOCKED_SESSION_KEY);
    await alarms()?.clear(AUTO_LOCK_ALARM);
  }

  /**
   * Set auto-lock timeout in milliseconds; 0 never locks. Counts from the
   * last activity rather than restarting the clock.
   */
  setAutoLockTimeout(ms: number): void {
    this.autoLockMs = ms;
    if (this.isStorageUnlocked()) {
      this.scheduleAutoLock();
      void this.scheduleAlarm();
    }
  }

  /**
   * Store sync configuration securely
   */
  async storeSyncConfig(config: SecureStorageConfig): Promise<void> {
    this.ensureUnlocked();

    const encrypted = encryptData(JSON.stringify(cleanSyncConfig(config)), this.encryptionKey!);
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
    // Verify current password
    if (!this.isUnlocked) {
      const verified = await this.initialize(currentPassword);
      if (!verified) {
        return false;
      }
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

      this.resetAutoLock(true);
      return true;
    } catch (error) {
      console.error('Failed to change master password:', error);
      return false;
    }
  }

  /**
   * Remove the master password: verify the current one, then drop the
   * encrypted layer (check value, salt, encrypted blobs) so the vault is no
   * longer locked. Raw display copies in chrome.storage.local are untouched.
   */
  async removeMasterPassword(currentPassword: string): Promise<boolean> {
    const verified = await this.initialize(currentPassword);
    if (!verified) {
      return false;
    }
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
