import { cleanSyncConfig } from '../sync/config';
/**
 * Secure Storage Module for Fenko Vault
 * Provides encrypted storage for sensitive data like seed hashes and passkeys
 */

import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';
import { uint8ArrayToBase64, base64ToUint8Array } from '../utils/base64';
import {
  deriveKey,
  legacyKdfSpec,
  newKdfSpec,
  parseKdfSpec,
  sameKdfSpec,
  UnsupportedKdfError,
  type KdfSpec,
} from './kdf';

const ENCRYPTION_CONFIG = {
  algorithm: 'AES-256-GCM',
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits for GCM
  saltLength: 32, // 256 bits
} as const;

const STORAGE_KEYS = {
  MASTER_KEY_CHECK: 'passext_master_key_check',
  ENCRYPTED_SYNC_CONFIG: 'passext_encrypted_sync_config',
  ENCRYPTED_PASSKEYS: 'passext_encrypted_passkeys',
  ENCRYPTED_TOTP_ENTRIES: 'passext_encrypted_totp_entries',
  /** How the vault key is derived from the PIN: a KdfSpec, `{ kdf, params, salt }`. */
  VAULT_KDF: 'passext_vault_kdf',
  /**
   * Legacy: the PBKDF2 salt of a vault from before VAULT_KDF existed. Read
   * only while VAULT_KDF is absent, and removed once the vault is re-keyed.
   */
  ENCRYPTION_SALT: 'passext_encryption_salt',
} as const;

/**
 * Every value encrypted under the vault key apart from the check value. A
 * re-key (PIN change, KDF upgrade) rewrites all of them in the same storage
 * write as the new KDF record and check value.
 */
const ENCRYPTED_BLOB_KEYS = [
  STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
  STORAGE_KEYS.ENCRYPTED_PASSKEYS,
  STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES,
] as const;

/** Everything that makes up the encrypted vault, for removal. */
const VAULT_STORAGE_KEYS = [
  STORAGE_KEYS.MASTER_KEY_CHECK,
  ...ENCRYPTED_BLOB_KEYS,
  STORAGE_KEYS.VAULT_KDF,
  STORAGE_KEYS.ENCRYPTION_SALT,
];

const CHECK_VALUE = 'passkey-vault-check';

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

export { UnsupportedKdfError };

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
    return decryptData(check, key) === CHECK_VALUE;
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

function secureWipe(arr: Uint8Array | null): void {
  if (!arr) return;
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
  /** Tail of the queue that serialises encrypted reads, writes and key swaps. */
  private storageJobs: Promise<unknown> = Promise.resolve();
  /** Called when the vault locks itself after the timeout. */
  onAutoLock: (() => void) | null = null;

  /**
   * Run `job` once every earlier job has finished. Everything that reads or
   * writes an encrypted value, or swaps the key, runs through here, so no
   * write under the old key can land after a re-key has committed, and no
   * read can decrypt with a key that changed between its fetch and its
   * decrypt. The slow key derivations stay outside. A job must not call a
   * public method of this class, which would wait on itself.
   */
  private exclusive<T>(job: () => Promise<T>): Promise<T> {
    const result = this.storageJobs.then(job, job);
    this.storageJobs = result.catch(() => {});
    return result;
  }

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
    return this.exclusive(async () => {
      // An unlock may have finished while this waited its turn; keep its key.
      if (this.isStorageUnlocked()) return true;
      const session = (await area.get(UNLOCKED_SESSION_KEY))[UNLOCKED_SESSION_KEY] as
        | UnlockedSession
        | undefined;
      if (!session) return false;

      const key = base64ToUint8Array(session.key);
      const check = await this.readCheck();
      if (this.isIdle(session.activeAt) || !check || !opensVault(check, key)) {
        secureWipe(key);
        await this.clearSession();
        return false;
      }

      this.encryptionKey = key;
      this.salt = base64ToUint8Array(session.salt);
      this.isUnlocked = true;
      this.activeAt = session.activeAt;
      this.sessionSavedAt = session.activeAt;
      this.scheduleAutoLock();
      return true;
    });
  }

  /**
   * Lock when the timeout has passed. The alarm calls this, since neither the
   * in-memory timer nor the key survives a stopped service worker.
   */
  async lockIfIdle(): Promise<void> {
    if (!(await this.restoreSession())) return;
    if (this.isIdle(this.activeAt)) this.autoLock();
  }

  /** The stored check value, encrypted under the vault key; absent without a PIN. */
  private async readCheck(): Promise<EncryptedData | undefined> {
    return (await chrome.storage.local.get(STORAGE_KEYS.MASTER_KEY_CHECK))[
      STORAGE_KEYS.MASTER_KEY_CHECK
    ];
  }

  /**
   * How the stored vault key is derived: its KDF record or, for a vault from
   * before records existed, PBKDF2 with the legacy salt. Null when neither is
   * stored. Throws UnsupportedKdfError for a record this build cannot use.
   */
  private async readVaultKdf(): Promise<KdfSpec | null> {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.VAULT_KDF,
      STORAGE_KEYS.ENCRYPTION_SALT,
    ]);
    if (stored[STORAGE_KEYS.VAULT_KDF] !== undefined) {
      return parseKdfSpec(stored[STORAGE_KEYS.VAULT_KDF]);
    }
    const legacySalt = stored[STORAGE_KEYS.ENCRYPTION_SALT];
    return legacySalt ? legacyKdfSpec(legacySalt) : null;
  }

  /** Whether the stored vault is still the one `spec` and `key` were checked against. */
  private async stillOpens(spec: KdfSpec, key: Uint8Array): Promise<boolean> {
    const current = await this.readVaultKdf();
    const check = await this.readCheck();
    return !!current && !!check && sameKdfSpec(current, spec) && opensVault(check, key);
  }

  /**
   * Re-encrypt the whole vault from `oldKey` to `newKey` and record `newSpec`,
   * in one storage write. chrome.storage.local applies a multi-key set() as a
   * single transaction (a LevelDB write batch in Chrome, an IndexedDB
   * transaction in Firefox), so a crash or a stopped worker leaves either the
   * old vault or the new one, never blobs under two keys. Every blob is
   * decrypted strictly: one that does not open with the old key aborts the
   * re-key, rather than being dropped or left behind under the old key. The
   * plaintext is carried over as stored, without parsing it.
   *
   * Resolves once the new vault is in storage. A set() that reports a
   * failure is checked against storage, since one that committed anyway must
   * not leave the old key in use. Callers that catch a failure keep the old
   * key only while it still opens the stored vault. Run inside exclusive().
   */
  private async rekey(oldKey: Uint8Array, newSpec: KdfSpec, newKey: Uint8Array): Promise<void> {
    const stored = await chrome.storage.local.get([...ENCRYPTED_BLOB_KEYS]);
    const batch: Record<string, unknown> = {
      [STORAGE_KEYS.VAULT_KDF]: newSpec,
      [STORAGE_KEYS.MASTER_KEY_CHECK]: encryptData(CHECK_VALUE, newKey),
    };
    for (const name of ENCRYPTED_BLOB_KEYS) {
      if (stored[name] === undefined) continue;
      batch[name] = encryptData(decryptData(stored[name], oldKey), newKey);
    }
    try {
      await chrome.storage.local.set(batch);
    } catch (error) {
      const current = await this.readVaultKdf().catch(() => null);
      if (!current || !sameKdfSpec(current, newSpec)) throw error;
    }
    await this.dropStaleLegacySalt();
  }

  /**
   * Remove a legacy PBKDF2 salt that outlived its vault's re-key (a worker
   * stopped between the two writes). VAULT_KDF takes precedence over it, so
   * until then it is only dead weight; a failure is retried next unlock.
   */
  private async dropStaleLegacySalt(): Promise<void> {
    try {
      const stored = await chrome.storage.local.get([
        STORAGE_KEYS.VAULT_KDF,
        STORAGE_KEYS.ENCRYPTION_SALT,
      ]);
      if (
        stored[STORAGE_KEYS.VAULT_KDF] !== undefined &&
        stored[STORAGE_KEYS.ENCRYPTION_SALT] !== undefined
      ) {
        await chrome.storage.local.remove(STORAGE_KEYS.ENCRYPTION_SALT);
      }
    } catch (error) {
      console.error('Failed to remove the legacy vault salt:', error);
    }
  }

  /** Make `key` the live vault key and save the unlock for a restarted worker. */
  private install(key: Uint8Array, spec: KdfSpec): void {
    if (this.encryptionKey && this.encryptionKey !== key) {
      secureWipe(this.encryptionKey);
    }
    this.encryptionKey = key;
    this.salt = base64ToUint8Array(spec.salt);
    this.isUnlocked = true;
    this.resetAutoLock(true);
  }

  /**
   * Unlock with the master PIN, or set it up when the vault has none yet.
   * A vault from before KDF records unlocks with its legacy PBKDF2 key.
   *
   * Returns false for a wrong PIN. Throws UnsupportedKdfError when the vault
   * was set up by a newer build with a KDF this one does not know.
   */
  async initialize(masterPassword: string): Promise<boolean> {
    // Candidate keys stay local until they have opened the check value. A
    // wrong PIN then leaves an unlocked vault unlocked with its own key, and
    // concurrent readers never decrypt with an unverified key.
    let candidate: Uint8Array | null = null;
    try {
      const spec = await this.readVaultKdf();
      const check = await this.readCheck();

      if (!check) {
        // First time setup: one write holds the KDF record and the check value.
        const fresh = newKdfSpec();
        candidate = await deriveKey(masterPassword, fresh);
        const key = candidate;
        const created = await this.exclusive(async () => {
          if (await this.readCheck()) return false; // set up meanwhile
          await chrome.storage.local.set({
            [STORAGE_KEYS.VAULT_KDF]: fresh,
            [STORAGE_KEYS.MASTER_KEY_CHECK]: encryptData(CHECK_VALUE, key),
          });
          this.install(key, fresh);
          // A legacy salt left by an interrupted setup in an older build.
          await this.dropStaleLegacySalt();
          return true;
        });
        if (created) candidate = null;
        return created;
      }
      // A check value without its salt cannot be opened by any PIN.
      if (!spec) return false;

      candidate = await deriveKey(masterPassword, spec);
      if (!opensVault(check, candidate)) return false;

      const verified = candidate;
      const installed = await this.exclusive(async () => {
        // The PIN may have changed while this was deriving.
        if (!(await this.stillOpens(spec, verified))) return false;
        this.install(verified, spec);
        await this.dropStaleLegacySalt();
        return true;
      });
      if (installed) candidate = null;
      return installed;
    } catch (error) {
      if (error instanceof UnsupportedKdfError) throw error;
      console.error('SecureStorage initialization failed:', error);
      return false;
    } finally {
      secureWipe(candidate);
    }
  }

  /**
   * Check a PIN against the stored check value without touching the unlock
   * state: the candidate key is derived locally and wiped afterwards. False
   * when no PIN is set up.
   */
  private async verifyPassword(password: string): Promise<boolean> {
    const spec = await this.readVaultKdf();
    const check = await this.readCheck();
    if (!spec || !check) return false;
    const key = await deriveKey(password, spec);
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
    return !!(await this.readCheck());
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

  /** Encrypt `plaintext` under the live key and store it, with `alongside` in the same write. */
  private async writeBlob(
    storageKey: string,
    plaintext: string,
    alongside: Record<string, unknown> = {}
  ): Promise<void> {
    this.ensureUnlocked();
    const encrypted = encryptData(plaintext, this.encryptionKey!);
    await chrome.storage.local.set({ ...alongside, [storageKey]: encrypted });
    this.resetAutoLock();
  }

  /**
   * Decrypt a stored value under the live key: undefined when absent, throws
   * when it does not decrypt.
   */
  private async readBlob(storageKey: string): Promise<string | undefined> {
    this.ensureUnlocked();
    const stored = (await chrome.storage.local.get(storageKey))[storageKey];
    if (!stored) return undefined;
    return decryptData(stored, this.encryptionKey!);
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
    return this.exclusive(() =>
      this.writeBlob(
        STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG,
        JSON.stringify(cleanSyncConfig(config)),
        alongside
      )
    );
  }

  /**
   * Retrieve sync configuration
   */
  async getSyncConfig(): Promise<SecureStorageConfig | null> {
    this.ensureUnlocked();
    return this.exclusive(async () => {
      try {
        const decrypted = await this.readBlob(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG);
        if (decrypted === undefined) return null;
        this.resetAutoLock();
        const stored = JSON.parse(decrypted);
        const config = cleanSyncConfig(stored);
        if (JSON.stringify(stored) !== JSON.stringify(config)) {
          await this.writeBlob(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG, JSON.stringify(config));
        }
        return config;
      } catch (error) {
        console.error('Failed to decrypt sync config:', error);
        return null;
      }
    });
  }

  /**
   * Delete sync configuration
   */
  deleteSyncConfig(): Promise<void> {
    return this.exclusive(() => chrome.storage.local.remove(STORAGE_KEYS.ENCRYPTED_SYNC_CONFIG));
  }

  async storePasskeys(passkeys: Record<string, unknown>[]): Promise<void> {
    this.ensureUnlocked();
    return this.exclusive(() =>
      this.writeBlob(STORAGE_KEYS.ENCRYPTED_PASSKEYS, JSON.stringify(passkeys))
    );
  }

  async getPasskeys(): Promise<Record<string, unknown>[]> {
    this.ensureUnlocked();
    return this.exclusive(() => this.readList(STORAGE_KEYS.ENCRYPTED_PASSKEYS, 'passkeys'));
  }

  /**
   * A stored list, or [] when it is absent or does not decrypt. The callers
   * refuse at once while locked; a lock while the read waited its turn reads
   * as [], as it did before reads were queued.
   */
  private async readList(storageKey: string, label: string): Promise<Record<string, unknown>[]> {
    try {
      const decrypted = await this.readBlob(storageKey);
      if (decrypted === undefined) return [];
      this.resetAutoLock();
      return JSON.parse(decrypted);
    } catch (error) {
      console.error(`Failed to decrypt ${label}:`, error);
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
    return this.exclusive(() =>
      this.writeBlob(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES, JSON.stringify(entries))
    );
  }

  async getTotpEntries(): Promise<Record<string, unknown>[]> {
    this.ensureUnlocked();
    return this.exclusive(() => this.readList(STORAGE_KEYS.ENCRYPTED_TOTP_ENTRIES, 'TOTP entries'));
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
   * Change the master PIN or passphrase. The new key comes from the current
   * default KDF with a fresh salt, so this also upgrades a legacy vault.
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<boolean> {
    let currentKey: Uint8Array | null = null;
    let newKey: Uint8Array | null = null;
    try {
      // Always check the current PIN. The background only routes this message
      // while unlocked, so a check that ran only when locked never ran at all.
      const spec = await this.readVaultKdf();
      const check = await this.readCheck();
      if (!spec || !check) return false;
      currentKey = await deriveKey(currentPassword, spec);
      if (!opensVault(check, currentKey)) return false;

      const nextSpec = newKdfSpec();
      newKey = await deriveKey(newPassword, nextSpec);

      // Re-encrypt everything with the new key and commit KDF record, check
      // value and blobs in a single set() (see rekey()). Writing the salt
      // separately before the re-encrypted data risked a crash leaving the
      // stored salt out of sync with the blobs, which would lock the user out
      // of both the old and new PIN. Only after the commit does the in-memory
      // key change.
      const oldKey = currentKey;
      const replacement = newKey;
      const changed = await this.exclusive(async () => {
        if (!(await this.stillOpens(spec, oldKey))) return false;
        try {
          await this.rekey(oldKey, nextSpec, replacement);
        } catch (error) {
          // Keep the old key only while it still opens the stored vault.
          if (!(await this.stillOpens(spec, oldKey).catch(() => false))) this.autoLock();
          throw error;
        }
        this.install(replacement, nextSpec);
        return true;
      });
      if (changed) newKey = null;
      return changed;
    } catch (error) {
      console.error('Failed to change master password:', error);
      return false;
    } finally {
      secureWipe(currentKey);
      secureWipe(newKey);
    }
  }

  /**
   * Remove the master password: verify the current one, hand the decrypted
   * vault to `persistPlaintext` to write the cleartext copy, and only once that
   * write has succeeded drop the encrypted layer (check value, KDF record,
   * blobs). A failure or a stopped worker before then leaves the PIN'd vault
   * intact. If only the final removal fails, the vault stays PIN'd and locked,
   * and the next unlock folds the cleartext copy back in and deletes it.
   * `persistPlaintext` runs while this holds the storage queue, so it must not
   * call SecureStorage.
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
    return this.exclusive(async () => {
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
      await chrome.storage.local.remove(VAULT_STORAGE_KEYS);
      return true;
    });
  }

  /** Decrypt a stored blob; null when absent, throws when it does not decrypt. */
  private async readEncrypted<T = Record<string, unknown>[]>(
    storageKey: string
  ): Promise<T | null> {
    const decrypted = await this.readBlob(storageKey);
    return decrypted === undefined ? null : (JSON.parse(decrypted) as T);
  }

  /**
   * Wipe all secure data (emergency reset)
   */
  emergencyWipe(): Promise<void> {
    return this.exclusive(async () => {
      this.lock();
      await chrome.storage.local.remove(VAULT_STORAGE_KEYS);
    });
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
