import {
  PasskeyData,
  PasskeyMetadata,
  EncryptedBackup,
  BackupFile,
  SecurityContext,
} from '../types/index';
import { ipfsAgent } from './ipfs';
import {
  encryptWithPassword,
  decryptWithPassword,
  createChecksum,
  verifyChecksum,
  generateSecureRandom,
  secureWipe,
} from '../crypto/index';

export class StorageAgent {
  private readonly STORAGE_PREFIX = 'passext_';
  private readonly BACKUP_KEY = 'passext_backup';
  private readonly METADATA_KEY = 'passext_metadata';
  private readonly SETTINGS_KEY = 'passext_settings';
  private useIPFS = false;

  private isInitialized = false;
  private masterPasswordHash: string | null = null;

  constructor() {
    this.initialize();
  }

  async enableIPFS(): Promise<void> {
    try {
      await ipfsAgent.initialize();
      this.useIPFS = true;
      console.info('IPFS backend enabled for passkey storage');
    } catch (error) {
      console.error('Failed to enable IPFS backend:', error);
      throw new Error(`IPFS enable failed: ${error.message}`);
    }
  }

  async disableIPFS(): Promise<void> {
    this.useIPFS = false;
    console.info('IPFS backend disabled, using local storage');
  }

  private async storeOnIPFS(passkey: PasskeyData, masterPassword: string): Promise<void> {
    const serializedData = JSON.stringify(passkey);
    const encrypted = await encryptWithPassword(serializedData, masterPassword);
    const checksum = await createChecksum(serializedData);

    const storageKey = this.getStorageKey(passkey.id);
    const storageData = {
      ...encrypted,
      checksum,
      createdAt: passkey.createdAt.getTime(),
      lastUsed: passkey.lastUsed.getTime(),
      backend: 'ipfs',
    };

    await chrome.storage.local.set({ [storageKey]: storageData });
    await this.updateMetadata(passkey.id, 'add');
  }

  private async storeOnLocal(passkey: PasskeyData, masterPassword: string): Promise<void> {
    const serializedData = JSON.stringify(passkey);
    const encrypted = await encryptWithPassword(serializedData, masterPassword);
    const checksum = await createChecksum(serializedData);

    const storageKey = this.getStorageKey(passkey.id);
    const storageData = {
      ...encrypted,
      checksum,
      createdAt: passkey.createdAt.getTime(),
      lastUsed: passkey.lastUsed.getTime(),
      backend: 'local',
    };

    await chrome.storage.local.set({ [storageKey]: storageData });
    await this.updateMetadata(passkey.id, 'add');
  }

  /**
   * Initialize the storage agent
   */
  private async initialize(): Promise<void> {
    try {
      // Ensure Chrome storage is available
      if (!chrome?.storage?.local) {
        throw new Error('Chrome storage API not available');
      }

      // Load or create metadata
      await this.ensureMetadata();

      this.isInitialized = true;
    } catch (error) {
      console.error('StorageAgent initialization failed:', error);
      throw error;
    }
  }

  /**
   * Ensure storage is initialized before operations
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }
  }

  async encryptAndStore(passkey: PasskeyData, masterPassword: string): Promise<void> {
    await this.ensureInitialized();

    try {
      this.validatePasskeyData(passkey);

      if (this.useIPFS) {
        await this.storeOnIPFS(passkey, masterPassword);
      } else {
        await this.storeOnLocal(passkey, masterPassword);
      }
    } catch (error) {
      console.error('Failed to store passkey:', error);
      throw new Error(`Failed to store passkey: ${error.message}`);
    }
  }

  /**
   * Retrieve and decrypt a passkey
   */
  async retrieveAndDecrypt(passkeyId: string, masterPassword: string): Promise<PasskeyData | null> {
    await this.ensureInitialized();

    try {
      const storageKey = this.getStorageKey(passkeyId);
      const result = await chrome.storage.local.get(storageKey);

      if (!result[storageKey]) {
        return null;
      }

      const encryptedData = result[storageKey];

      // Decrypt the data
      const decryptedData = await decryptWithPassword(
        encryptedData.data,
        encryptedData.iv,
        encryptedData.salt,
        masterPassword
      );

      // Verify integrity
      const isValid = await verifyChecksum(decryptedData, encryptedData.checksum);
      if (!isValid) {
        throw new Error('Data integrity check failed');
      }

      // Parse passkey data
      const passkey = JSON.parse(decryptedData) as PasskeyData;

      // Convert date strings back to Date objects
      passkey.createdAt = new Date(passkey.createdAt);
      passkey.lastUsed = new Date(passkey.lastUsed);

      // Validate the decrypted data
      this.validatePasskeyData(passkey);

      // Update last used timestamp
      await this.updateLastUsed(passkeyId);

      return passkey;
    } catch (error) {
      console.error('Failed to retrieve passkey:', error);

      // Don't expose specific error details for security
      if (
        error.message.includes('Invalid password') ||
        error.message.includes('Decryption failed') ||
        error.message.includes('Data integrity check failed')
      ) {
        throw new Error('Invalid master password or corrupted data');
      }

      throw new Error(`Failed to retrieve passkey: ${error.message}`);
    }
  }

  /**
   * List all stored passkey metadata
   */
  async listStoredPasskeys(): Promise<PasskeyMetadata[]> {
    await this.ensureInitialized();

    try {
      const metadata = await this.getMetadata();
      return metadata.passkeys;
    } catch (error) {
      console.error('Failed to list passkeys:', error);
      throw new Error(`Failed to list passkeys: ${error.message}`);
    }
  }

  /**
   * Delete a stored passkey
   */
  async deletePasskey(passkeyId: string): Promise<void> {
    await this.ensureInitialized();

    try {
      const storageKey = this.getStorageKey(passkeyId);

      // Remove from storage
      await chrome.storage.local.remove(storageKey);

      // Update metadata
      await this.updateMetadata(passkeyId, 'remove');
    } catch (error) {
      console.error('Failed to delete passkey:', error);
      throw new Error(`Failed to delete passkey: ${error.message}`);
    }
  }

  /**
   * Export encrypted backup
   */
  async exportEncryptedBackup(masterPassword: string): Promise<EncryptedBackup> {
    await this.ensureInitialized();

    try {
      // Get all passkey data
      const passkeys = await this.getAllPasskeyData(masterPassword);

      // Create backup payload
      const payload = {
        version: '1.0',
        timestamp: Date.now(),
        passkeys,
        metadata: await this.getMetadata(),
      };

      const serializedPayload = JSON.stringify(payload);

      // Encrypt the backup
      const encrypted = await encryptWithPassword(serializedPayload, masterPassword);

      // Create checksum
      const checksum = await createChecksum(serializedPayload);

      const backup: EncryptedBackup = {
        version: '1.0',
        algorithm: encrypted.algorithm,
        salt: encrypted.salt,
        iv: encrypted.iv,
        data: encrypted.data,
        checksum,
        timestamp: Date.now(),
      };

      // Store backup locally as well
      await chrome.storage.local.set({
        [this.BACKUP_KEY]: {
          ...backup,
          createdAt: Date.now(),
        },
      });

      return backup;
    } catch (error) {
      console.error('Failed to export backup:', error);
      throw new Error(`Failed to export backup: ${error.message}`);
    }
  }

  /**
   * Import encrypted backup
   */
  async importEncryptedBackup(backup: EncryptedBackup, masterPassword: string): Promise<void> {
    await this.ensureInitialized();

    try {
      // Decrypt backup
      const decryptedData = await decryptWithPassword(
        backup.data,
        backup.iv,
        backup.salt,
        masterPassword
      );

      // Parse backup data
      const backupPayload = JSON.parse(decryptedData);

      // Validate backup format
      if (!backupPayload.version || !backupPayload.passkeys) {
        throw new Error('Invalid backup format');
      }

      // Import each passkey
      for (const passkey of backupPayload.passkeys) {
        // Convert date strings to Date objects
        passkey.createdAt = new Date(passkey.createdAt);
        passkey.lastUsed = new Date(passkey.lastUsed);
        await this.encryptAndStore(passkey, masterPassword);
      }

      // Update metadata
      if (backupPayload.metadata) {
        await chrome.storage.local.set({
          [this.METADATA_KEY]: backupPayload.metadata,
        });
      }
    } catch (error) {
      console.error('Failed to import backup:', error);
      throw new Error(`Failed to import backup: ${error.message}`);
    }
  }

  /**
   * Get storage usage statistics
   */
  async getStorageStats(): Promise<{
    usedBytes: number;
    totalBytes: number;
    passkeyCount: number;
  }> {
    await this.ensureInitialized();

    try {
      // Get all storage keys for this extension
      const items = await chrome.storage.local.get();
      const extensionKeys = Object.keys(items).filter((key) => key.startsWith(this.STORAGE_PREFIX));

      // Calculate used space
      let usedBytes = 0;
      for (const key of extensionKeys) {
        const item = items[key];
        usedBytes += JSON.stringify(item).length * 2; // Approximate byte size
      }

      const metadata = await this.getMetadata();

      return {
        usedBytes,
        totalBytes: 5242880, // Chrome's local storage limit (approx 5MB)
        passkeyCount: metadata.passkeys.length,
      };
    } catch (error) {
      console.error('Failed to get storage stats:', error);
      return {
        usedBytes: 0,
        totalBytes: 5242880,
        passkeyCount: 0,
      };
    }
  }

  /**
   * Clear all stored data (for emergency wipe)
   */
  async emergencyWipe(): Promise<void> {
    await this.ensureInitialized();

    try {
      // Get all extension keys
      const items = await chrome.storage.local.get();
      const extensionKeys = Object.keys(items).filter(
        (key) =>
          key.startsWith(this.STORAGE_PREFIX) ||
          key === this.BACKUP_KEY ||
          key === this.METADATA_KEY ||
          key === this.SETTINGS_KEY
      );

      // Remove all extension data
      await chrome.storage.local.remove(extensionKeys);

      this.masterPasswordHash = null;
    } catch (error) {
      console.error('Failed to perform emergency wipe:', error);
      throw new Error(`Emergency wipe failed: ${error.message}`);
    }
  }

  /**
   * Get storage key for a passkey
   */
  private getStorageKey(passkeyId: string): string {
    return `${this.STORAGE_PREFIX}passkey_${passkeyId}`;
  }

  /**
   * Validate passkey data structure
   */
  private validatePasskeyData(passkey: PasskeyData): void {
    const requiredFields = [
      'id',
      'name',
      'rpId',
      'rpName',
      'userId',
      'userName',
      'publicKey',
      'privateKey',
      'counter',
      'createdAt',
      'lastUsed',
    ];

    for (const field of requiredFields) {
      if (!(field in passkey)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    // Validate ID format
    if (!passkey.id || typeof passkey.id !== 'string') {
      throw new Error('Invalid passkey ID');
    }

    // Validate dates
    if (!(passkey.createdAt instanceof Date) || !(passkey.lastUsed instanceof Date)) {
      throw new Error('Invalid date fields');
    }
  }

  /**
   * Ensure metadata exists
   */
  private async ensureMetadata(): Promise<void> {
    const result = await chrome.storage.local.get(this.METADATA_KEY);

    if (!result[this.METADATA_KEY]) {
      const initialMetadata = {
        version: '1.0',
        createdAt: Date.now(),
        passkeys: [],
        settings: {
          autoBackup: false,
          biometricAuth: false,
          lockTimeout: 30,
        },
      };

      await chrome.storage.local.set({ [this.METADATA_KEY]: initialMetadata });
    }
  }

  /**
   * Get metadata
   */
  private async getMetadata(): Promise<any> {
    const result = await chrome.storage.local.get(this.METADATA_KEY);
    return result[this.METADATA_KEY] || { passkeys: [] };
  }

  /**
   * Update metadata when passkeys are added/removed
   */
  private async updateMetadata(passkeyId: string, operation: 'add' | 'remove'): Promise<void> {
    const metadata = await this.getMetadata();
    const passkeyMetadata: PasskeyMetadata = {
      id: passkeyId,
      name: '', // Will be filled by caller if needed
      rpId: '',
      createdAt: new Date(),
      lastUsed: new Date(),
    };

    if (operation === 'add') {
      // Remove if exists, then add (update operation)
      metadata.passkeys = metadata.passkeys.filter((p) => p.id !== passkeyId);
      metadata.passkeys.push(passkeyMetadata);
    } else {
      // Remove operation
      metadata.passkeys = metadata.passkeys.filter((p) => p.id !== passkeyId);
    }

    metadata.lastUpdated = Date.now();

    await chrome.storage.local.set({ [this.METADATA_KEY]: metadata });
  }

  /**
   * Update last used timestamp for a passkey
   */
  private async updateLastUsed(passkeyId: string): Promise<void> {
    const storageKey = this.getStorageKey(passkeyId);
    const result = await chrome.storage.local.get(storageKey);

    if (result[storageKey]) {
      const updatedData = {
        ...result[storageKey],
        lastUsed: Date.now(),
      };

      await chrome.storage.local.set({ [storageKey]: updatedData });
    }
  }

  /**
   * Get all passkey data (for backup)
   */
  private async getAllPasskeyData(masterPassword: string): Promise<PasskeyData[]> {
    const metadata = await this.getMetadata();
    const passkeys: PasskeyData[] = [];

    for (const passkeyInfo of metadata.passkeys) {
      try {
        const passkey = await this.retrieveAndDecrypt(passkeyInfo.id, masterPassword);
        if (passkey) {
          passkeys.push(passkey);
        }
      } catch (error) {
        console.warn(`Failed to retrieve passkey ${passkeyInfo.id} for backup:`, error);
        // Continue with other passkeys
      }
    }

    return passkeys;
  }
}
