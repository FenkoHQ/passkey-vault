import {
  deriveKey,
  encryptWithPassword,
  decryptWithPassword,
  secureWipe,
  createChecksum,
  verifyChecksum,
} from '../crypto/encryption';

export interface IPFSKeyPair {
  peerId: string;
  privateKey: string;
  publicKey: string;
  keyType: 'ed25519' | 'rsa' | 'secp256k1';
  createdAt: Date;
  name?: string;
}

export interface IPFSConfig {
  enabled: boolean;
  gateway: string;
  apiUrl: string;
  autoSync: boolean;
  pinning: boolean;
  replication: number;
  networkMode: 'public' | 'private' | 'local';
}

export interface IPFSBackupInfo {
  hash: string;
  size: number;
  pinned: boolean;
  createdAt: Date;
  passkeyCount: number;
  integrityHash: string;
  version: string;
  deviceId: string;
}

export interface IPFSSyncState {
  lastSync: Date | null;
  pendingUploads: string[];
  pendingDownloads: string[];
  conflictResolution: 'local' | 'remote' | 'merge';
  syncEnabled: boolean;
}

export interface IPFSNodeInfo {
  peerId: string;
  addresses: string[];
  connectedPeers: number;
  repoSize: number;
  version: string;
  online: boolean;
}

export class IPFSAgent {
  private config: IPFSConfig;
  private currentKeyPair: IPFSKeyPair | null = null;
  private deviceId: string;
  private isInitialized = false;

  private readonly IPFS_CONFIG_KEY = 'passext_ipfs_config';
  private readonly IPFS_KEYPAIR_KEY = 'passext_ipfs_keypair';
  private readonly IPFS_DEVICE_ID_KEY = 'passext_ipfs_device_id';
  private readonly IPFS_SYNC_STATE_KEY = 'passext_ipfs_sync_state';

  constructor() {
    this.deviceId = '';
    this.config = this.getDefaultConfig();
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      this.deviceId = await this.getOrCreateDeviceId();
      await this.loadConfiguration();

      if (this.config.enabled) {
        await this.validateConnectivity();
      }

      this.isInitialized = true;
    } catch (error) {
      console.error('IPFSAgent initialization failed:', error);
      throw new Error(`IPFS initialization failed: ${error.message}`);
    }
  }

  async generateKeyPair(
    keyType: 'ed25519' | 'rsa' | 'secp256k1' = 'ed25519',
    name?: string
  ): Promise<IPFSKeyPair> {
    try {
      let keyPair: IPFSKeyPair;

      if (keyType === 'ed25519') {
        const keyPairData = await this.generateEd25519KeyPair();
        keyPair = {
          ...keyPairData,
          keyType: 'ed25519',
          createdAt: new Date(),
          name: name || 'Default IPFS Key',
        };
      } else if (keyType === 'secp256k1') {
        const keyPairData = await this.generateSecp256k1KeyPair();
        keyPair = {
          ...keyPairData,
          keyType: 'secp256k1',
          createdAt: new Date(),
          name: name || 'Default IPFS Key',
        };
      } else {
        throw new Error(`RSA keys not yet supported: ${keyType}`);
      }

      this.validateKeyPair(keyPair);
      await this.storeKeyPair(keyPair);
      this.currentKeyPair = keyPair;

      return keyPair;
    } catch (error) {
      console.error('Failed to generate IPFS keypair:', error);
      throw new Error(`Key generation failed: ${error.message}`);
    }
  }

  async storeBackup(encryptedData: string, metadata: any, masterPassword: string): Promise<string> {
    this.ensureInitialized();
    this.ensureKeyPair();

    try {
      const backupPayload = {
        version: '1.0',
        deviceId: this.deviceId,
        timestamp: Date.now(),
        metadata,
        data: encryptedData,
        integrity: await createChecksum(encryptedData),
      };

      const serializedPayload = JSON.stringify(backupPayload);
      const backupBuffer = new TextEncoder().encode(serializedPayload);

      const ipfsHash = await this.uploadToIPFS(backupBuffer);

      if (this.config.pinning) {
        await this.pinContent(ipfsHash);
      }

      const backupInfo: IPFSBackupInfo = {
        hash: ipfsHash,
        size: backupBuffer.byteLength,
        pinned: this.config.pinning,
        createdAt: new Date(),
        passkeyCount: metadata.passkeyCount || 0,
        integrityHash: backupPayload.integrity,
        version: backupPayload.version,
        deviceId: this.deviceId,
      };

      await this.trackBackup(backupInfo);

      return ipfsHash;
    } catch (error) {
      console.error('Failed to store backup to IPFS:', error);
      throw new Error(`IPFS backup failed: ${error.message}`);
    }
  }

  async retrieveBackup(
    ipfsHash: string,
    masterPassword: string
  ): Promise<{ data: string; metadata: any; deviceId: string }> {
    this.ensureInitialized();
    this.ensureKeyPair();

    try {
      const backupBuffer = await this.downloadFromIPFS(ipfsHash);

      if (!backupBuffer) {
        throw new Error('Backup not found on IPFS');
      }

      const serializedPayload = new TextDecoder().decode(backupBuffer);
      const backupPayload = JSON.parse(serializedPayload);

      this.validateBackupFormat(backupPayload);

      const isValidIntegrity = await verifyChecksum(backupPayload.data, backupPayload.integrity);
      if (!isValidIntegrity) {
        throw new Error('Backup integrity check failed');
      }

      return {
        data: backupPayload.data,
        metadata: backupPayload.metadata,
        deviceId: backupPayload.deviceId,
      };
    } catch (error) {
      console.error('Failed to retrieve backup from IPFS:', error);
      throw new Error(`IPFS retrieval failed: ${error.message}`);
    }
  }

  async listBackups(): Promise<IPFSBackupInfo[]> {
    this.ensureInitialized();
    this.ensureKeyPair();

    try {
      const syncState = await this.getSyncState();
      return syncState.backups || [];
    } catch (error) {
      console.error('Failed to list IPFS backups:', error);
      return [];
    }
  }

  async syncWithDevices(): Promise<{
    downloaded: string[];
    uploaded: string[];
    conflicts: string[];
  }> {
    this.ensureInitialized();
    this.ensureKeyPair();

    try {
      const result = {
        downloaded: [] as string[],
        uploaded: [] as string[],
        conflicts: [] as string[],
      };

      const syncState = await this.getSyncState();
      const remoteBackups = await this.discoverRemoteBackups();

      await this.updateSyncState(syncState);

      return result;
    } catch (error) {
      console.error('Failed to sync with devices:', error);
      throw new Error(`Sync failed: ${error.message}`);
    }
  }

  async getConfiguration(): Promise<IPFSConfig> {
    return { ...this.config };
  }

  async updateConfiguration(newConfig: Partial<IPFSConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };

    try {
      const configString = JSON.stringify(this.config);
      const encrypted = await encryptWithPassword(configString, 'ipfs-config-default-key');

      await chrome.storage.local.set({ [this.IPFS_CONFIG_KEY]: encrypted });

      if (newConfig.enabled && !this.config.enabled) {
        await this.validateConnectivity();
      }
    } catch (error) {
      console.error('Failed to update IPFS configuration:', error);
      throw new Error(`Configuration update failed: ${error.message}`);
    }
  }

  async getNodeInfo(): Promise<IPFSNodeInfo | null> {
    if (!this.config.enabled) {
      return null;
    }

    try {
      return {
        peerId: this.currentKeyPair?.peerId || '',
        addresses: [],
        connectedPeers: 0,
        repoSize: 0,
        version: '0.0.0-browser',
        online: false,
      };
    } catch (error) {
      console.error('Failed to get IPFS node info:', error);
      return null;
    }
  }

  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new Error('IPFSAgent not initialized');
    }
  }

  private ensureKeyPair(): void {
    if (!this.currentKeyPair) {
      throw new Error('No IPFS keypair available');
    }
  }

  private async generateEd25519KeyPair(): Promise<{
    peerId: string;
    privateKey: string;
    publicKey: string;
  }> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify']
    );

    const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);

    const peerId = await this.generatePeerIdFromPublicKey(publicKeyBuffer);

    return {
      peerId,
      privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer))),
      publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))),
    };
  }

  private async generateSecp256k1KeyPair(): Promise<{
    peerId: string;
    privateKey: string;
    publicKey: string;
  }> {
    throw new Error('secp256k1 key generation not yet implemented');
  }

  private async generatePeerIdFromPublicKey(publicKeyBuffer: ArrayBuffer): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', publicKeyBuffer);
    const hashArray = Array.from(new Uint8Array(hash));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    return `Qm${hashHex.substring(0, 44)}`;
  }

  private validateKeyPair(keyPair: IPFSKeyPair): void {
    if (!keyPair.peerId || !keyPair.privateKey || !keyPair.publicKey) {
      throw new Error('Invalid keypair: missing required fields');
    }

    if (!keyPair.peerId.startsWith('Qm') && !keyPair.peerId.startsWith('baf')) {
      throw new Error('Invalid peer ID format');
    }
  }

  private async storeKeyPair(keyPair: IPFSKeyPair): Promise<void> {
    try {
      const keyPairString = JSON.stringify(keyPair);
      const encrypted = await encryptWithPassword(keyPairString, 'ipfs-keypair-default-key');

      await chrome.storage.local.set({ [this.IPFS_KEYPAIR_KEY]: encrypted });
    } catch (error) {
      throw new Error(`Failed to store keypair: ${error.message}`);
    }
  }

  private async loadKeyPair(): Promise<IPFSKeyPair | null> {
    try {
      const result = await chrome.storage.local.get(this.IPFS_KEYPAIR_KEY);

      if (!result[this.IPFS_KEYPAIR_KEY]) {
        return null;
      }

      const encrypted = result[this.IPFS_KEYPAIR_KEY];
      const decrypted = await decryptWithPassword(
        encrypted.data,
        encrypted.iv,
        encrypted.salt,
        'ipfs-keypair-default-key'
      );

      const keyPair = JSON.parse(decrypted) as IPFSKeyPair;
      keyPair.createdAt = new Date(keyPair.createdAt);

      return keyPair;
    } catch (error) {
      console.error('Failed to load keypair:', error);
      return null;
    }
  }

  private async getOrCreateDeviceId(): Promise<string> {
    try {
      const result = await chrome.storage.local.get(this.IPFS_DEVICE_ID_KEY);
      if (result[this.IPFS_DEVICE_ID_KEY]) {
        return result[this.IPFS_DEVICE_ID_KEY];
      }
    } catch (e) {}

    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    const randomHex = Array.from(randomBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const deviceId = `device_${randomHex}_${Date.now()}`;

    try {
      await chrome.storage.local.set({ [this.IPFS_DEVICE_ID_KEY]: deviceId });
    } catch (e) {}

    return deviceId;
  }

  private getDefaultConfig(): IPFSConfig {
    return {
      enabled: false,
      gateway: 'https://ipfs.io/ipfs/',
      apiUrl: 'https://ipfs.io/api/v0/',
      autoSync: true,
      pinning: true,
      replication: 1,
      networkMode: 'public',
    };
  }

  private async loadConfiguration(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(this.IPFS_CONFIG_KEY);

      if (result[this.IPFS_CONFIG_KEY]) {
        const encrypted = result[this.IPFS_CONFIG_KEY];
        const decrypted = await decryptWithPassword(
          encrypted.data,
          encrypted.iv,
          encrypted.salt,
          'ipfs-config-default-key'
        );

        this.config = { ...this.config, ...JSON.parse(decrypted) };
      }

      this.currentKeyPair = await this.loadKeyPair();
    } catch (error) {
      console.error('Failed to load IPFS configuration:', error);
    }
  }

  private async validateConnectivity(): Promise<void> {
    try {
      const response = await fetch(`${this.config.gateway}Qmtest`, {
        method: 'HEAD',
        mode: 'cors',
      });

      if (!response.ok && response.status !== 404) {
        throw new Error(`IPFS gateway not accessible: ${response.status}`);
      }
    } catch (error) {
      if (error.message.includes('Failed to fetch')) {
        throw new Error('IPFS gateway not reachable - check network connectivity');
      }
      throw error;
    }
  }

  private async uploadToIPFS(data: Uint8Array): Promise<string> {
    const randomBytes = new Uint8Array(44);
    crypto.getRandomValues(randomBytes);
    const randomStr = Array.from(randomBytes)
      .map((b) => b.toString(36))
      .join('')
      .substring(0, 44);
    const mockHash = `bafy${randomStr}`;
    return mockHash;
  }

  private async downloadFromIPFS(hash: string): Promise<Uint8Array | null> {
    return new Uint8Array([]);
  }

  private async pinContent(hash: string): Promise<void> {}

  private async trackBackup(backupInfo: IPFSBackupInfo): Promise<void> {
    const syncState = await this.getSyncState();
    syncState.backups = syncState.backups || [];
    syncState.backups.push(backupInfo);
    await this.updateSyncState(syncState);
  }

  private async getSyncState(): Promise<IPFSSyncState & { backups: IPFSBackupInfo[] }> {
    try {
      const result = await chrome.storage.local.get(this.IPFS_SYNC_STATE_KEY);
      return (
        result[this.IPFS_SYNC_STATE_KEY] || {
          lastSync: null,
          pendingUploads: [],
          pendingDownloads: [],
          conflictResolution: 'local',
          syncEnabled: this.config.autoSync,
          backups: [],
        }
      );
    } catch (error) {
      return {
        lastSync: null,
        pendingUploads: [],
        pendingDownloads: [],
        conflictResolution: 'local',
        syncEnabled: false,
        backups: [],
      };
    }
  }

  private async updateSyncState(
    state: IPFSSyncState & { backups: IPFSBackupInfo[] }
  ): Promise<void> {
    await chrome.storage.local.set({ [this.IPFS_SYNC_STATE_KEY]: state });
  }

  private async discoverRemoteBackups(): Promise<IPFSBackupInfo[]> {
    return [];
  }

  private validateBackupFormat(backup: any): void {
    if (!backup.version || !backup.data || !backup.integrity || !backup.deviceId) {
      throw new Error('Invalid backup format');
    }

    if (backup.version !== '1.0') {
      throw new Error(`Unsupported backup version: ${backup.version}`);
    }
  }
}

export const ipfsAgent = new IPFSAgent();
