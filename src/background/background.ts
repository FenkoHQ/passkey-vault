import { StorageAgent } from '../agents/storage';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToBytes,
  deriveEd25519Keypair,
  createAccessToken,
  verifyAccessToken,
} from '../crypto/bip39';

interface IPFSConfig {
  enabled: boolean;
  nodeType: 'gateway' | 'local';
  gatewayUrls: string[];
}

interface SyncConfig {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  seedHash: string | null;
}

interface SyncDevice {
  id: string;
  name: string;
  deviceType: string;
  publicKey: string;
  createdAt: number;
  lastSeen: number;
  isThisDevice: boolean;
}

interface SyncChain {
  id: string;
  createdAt: number;
  devices: SyncDevice[];
  seedHash: string;
}

const IPFS_CONFIG_KEY = 'passkey_vault_ipfs_config';
const SYNC_CONFIG_KEY = 'sync_config';
const SYNC_DEVICES_KEY = 'sync_devices';

const DEFAULT_CONFIG: IPFSConfig = {
  enabled: false,
  nodeType: 'gateway',
  gatewayUrls: ['https://ipfs.io/ipfs/', 'https://cloudflare-ipfs.com/ipfs/'],
};

class BackgroundService {
  private storageAgent: StorageAgent;
  private config: IPFSConfig = DEFAULT_CONFIG;

  constructor() {
    this.storageAgent = new StorageAgent();
  }

  private async loadConfig(): Promise<IPFSConfig> {
    try {
      const result = await chrome.storage.local.get(IPFS_CONFIG_KEY);
      return result[IPFS_CONFIG_KEY] || DEFAULT_CONFIG;
    } catch (error) {
      console.error('Failed to load IPFS config:', error);
      return DEFAULT_CONFIG;
    }
  }

  private async saveConfig(config: IPFSConfig): Promise<void> {
    try {
      await chrome.storage.local.set({ [IPFS_CONFIG_KEY]: config });
    } catch (error) {
      console.error('Failed to save IPFS config:', error);
    }
  }

  async initialize(): Promise<void> {
    try {
      console.log('PassKey Vault: Background service initializing...');
      this.config = await this.loadConfig();
      this.setupMessageHandlers();
      console.log('PassKey Vault with IPFS: Background service initialized');
    } catch (error) {
      console.error('Failed to initialize background service:', error);
      throw error;
    }
  }

  private setupMessageHandlers(): void {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender)
        .then((response) => sendResponse(response))
        .catch((error) => sendResponse({ success: false, error: error.message }));

      return true;
    });

    chrome.runtime.onInstalled.addListener((details) => {
      if (details.reason === 'install') {
        this.handleInstall();
      }
    });
  }

  private async handleMessage(message: any, sender: any): Promise<any> {
    try {
      switch (message.type) {
        case 'GET_CONFIG':
          return { success: true, config: this.config };

        case 'SET_CONFIG':
          this.config = message.config;
          await this.saveConfig(this.config);
          return { success: true };

        case 'GET_PASSKEYS':
          return await this.getStoredPasskeys();

        case 'STORE_PASSKEY':
          return await this.storePasskey(message.passkey, message.masterPassword);

        case 'DELETE_PASSKEY':
          return await this.deletePasskey(message.passkeyId, message.masterPassword);

        case 'ENABLE_IPFS':
          return await this.enableIPFS();

        case 'DISABLE_IPFS':
          return await this.disableIPFS();

        case 'GET_IPFS_STATUS':
          return await this.getIPFSStatus();

        case 'CREATE_SYNC_CHAIN':
          return await this.createSyncChain(message.deviceName, message.wordCount);

        case 'JOIN_SYNC_CHAIN':
          return await this.joinSyncChain(message.deviceName, message.mnemonic);

        case 'LEAVE_SYNC_CHAIN':
          return await this.leaveSyncChain();

        case 'GET_SYNC_CHAIN_INFO':
          return await this.getSyncChainInfo();

        case 'REMOVE_SYNC_DEVICE':
          return await this.removeSyncDevice(message.deviceId);

        default:
          throw new Error(`Unknown message type: ${message.type}`);
      }
    } catch (error) {
      console.error(`Error handling message ${message.type}:`, error);
      return { success: false, error: error.message };
    }
  }

  private async handleInstall(): Promise<void> {
    console.log('Extension installed');
    // Could show welcome screen or setup wizard here
  }

  private async getStoredPasskeys(): Promise<any> {
    try {
      const result = await chrome.storage.local.get('passkeys');
      const passkeys = result.passkeys || [];
      return { success: true, passkeys };
    } catch (error) {
      console.error('Failed to get passkeys:', error);
      return { success: false, error: error.message };
    }
  }

  private async storePasskey(passkey: any, masterPassword: string): Promise<any> {
    try {
      // For now, just store using existing storage agent
      // In future, this would be enhanced with IPFS capabilities
      const result = await chrome.storage.local.get('passkeys');
      const passkeys = result.passkeys || [];
      passkeys.push(passkey);

      await chrome.storage.local.set({ passkeys });
      return { success: true };
    } catch (error) {
      console.error('Failed to store passkey:', error);
      return { success: false, error: error.message };
    }
  }

  private async deletePasskey(passkeyId: string, masterPassword: string): Promise<any> {
    try {
      const result = await chrome.storage.local.get('passkeys');
      const passkeys = result.passkeys || [];
      const filteredPasskeys = passkeys.filter((pk: any) => pk.id !== passkeyId);

      await chrome.storage.local.set({ passkeys: filteredPasskeys });
      return { success: true };
    } catch (error) {
      console.error('Failed to delete passkey:', error);
      return { success: false, error: error.message };
    }
  }

  private async enableIPFS(): Promise<any> {
    try {
      this.config.enabled = true;
      this.config.nodeType = 'gateway';
      await this.saveConfig(this.config);

      console.log('IPFS enabled with gateway backend');
      return { success: true, enabled: true, nodeType: 'gateway' };
    } catch (error) {
      console.error('Failed to enable IPFS:', error);
      return { success: false, error: error.message };
    }
  }

  private async disableIPFS(): Promise<any> {
    try {
      this.config.enabled = false;
      await this.saveConfig(this.config);

      console.log('IPFS disabled');
      return { success: true, enabled: false };
    } catch (error) {
      console.error('Failed to disable IPFS:', error);
      return { success: false, error: error.message };
    }
  }

  private async getIPFSStatus(): Promise<any> {
    try {
      return {
        success: true,
        data: {
          enabled: this.config.enabled,
          nodeType: this.config.nodeType,
          gatewayUrls: this.config.gatewayUrls,
          status: this.config.enabled ? 'connected' : 'disabled',
        },
      };
    } catch (error) {
      console.error('Failed to get IPFS status:', error);
      return { success: false, error: error.message };
    }
  }

  private async createSyncChain(deviceName: string, wordCount: number): Promise<any> {
    try {
      const mnemonic = await generateMnemonic(wordCount);
      const seedBytes = mnemonicToBytes(mnemonic);
      const keypair = await deriveEd25519Keypair(seedBytes);
      const deviceId = crypto.randomUUID();

      const seedHashBuffer = await crypto.subtle.digest('SHA-256', new Uint8Array(seedBytes));
      const seedHashHex = Array.from(new Uint8Array(seedHashBuffer))
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join('');
      // Derive chainId deterministically from seed hash so all devices with same mnemonic get same chainId
      const chainId = seedHashHex.substring(0, 32);

      const newDevice: SyncDevice = {
        id: deviceId,
        name: deviceName,
        deviceType: this.getDeviceType(),
        publicKey: Array.from(keypair.publicKey)
          .map((b: number) => b.toString(16).padStart(2, '0'))
          .join(''),
        createdAt: Date.now(),
        lastSeen: Date.now(),
        isThisDevice: true,
      };

      const chain: SyncChain = {
        id: chainId,
        createdAt: Date.now(),
        seedHash: seedHashHex,
        devices: [newDevice],
      };

      await chrome.storage.local.set({
        [SYNC_CONFIG_KEY]: {
          enabled: true,
          chainId,
          deviceId,
          deviceName,
          seedHash: seedHashHex,
        },
        [SYNC_DEVICES_KEY]: chain,
      });

      return { success: true, mnemonic, deviceId, chainId };
    } catch (error) {
      console.error('Failed to create sync chain:', error);
      return { success: false, error: error.message };
    }
  }

  private async joinSyncChain(deviceName: string, mnemonic: string): Promise<any> {
    try {
      if (!validateMnemonic(mnemonic)) {
        return { success: false, error: 'Invalid recovery phrase' };
      }

      const seedBytes = mnemonicToBytes(mnemonic);
      const keypair = await deriveEd25519Keypair(seedBytes);
      const deviceId = crypto.randomUUID();
      const seedHashBuffer = await crypto.subtle.digest('SHA-256', new Uint8Array(seedBytes));
      const seedHashHex = Array.from(new Uint8Array(seedHashBuffer))
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join('');

      const newDevice: SyncDevice = {
        id: deviceId,
        name: deviceName,
        deviceType: this.getDeviceType(),
        publicKey: Array.from(keypair.publicKey)
          .map((b: number) => b.toString(16).padStart(2, '0'))
          .join(''),
        createdAt: Date.now(),
        lastSeen: Date.now(),
        isThisDevice: true,
      };

      const chainId = seedHashHex.substring(0, 32);

      const chain: SyncChain = {
        id: chainId,
        createdAt: Date.now(),
        seedHash: seedHashHex,
        devices: [newDevice],
      };

      const config: SyncConfig = {
        enabled: true,
        chainId,
        deviceId,
        deviceName,
        seedHash: seedHashHex,
      };

      await chrome.storage.local.set({
        [SYNC_CONFIG_KEY]: config,
        [SYNC_DEVICES_KEY]: chain,
      });

      return { success: true, deviceId };
    } catch (error) {
      console.error('Failed to join sync chain:', error);
      return { success: false, error: error.message };
    }
  }

  private async leaveSyncChain(): Promise<any> {
    try {
      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];

      if (!config || !config.enabled) {
        return { success: false, error: 'Not currently synced' };
      }

      const chainResult = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain: SyncChain = chainResult[SYNC_DEVICES_KEY];

      if (!chain) {
        return { success: false, error: 'Sync chain not found' };
      }

      const devices = chain.devices.filter((d) => !d.isThisDevice);
      const updatedChain: SyncChain = {
        ...chain,
        devices: devices.filter((d) => !d.isThisDevice),
      };

      await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: updatedChain });
      await chrome.storage.local.set({
        [SYNC_CONFIG_KEY]: {
          enabled: false,
          chainId: null,
          deviceId: null,
          deviceName: null,
          seedHash: null,
        },
      });

      return { success: true };
    } catch (error) {
      console.error('Failed to leave sync chain:', error);
      return { success: false, error: error.message };
    }
  }

  private async getSyncChainInfo(): Promise<any> {
    try {
      const chainResult = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain: SyncChain = chainResult[SYNC_DEVICES_KEY];
      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];

      if (!chain || !config || !config.enabled) {
        return { success: true, chainInfo: null };
      }

      const thisDeviceId = config.deviceId;

      const chainInfo: SyncChain = {
        ...chain,
        devices: chain.devices.map((d) => ({
          ...d,
          isThisDevice: d.id === thisDeviceId,
        })),
      };

      return { success: true, chainInfo };
    } catch (error) {
      console.error('Failed to get sync chain info:', error);
      return { success: false, error: error.message };
    }
  }

  private async removeSyncDevice(deviceId: string): Promise<any> {
    try {
      const result = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain: SyncChain = result[SYNC_DEVICES_KEY];

      if (!chain) {
        return { success: false, error: 'Sync chain not found' };
      }

      const updatedDevices = chain.devices.filter((d) => d.id !== deviceId);

      const updatedChain: SyncChain = {
        ...chain,
        devices: updatedDevices,
      };

      await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: updatedChain });

      return { success: true };
    } catch (error) {
      console.error('Failed to remove sync device:', error);
      return { success: false, error: error.message };
    }
  }

  private getDeviceType(): string {
    const platform = navigator.platform?.toLowerCase() || '';
    const isMobile = /android|iphone|ipad|ipod/.test(platform);

    if (isMobile) {
      return 'Mobile';
    }

    if (platform.includes('mac')) {
      return 'Desktop (macOS)';
    }

    if (platform.includes('win')) {
      return 'Desktop (Windows)';
    }

    if (platform.includes('linux')) {
      return 'Desktop (Linux)';
    }

    return 'Desktop';
  }
}

const backgroundService = new BackgroundService();

backgroundService.initialize().catch((error) => {
  console.error('Failed to initialize background service:', error);
});

export { backgroundService };
