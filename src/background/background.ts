import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToBytes,
  deriveEd25519Keypair,
} from '../crypto/bip39';
import { syncService } from '../sync/sync-service';
import { secureStorage } from '../crypto/secure-storage';
import { encryptWithPassword, decryptWithPassword } from '../crypto/encryption';
import { randomBytes } from '@noble/hashes/utils';
import { logger } from '../utils/logger';
import { arrayBufferToBase64, arrayBufferToBase64URL, base64urlToBase64 } from '../utils/base64';
import { createAuthenticatorData, createAttestationObjectNone, convertP1363ToDER } from './cbor';
import {
  selectPrfEval,
  getOrCreatePrfKey,
  computePrfResults,
  buildClientExtensionResults,
  encodePrfExtension,
} from './prf';

const PASSKEY_STORAGE_KEY = 'passkeys';
const SYNC_CONFIG_KEY = 'sync_config';
const SYNC_DEVICES_KEY = 'sync_devices';
const SYNC_STATUS_KEY = 'sync_status';

interface StoredPasskey {
  id: string;
  credentialId: string;
  type: string;
  rpId: string;
  origin: string;
  user: {
    id: string | null;
    name: string;
    displayName: string;
  };
  privateKey: string;
  publicKey: string;
  createdAt: number;
  counter: number;
  prfKey?: string;
  // Fields from STORE_PASSKEY path (external passkeys)
  rawId?: string;
  response?: Record<string, unknown>;
}

interface SyncStatus {
  lastSyncAttempt: number | null;
  lastSyncSuccess: number | null;
  pendingChanges: number;
  connectionStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  lastError: string | null;
  localPasskeyCount: number;
  syncedPasskeyCount: number;
}

interface SyncConfig {
  enabled: boolean;
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  seedHash: string | null;
  syncSalt: string | null;
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

type MessagePayload = Record<string, unknown>;

interface ExtensionMessage {
  type: string;
  payload?: MessagePayload;
  requestId?: string;
  timestamp?: number;
  deviceName?: string;
  wordCount?: number;
  mnemonic?: string;
  deviceId?: string;
}

class BackgroundService {
  private isInitialized: boolean;
  private syncStatus: SyncStatus;

  constructor() {
    this.isInitialized = false;
    this.syncStatus = {
      lastSyncAttempt: null,
      lastSyncSuccess: null,
      pendingChanges: 0,
      connectionStatus: 'disconnected',
      lastError: null,
      localPasskeyCount: 0,
      syncedPasskeyCount: 0,
    };
    // MV3: listeners must be attached synchronously at SW wake, before any
    // await — otherwise the first message after a cold start is dropped with
    // "Could not establish connection. Receiving end does not exist."
    this.setupMessageHandlers();
    this.setupLifecycleHandlers();
    this.initialize();
  }

  // ==================== STORAGE HELPERS ====================
  // When secure storage is set up and unlocked, passkeys are stored encrypted.
  // Otherwise, falls back to raw chrome.storage.local for backwards compatibility.

  private get useSecureStorage(): boolean {
    return secureStorage.isStorageUnlocked();
  }

  private async loadPasskeys(): Promise<StoredPasskey[]> {
    if (this.useSecureStorage) {
      return (await secureStorage.getPasskeys()) as unknown as StoredPasskey[];
    }
    const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
    return result[PASSKEY_STORAGE_KEY] || [];
  }

  private async savePasskeys(passkeys: StoredPasskey[]): Promise<void> {
    // Always write to raw storage (needed by popup for display)
    await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });
    // Also write encrypted copy if secure storage is available
    if (this.useSecureStorage) {
      await secureStorage.storePasskeys(passkeys as unknown as Record<string, unknown>[]);
    }
  }

  private async initialize(): Promise<void> {
    try {
      await logger.init();
      logger.info('Background service initializing...');
      await this.initializeSyncService();
      // Restore auto-lock timeout from storage
      const stored = await chrome.storage.local.get('auto_lock_timeout');
      if (stored.auto_lock_timeout != null) {
        const ms = stored.auto_lock_timeout === 0 ? 0 : stored.auto_lock_timeout * 60 * 1000;
        secureStorage.setAutoLockTimeout(ms);
      }
      this.isInitialized = true;
      logger.info('Background service initialized successfully');
    } catch (error) {
      logger.error('Background service initialization failed:', error);
    }
  }

  private async initializeSyncService(): Promise<void> {
    try {
      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];

      if (config?.enabled && config.chainId && config.deviceId && config.seedHash) {
        logger.info('Starting sync service...');
        await syncService.initialize(
          config.chainId,
          config.deviceId,
          config.seedHash,
          config.deviceName || undefined,
          config.syncSalt || undefined
        );
        await this.updateSyncStatus({ connectionStatus: 'connected' });
        logger.info('Sync service started');
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Failed to start sync service:', error);
      await this.updateSyncStatus({
        connectionStatus: 'error',
        lastError: message,
      });
    }
  }

  private setupMessageHandlers(): void {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      void sender;
      this.handleMessage(message, sendResponse);
      return true;
    });
  }

  private async handleMessage(
    message: ExtensionMessage,
    sendResponse: (response?: unknown) => void
  ): Promise<void> {
    try {
      const response = await this.routeMessage(message);
      sendResponse(response);
    } catch (error: unknown) {
      const message_str = error instanceof Error ? error.message : String(error);
      console.error('Message handling error:', error);
      sendResponse({ success: false, error: message_str });
    }
  }

  private async routeMessage(message: ExtensionMessage): Promise<unknown> {
    const { type, payload } = message;

    switch (type) {
      case 'CREATE_PASSKEY':
        return this.handleCreatePasskey(payload || {});
      case 'GET_PASSKEY':
        return this.handleGetPasskey(payload || {});
      case 'STORE_PASSKEY':
        return this.handleStorePasskey(payload || {});
      case 'RETRIEVE_PASSKEY':
        return this.handleRetrievePasskey(payload || {});
      case 'LIST_PASSKEYS':
      case 'GET_PASSKEYS':
        return this.handleListPasskeys();
      case 'LIST_PASSKEYS_FOR_RP':
        return this.handleListPasskeysForRp(payload || {});
      case 'DELETE_PASSKEY':
        return this.handleDeletePasskey(payload || {});
      case 'ENCRYPT_BACKUP':
        return this.handleEncryptBackup(payload as { data: string; password: string });
      case 'DECRYPT_BACKUP':
        return this.handleDecryptBackup(
          payload as { data: string; iv: string; salt: string; password: string }
        );
      case 'ACTIVATE_UI':
        return { success: true, message: 'Activate UI placeholder' };
      case 'CREATE_SYNC_CHAIN':
        return this.createSyncChain(message.deviceName || '', message.wordCount || 12);
      case 'JOIN_SYNC_CHAIN':
        return this.joinSyncChain(message.deviceName || '', message.mnemonic || '');
      case 'LEAVE_SYNC_CHAIN':
        return this.leaveSyncChain();
      case 'GET_SYNC_CHAIN_INFO':
        return this.getSyncChainInfo();
      case 'REMOVE_SYNC_DEVICE':
        return this.removeSyncDevice(message.deviceId || '');
      case 'GET_SYNC_STATUS':
        return this.getSyncStatus();
      case 'TRIGGER_SYNC':
        return this.handleTriggerSync();
      case 'GET_SYNC_DEBUG_INFO':
        return this.getSyncDebugInfo();
      case 'GET_SYNC_DEBUG_LOGS':
        return this.getSyncDebugLogs();
      case 'CLEAR_SYNC_DEBUG_LOGS':
        return this.clearSyncDebugLogs();
      case 'SETUP_MASTER_PASSWORD':
        return this.handleSetupMasterPassword(payload as { password: string });
      case 'UNLOCK_SECURE_STORAGE':
        return this.handleUnlockSecureStorage(payload as { password: string });
      case 'LOCK_SECURE_STORAGE':
        return this.handleLockSecureStorage();
      case 'IS_SECURE_STORAGE_UNLOCKED':
        return this.handleIsSecureStorageUnlocked();
      case 'CHANGE_MASTER_PASSWORD':
        return this.handleChangeMasterPassword(
          payload as { currentPassword: string; newPassword: string }
        );
      case 'SET_DEBUG_LOGGING':
        return this.handleSetDebugLogging(payload as { enabled: boolean });
      case 'GET_DEBUG_LOGGING':
        return this.handleGetDebugLogging();
      case 'SET_AUTO_LOCK_TIMEOUT':
        return this.handleSetAutoLockTimeout(payload as { minutes: number });
      case 'GET_WEBAUTHN_LOG':
        return this.handleGetWebAuthnLog();
      case 'CLEAR_WEBAUTHN_LOG':
        return this.handleClearWebAuthnLog();
      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  private setupLifecycleHandlers(): void {
    chrome.runtime.onInstalled.addListener((details) => {
      logger.info('Extension installed', details);
      if (details.reason === 'install') {
        logger.info('First-time installation');
      } else if (details.reason === 'update') {
        logger.info('Extension updated');
      }
    });
    chrome.runtime.onStartup.addListener(() => {
      logger.info('Extension startup');
    });
    chrome.runtime.onSuspend.addListener(() => {
      logger.info('Extension suspending');
    });
  }

  // ==================== PASSKEY OPERATIONS ====================

  private async handleCreatePasskey(payload: MessagePayload): Promise<unknown> {
    try {
      const options = payload.publicKey as Record<string, unknown> | undefined;
      const origin = payload.origin as string | undefined;
      const challenge = options?.challenge;
      const user = options?.user as Record<string, unknown> | undefined;
      const rpId =
        (options?.rpId as string) ||
        (options?.rp as Record<string, string> | undefined)?.id ||
        (origin ? new URL(origin).hostname : 'localhost');

      logger.debug('Creating passkey for', rpId, 'user:', (user?.name as string) || 'unknown');

      const existingPasskeys = await this.loadPasskeys();
      const existingPasskey = existingPasskeys.find((p) => p.rpId === rpId);

      if (existingPasskey) {
        logger.debug('Passkey already exists for', rpId);
        return {
          success: false,
          error: 'A passkey already exists for this site',
          name: 'InvalidStateError',
          existingCredentialId: existingPasskey.id,
        };
      }

      const credentialId = new Uint8Array(16);
      crypto.getRandomValues(credentialId);
      const credentialIdBase64 = arrayBufferToBase64URL(credentialId.buffer as ArrayBuffer);

      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );

      const privateKeyExport = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const privateKeyBase64 = arrayBufferToBase64(privateKeyExport);

      const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
      const publicKeyBase64 = arrayBufferToBase64(publicKeyRaw);

      const prfKeyBytes = crypto.getRandomValues(new Uint8Array(32));
      const prfKeyBase64 = arrayBufferToBase64URL(prfKeyBytes.buffer);

      const prfInput = (options?.extensions as Record<string, unknown> | undefined)?.prf;
      const prfEvalInput = selectPrfEval(
        prfInput as Parameters<typeof selectPrfEval>[0],
        credentialIdBase64
      );
      const prfResults = prfEvalInput
        ? await computePrfResults(prfKeyBytes.buffer, prfEvalInput)
        : null;
      const extensionsData = prfResults ? encodePrfExtension(prfResults) : null;
      const clientExtensionResults = buildClientExtensionResults(prfResults);

      const clientData = { type: 'webauthn.create', challenge, origin };
      const clientDataJSONBytes = new TextEncoder().encode(JSON.stringify(clientData));

      const authenticatorData = await createAuthenticatorData(
        rpId,
        credentialId,
        publicKeyRaw,
        true,
        0,
        extensionsData
      );

      const attestationObject = createAttestationObjectNone(authenticatorData);

      const passkeys = await this.loadPasskeys();

      const userId = user?.id;
      passkeys.push({
        id: credentialIdBase64,
        credentialId: credentialIdBase64,
        type: 'public-key',
        rpId,
        origin: origin || '',
        user: {
          id:
            userId != null
              ? userId instanceof ArrayBuffer
                ? arrayBufferToBase64URL(userId)
                : String(userId)
              : null,
          name: (user?.name as string) || '',
          displayName: (user?.displayName as string) || '',
        },
        privateKey: privateKeyBase64,
        publicKey: publicKeyBase64,
        createdAt: Date.now(),
        counter: 0,
        prfKey: prfKeyBase64,
      });

      await this.savePasskeys(passkeys);
      logger.debug('Created and stored passkey', credentialIdBase64);

      this.logWebAuthn('CREATE', 'info', `Created passkey for ${rpId}`, {
        rpId,
        credentialId: credentialIdBase64,
        user: (user?.name as string) || '',
      });
      this.logSync('PASSKEY_CREATED', { id: credentialIdBase64, rpId });
      await this.incrementPendingChanges();
      this.triggerSync();

      const rawIdBase64 = base64urlToBase64(credentialIdBase64);
      const clientDataJSONBase64 = arrayBufferToBase64(clientDataJSONBytes.buffer);
      const attestationObjectBase64 = arrayBufferToBase64(attestationObject);

      return {
        success: true,
        credential: {
          id: credentialIdBase64,
          rawId: rawIdBase64,
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONBase64,
            attestationObject: attestationObjectBase64,
          },
          authenticatorAttachment: 'cross-platform',
          clientExtensionResults,
        },
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error creating passkey:', error);
      return { success: false, error: message };
    }
  }

  private async handleGetPasskey(payload: MessagePayload): Promise<unknown> {
    try {
      const options = payload.publicKey as Record<string, unknown> | undefined;
      const origin = payload.origin as string | undefined;
      const selectedPasskeyId = payload.selectedPasskeyId as string | undefined;
      const challenge = options?.challenge;
      const rpId = (options?.rpId as string) || (origin ? new URL(origin).hostname : 'localhost');

      logger.debug('Getting passkey for', rpId, 'selectedId:', selectedPasskeyId);

      const passkeys = await this.loadPasskeys();
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      if (matchingPasskeys.length === 0) {
        logger.debug('No passkeys found for', rpId);
        return {
          success: false,
          error: 'No passkeys found for this site',
          name: 'NotAllowedError',
        };
      }

      let passkey: StoredPasskey | undefined;
      if (selectedPasskeyId) {
        passkey = matchingPasskeys.find((p) => p.id === selectedPasskeyId);
        if (!passkey) {
          logger.debug('Selected passkey not found:', selectedPasskeyId);
          return { success: false, error: 'Selected passkey not found', name: 'NotAllowedError' };
        }
      } else {
        passkey = matchingPasskeys[0];
      }

      logger.debug('Using passkey', passkey.id, 'for signing');

      if (!passkey.privateKey || typeof passkey.privateKey !== 'string') {
        throw new Error('Invalid private key format: ' + typeof passkey.privateKey);
      }
      if (passkey.privateKey.length === 0) {
        throw new Error('Private key is empty');
      }

      let privateKeyBinary: string;
      try {
        privateKeyBinary = atob(passkey.privateKey);
      } catch (atobError: unknown) {
        const msg = atobError instanceof Error ? atobError.message : String(atobError);
        logger.error('Failed to decode private key:', atobError);
        throw new Error('Invalid base64 encoding for private key: ' + msg);
      }

      const privateKeyBytes = new Uint8Array(privateKeyBinary.length);
      for (let i = 0; i < privateKeyBinary.length; i++) {
        privateKeyBytes[i] = privateKeyBinary.charCodeAt(i);
      }

      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBytes.buffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      );

      const clientData = { type: 'webauthn.get', challenge, origin };
      const clientDataJSONBytes = new TextEncoder().encode(JSON.stringify(clientData));

      const prfInput = (options?.extensions as Record<string, unknown> | undefined)?.prf;
      const prfEvalInput = selectPrfEval(
        prfInput as Parameters<typeof selectPrfEval>[0],
        passkey.id
      );
      const prfKeyBuffer = await getOrCreatePrfKey(passkey);
      const prfResults = prfEvalInput ? await computePrfResults(prfKeyBuffer, prfEvalInput) : null;
      const extensionsData = prfResults ? encodePrfExtension(prfResults) : null;
      const clientExtensionResults = buildClientExtensionResults(prfResults);

      passkey.counter = (passkey.counter || 0) + 1;
      const authenticatorData = await createAuthenticatorData(
        rpId,
        null,
        null,
        false,
        passkey.counter,
        extensionsData
      );

      const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSONBytes.buffer);
      const authenticatorDataBytes = new Uint8Array(authenticatorData);
      const signatureBase = new Uint8Array(
        authenticatorDataBytes.length + clientDataHash.byteLength
      );
      signatureBase.set(authenticatorDataBytes, 0);
      signatureBase.set(new Uint8Array(clientDataHash), authenticatorDataBytes.length);

      const signatureP1363 = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        signatureBase
      );

      const signatureDER = convertP1363ToDER(signatureP1363);

      const index = passkeys.findIndex((p) => p.id === passkey!.id);
      if (index >= 0) {
        passkeys[index] = passkey;
        await this.savePasskeys(passkeys);
      }

      logger.debug('Signed assertion for', passkey.id);

      const rawIdBase64 = base64urlToBase64(passkey.id);
      const clientDataJSONBase64 = arrayBufferToBase64(clientDataJSONBytes.buffer);
      const authenticatorDataBase64 = arrayBufferToBase64(authenticatorData);
      const signatureBase64 = arrayBufferToBase64(signatureDER);
      const userHandleBase64 = passkey.user?.id
        ? typeof passkey.user.id === 'string'
          ? base64urlToBase64(passkey.user.id)
          : null
        : null;

      this.logWebAuthn('GET', 'info', `Signed assertion for ${rpId}`, {
        rpId,
        credentialId: passkey.id,
        user: passkey.user?.name || '',
      });

      return {
        success: true,
        credential: {
          id: passkey.id,
          rawId: rawIdBase64,
          type: 'public-key',
          response: {
            clientDataJSON: clientDataJSONBase64,
            authenticatorData: authenticatorDataBase64,
            signature: signatureBase64,
            userHandle: userHandleBase64,
          },
          authenticatorAttachment: 'cross-platform',
          clientExtensionResults,
        },
      };
    } catch (error: unknown) {
      let errorMessage = 'Unknown error';
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (error instanceof DOMException) {
        errorMessage = error.message || error.name || 'DOMException';
      } else if (typeof error === 'string') {
        errorMessage = error;
      }
      logger.error('Error getting passkey:', error);
      return { success: false, error: errorMessage };
    }
  }

  private async handleStorePasskey(payload: MessagePayload): Promise<unknown> {
    try {
      const publicKey = payload.publicKey as Record<string, string> | undefined;
      const origin = payload.origin as string;
      const options = payload.options as Record<string, Record<string, string>> | undefined;
      const passkeys = await this.loadPasskeys();
      const rpId = options?.publicKey?.rpId || new URL(origin).hostname;
      const credentialId = publicKey?.id || publicKey?.rawId;

      if (credentialId) {
        const existingIndex = passkeys.findIndex((p) => p.credentialId === credentialId);
        const passkeyData: StoredPasskey = {
          credentialId,
          id: publicKey!.id,
          rawId: publicKey!.rawId,
          type: publicKey!.type,
          response: publicKey!.response as unknown as Record<string, unknown>,
          rpId,
          origin,
          createdAt: Date.now(),
          user: { id: null, name: '', displayName: '' },
          privateKey: '',
          publicKey: '',
          counter: 0,
        };

        if (existingIndex >= 0) {
          passkeys[existingIndex] = passkeyData;
        } else {
          passkeys.push(passkeyData);
        }

        await this.savePasskeys(passkeys);
        logger.debug('Stored passkey', credentialId, 'for', rpId);
        return { success: true, message: 'Passkey stored successfully', count: passkeys.length };
      }
      return { success: false, error: 'No credential ID in payload' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error storing passkey:', error);
      return { success: false, error: message };
    }
  }

  private async handleRetrievePasskey(payload: MessagePayload): Promise<unknown> {
    try {
      const publicKey = payload.publicKey as Record<string, string> | undefined;
      const origin = payload.origin as string | undefined;
      const rpId = publicKey?.rpId || (origin ? new URL(origin).hostname : null);
      if (!rpId) return { success: false, error: 'No rpId provided' };

      const passkeys = await this.loadPasskeys();
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      logger.debug('Found', matchingPasskeys.length, 'passkeys for', rpId);
      return { success: true, passkeys: matchingPasskeys, count: matchingPasskeys.length, rpId };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error retrieving passkey:', error);
      return { success: false, error: message };
    }
  }

  private async handleListPasskeys(): Promise<unknown> {
    try {
      const passkeys = await this.loadPasskeys();
      return { success: true, passkeys, count: passkeys.length };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleListPasskeysForRp(payload: MessagePayload): Promise<unknown> {
    try {
      const rpId = payload.rpId as string | undefined;
      if (!rpId) return { success: false, error: 'No rpId provided' };

      const passkeys = await this.loadPasskeys();
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      logger.debug('Found', matchingPasskeys.length, 'passkeys for', rpId);
      return {
        success: true,
        passkeys: matchingPasskeys.map((p) => ({
          id: p.id,
          credentialId: p.credentialId || p.id,
          rpId: p.rpId,
          origin: p.origin,
          user: p.user,
          createdAt: p.createdAt,
        })),
        count: matchingPasskeys.length,
        rpId,
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleDeletePasskey(payload: MessagePayload): Promise<unknown> {
    try {
      const credentialId = payload.credentialId as string;
      const passkeys = await this.loadPasskeys();
      const filtered = passkeys.filter(
        (p) => p.credentialId !== credentialId && p.id !== credentialId
      );

      if (filtered.length < passkeys.length) {
        await this.savePasskeys(filtered);
        this.logSync('PASSKEY_DELETED', { credentialId });
        await this.incrementPendingChanges();
        this.triggerSync();
        return { success: true, message: 'Passkey deleted' };
      }
      return { success: false, error: 'Passkey not found' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ==================== SYNC OPERATIONS ====================

  private async createSyncChain(deviceName: string, wordCount: number): Promise<unknown> {
    try {
      const mnemonic = await generateMnemonic(wordCount);
      const seedBytes = mnemonicToBytes(mnemonic);
      const keypair = await deriveEd25519Keypair(seedBytes);
      const deviceId = crypto.randomUUID();

      const seedHashBuffer = await crypto.subtle.digest('SHA-256', new Uint8Array(seedBytes));
      const seedHashHex = Array.from(new Uint8Array(seedHashBuffer))
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join('');
      const chainId = seedHashHex.substring(0, 32);

      const syncSaltBytes = randomBytes(32);
      const syncSalt = Array.from(syncSaltBytes)
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
          syncSalt,
        },
        [SYNC_DEVICES_KEY]: chain,
      });

      await syncService.initialize(chainId, deviceId, seedHashHex, deviceName, syncSalt);
      this.logSync('SYNC_CHAIN_CREATED', { chainId, deviceId });

      return { success: true, mnemonic, deviceId, chainId };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to create sync chain:', error);
      return { success: false, error: message };
    }
  }

  private async joinSyncChain(deviceName: string, mnemonic: string): Promise<unknown> {
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

      const syncSaltBytes = randomBytes(32);
      const syncSalt = Array.from(syncSaltBytes)
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
        syncSalt,
      };

      await chrome.storage.local.set({
        [SYNC_CONFIG_KEY]: config,
        [SYNC_DEVICES_KEY]: chain,
      });

      await syncService.initialize(chainId, deviceId, seedHashHex, deviceName, syncSalt);
      await syncService.requestSync();
      this.logSync('SYNC_CHAIN_JOINED', { chainId, deviceId });

      return { success: true, deviceId };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to join sync chain:', error);
      return { success: false, error: message };
    }
  }

  private async leaveSyncChain(): Promise<unknown> {
    try {
      await syncService.disconnect();

      await chrome.storage.local.set({
        [SYNC_CONFIG_KEY]: {
          enabled: false,
          chainId: null,
          deviceId: null,
          deviceName: null,
          seedHash: null,
          syncSalt: null,
        },
        [SYNC_DEVICES_KEY]: null,
      });

      this.logSync('SYNC_CHAIN_LEFT', {});
      return { success: true };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to leave sync chain:', error);
      return { success: false, error: message };
    }
  }

  private async getSyncChainInfo(): Promise<unknown> {
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
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to get sync chain info:', error);
      return { success: false, error: message };
    }
  }

  private async removeSyncDevice(deviceId: string): Promise<unknown> {
    try {
      const result = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain: SyncChain = result[SYNC_DEVICES_KEY];

      if (!chain) return { success: false, error: 'Sync chain not found' };

      const updatedDevices = chain.devices.filter((d) => d.id !== deviceId);
      const updatedChain: SyncChain = { ...chain, devices: updatedDevices };

      await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: updatedChain });
      return { success: true };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to remove sync device:', error);
      return { success: false, error: message };
    }
  }

  private getDeviceType(): string {
    const platform = navigator.platform?.toLowerCase() || '';
    const isMobile = /android|iphone|ipad|ipod/.test(platform);

    if (isMobile) return 'Mobile';
    if (platform.includes('mac')) return 'Desktop (macOS)';
    if (platform.includes('win')) return 'Desktop (Windows)';
    if (platform.includes('linux')) return 'Desktop (Linux)';
    return 'Desktop';
  }

  private async getSyncStatus(): Promise<unknown> {
    try {
      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];
      const passkeys = await this.loadPasskeys();

      const statusResult = await chrome.storage.local.get(SYNC_STATUS_KEY);
      const persistedStatus = statusResult[SYNC_STATUS_KEY] || {};

      this.syncStatus = {
        ...this.syncStatus,
        ...persistedStatus,
        localPasskeyCount: passkeys.length,
      };

      const isEnabled = config?.enabled || false;

      this.logSync('GET_SYNC_STATUS', {
        enabled: isEnabled,
        localCount: passkeys.length,
        pendingChanges: this.syncStatus.pendingChanges,
      });

      return {
        success: true,
        status: {
          enabled: isEnabled,
          chainId: config?.chainId || null,
          deviceId: config?.deviceId || null,
          ...this.syncStatus,
        },
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error getting sync status:', error);
      return { success: false, error: message };
    }
  }

  private async updateSyncStatus(updates: Partial<SyncStatus>): Promise<void> {
    this.syncStatus = { ...this.syncStatus, ...updates };
    await chrome.storage.local.set({ [SYNC_STATUS_KEY]: this.syncStatus });
    this.logSync('SYNC_STATUS_UPDATE', updates);
  }

  private async incrementPendingChanges(): Promise<void> {
    await this.updateSyncStatus({
      pendingChanges: this.syncStatus.pendingChanges + 1,
    });
  }

  private logSync(action: string, details?: Record<string, unknown>): void {
    const timestamp = new Date().toISOString();
    console.log(`[SYNC ${timestamp}] ${action}`, details || '');
  }

  private async logWebAuthn(
    action: string,
    level: 'info' | 'warn' | 'error',
    message: string,
    data?: unknown
  ): Promise<void> {
    try {
      const result = await chrome.storage.local.get('webauthn_log');
      const logs: Array<Record<string, unknown>> = result.webauthn_log || [];
      logs.push({ timestamp: Date.now(), level, category: action, message, data });
      // Keep last 200 entries
      if (logs.length > 200) logs.splice(0, logs.length - 200);
      await chrome.storage.local.set({ webauthn_log: logs });
    } catch {
      // Don't let logging errors break operations
    }
  }

  private async handleTriggerSync(): Promise<unknown> {
    await this.triggerSync();
    return { success: true };
  }

  private async getSyncDebugInfo(): Promise<unknown> {
    try {
      const debugInfo = syncService.getDebugInfo();
      return { success: true, debugInfo };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async getSyncDebugLogs(): Promise<unknown> {
    try {
      const logs = syncService.getDebugLogs();
      return { success: true, logs };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async clearSyncDebugLogs(): Promise<unknown> {
    try {
      syncService.clearDebugLogs();
      return { success: true };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async triggerSync(): Promise<void> {
    const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
    const config: SyncConfig = configResult[SYNC_CONFIG_KEY];

    if (!config?.enabled) {
      this.logSync('TRIGGER_SYNC_SKIPPED', { reason: 'sync not enabled' });
      return;
    }

    this.logSync('TRIGGER_SYNC', {
      chainId: config.chainId,
      pendingChanges: this.syncStatus.pendingChanges,
    });

    await this.updateSyncStatus({
      lastSyncAttempt: Date.now(),
      connectionStatus: 'connecting',
    });

    try {
      const passkeys = await this.loadPasskeys();

      const syncStatus = syncService.getStatus();
      if (!syncStatus.connected) {
        if (config.chainId && config.deviceId && config.seedHash) {
          await syncService.initialize(
            config.chainId,
            config.deviceId,
            config.seedHash,
            config.deviceName || undefined,
            config.syncSalt || undefined
          );
        }
      }

      await syncService.broadcastPasskeyUpdate(passkeys);
      await syncService.requestSync();

      await this.updateSyncStatus({
        lastSyncSuccess: Date.now(),
        pendingChanges: 0,
        connectionStatus: 'connected',
        lastError: null,
        localPasskeyCount: passkeys.length,
        syncedPasskeyCount: passkeys.length,
      });

      this.logSync('SYNC_COMPLETE', { passkeyCount: passkeys.length });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      await this.updateSyncStatus({
        connectionStatus: 'error',
        lastError: message,
      });
      this.logSync('SYNC_ERROR', { error: message });
    }
  }

  // ==================== SECURE STORAGE HANDLERS ====================

  private async handleSetupMasterPassword(payload: { password: string }): Promise<unknown> {
    try {
      const { password } = payload;
      if (!password || password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters' };
      }

      const unlocked = await secureStorage.initialize(password);
      if (!unlocked) {
        return { success: false, error: 'Failed to initialize secure storage' };
      }

      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];
      if (config?.seedHash) {
        await secureStorage.storeSyncConfig({
          chainId: config.chainId || '',
          deviceId: config.deviceId || '',
          deviceName: config.deviceName || '',
          seedHash: config.seedHash,
          syncSalt: config.syncSalt || null,
          enabled: config.enabled || false,
        });
        logger.info('Migrated sync config to secure storage');
      }

      const passkeysResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: StoredPasskey[] = passkeysResult[PASSKEY_STORAGE_KEY] || [];
      for (const passkey of passkeys) {
        await secureStorage.upsertPasskey(passkey as unknown as Record<string, unknown>);
      }
      if (passkeys.length > 0) {
        logger.info(`Migrated ${passkeys.length} passkeys to secure storage`);
      }

      return { success: true, message: 'Master password setup complete' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to setup master password:', error);
      return { success: false, error: message };
    }
  }

  private async handleUnlockSecureStorage(payload: { password: string }): Promise<unknown> {
    try {
      const { password } = payload;
      if (!password) {
        return { success: false, error: 'Password is required' };
      }

      const unlocked = await secureStorage.initialize(password);
      if (!unlocked) {
        return { success: false, error: 'Invalid password or storage not initialized' };
      }

      return { success: true, message: 'Secure storage unlocked' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to unlock secure storage:', error);
      return { success: false, error: message };
    }
  }

  private async handleLockSecureStorage(): Promise<unknown> {
    try {
      secureStorage.lock();
      return { success: true, message: 'Secure storage locked' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to lock secure storage:', error);
      return { success: false, error: message };
    }
  }

  private async handleIsSecureStorageUnlocked(): Promise<unknown> {
    try {
      const isUnlocked = secureStorage.isStorageUnlocked();
      const isSetup = await secureStorage.isSetup();
      return { success: true, isUnlocked, isSetup };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleChangeMasterPassword(payload: {
    currentPassword: string;
    newPassword: string;
  }): Promise<unknown> {
    try {
      const { currentPassword, newPassword } = payload;
      if (!currentPassword || !newPassword) {
        return { success: false, error: 'Both current and new passwords are required' };
      }
      if (newPassword.length < 8) {
        return { success: false, error: 'New password must be at least 8 characters' };
      }

      const changed = await secureStorage.changeMasterPassword(currentPassword, newPassword);
      if (!changed) {
        return { success: false, error: 'Failed to change password - check current password' };
      }

      return { success: true, message: 'Master password changed successfully' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to change master password:', error);
      return { success: false, error: message };
    }
  }

  // ==================== BACKUP ENCRYPTION ====================

  private async handleEncryptBackup(payload: { data: string; password: string }): Promise<unknown> {
    try {
      const { data, password } = payload;
      if (!password || password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters' };
      }
      const result = await encryptWithPassword(data, password);
      return { success: true, encrypted: result };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleDecryptBackup(payload: {
    data: string;
    iv: string;
    salt: string;
    password: string;
  }): Promise<unknown> {
    try {
      const { data, iv, salt, password } = payload;
      const decrypted = await decryptWithPassword(data, iv, salt, password);
      return { success: true, data: decrypted };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleSetDebugLogging(payload: { enabled: boolean }): Promise<unknown> {
    try {
      const { enabled } = payload;
      await logger.setDebugEnabled(enabled);
      logger.info(`Debug logging ${enabled ? 'enabled' : 'disabled'}`);
      return { success: true, enabled };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleGetDebugLogging(): Promise<unknown> {
    try {
      const enabled = logger.isDebugEnabled();
      return { success: true, enabled };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }
  private async handleSetAutoLockTimeout(payload: { minutes: number }): Promise<unknown> {
    try {
      const ms = payload.minutes === 0 ? 0 : payload.minutes * 60 * 1000;
      secureStorage.setAutoLockTimeout(ms);
      await chrome.storage.local.set({ auto_lock_timeout: payload.minutes });
      logger.info(`Auto-lock timeout set to ${payload.minutes} minutes`);
      return { success: true, minutes: payload.minutes };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleGetWebAuthnLog(): Promise<unknown> {
    try {
      const result = await chrome.storage.local.get('webauthn_log');
      return { success: true, logs: result.webauthn_log || [] };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleClearWebAuthnLog(): Promise<unknown> {
    try {
      await chrome.storage.local.set({ webauthn_log: [] });
      return { success: true };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }
}

new BackgroundService();
