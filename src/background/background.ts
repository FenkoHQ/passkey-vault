import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToBytes,
  deriveEd25519Keypair,
} from '../crypto/bip39';
import { syncService } from '../sync/sync-service';
import { secureStorage, SecureStorageConfig } from '../crypto/secure-storage';
import { randomBytes } from '@noble/hashes/utils';
import { logger } from '../utils/logger';

const PASSKEY_STORAGE_KEY = 'passkeys';
const SYNC_CONFIG_KEY = 'sync_config';
const SYNC_DEVICES_KEY = 'sync_devices';
const SYNC_STATUS_KEY = 'sync_status';

// SECURITY: Flag to track if secure storage is initialized
// In production, this should always require user interaction to unlock

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
  // SECURITY FIX: Random salt for PBKDF2 derivation
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

class BackgroundService {
  private agents: Map<string, any>;
  private isInitialized: boolean;
  private syncStatus: SyncStatus;

  constructor() {
    this.agents = new Map();
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
    this.initialize();
  }

  private async initialize(): Promise<void> {
    try {
      // Initialize logger first
      await logger.init();

      logger.info('Background service initializing...');
      this.setupMessageHandlers();
      this.setupLifecycleHandlers();
      await this.initializeAgents();
      await this.initializeSyncService();
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
        // SECURITY FIX: Pass syncSalt to sync service for random PBKDF2 derivation
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
    } catch (error: any) {
      logger.error('Failed to start sync service:', error);
      await this.updateSyncStatus({
        connectionStatus: 'error',
        lastError: error.message,
      });
    }
  }

  private setupMessageHandlers(): void {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true;
    });
  }

  private async handleMessage(
    message: any,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response?: any) => void
  ): Promise<void> {
    try {
      const response = await this.routeMessage(message, sender);
      sendResponse(response);
    } catch (error: any) {
      console.error('Message handling error:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  private async routeMessage(message: any, sender: chrome.runtime.MessageSender): Promise<any> {
    const { type, payload } = message;

    switch (type) {
      case 'CREATE_PASSKEY':
        return this.handleCreatePasskey(payload, sender);
      case 'GET_PASSKEY':
        return this.handleGetPasskey(payload, sender);
      case 'STORE_PASSKEY':
        return this.handleStorePasskey(payload, sender);
      case 'RETRIEVE_PASSKEY':
        return this.handleRetrievePasskey(payload, sender);
      case 'LIST_PASSKEYS':
        return this.handleListPasskeys(payload, sender);
      case 'LIST_PASSKEYS_FOR_RP':
        return this.handleListPasskeysForRp(payload, sender);
      case 'GET_PASSKEYS':
        return this.handleListPasskeys(payload, sender);
      case 'DELETE_PASSKEY':
        return this.handleDeletePasskey(payload, sender);
      case 'BACKUP':
        return this.handleBackup(payload, sender);
      case 'RESTORE':
        return this.handleRestore(payload, sender);
      case 'ACTIVATE_UI':
        return this.handleActivateUI(payload, sender);
      case 'CREATE_SYNC_CHAIN':
        return this.createSyncChain(message.deviceName, message.wordCount);
      case 'JOIN_SYNC_CHAIN':
        return this.joinSyncChain(message.deviceName, message.mnemonic);
      case 'LEAVE_SYNC_CHAIN':
        return this.leaveSyncChain();
      case 'GET_SYNC_CHAIN_INFO':
        return this.getSyncChainInfo();
      case 'REMOVE_SYNC_DEVICE':
        return this.removeSyncDevice(message.deviceId);
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
      // SECURITY: Secure storage message handlers for encrypted passkey storage
      case 'SETUP_MASTER_PASSWORD':
        return this.handleSetupMasterPassword(payload);
      case 'UNLOCK_SECURE_STORAGE':
        return this.handleUnlockSecureStorage(payload);
      case 'LOCK_SECURE_STORAGE':
        return this.handleLockSecureStorage();
      case 'IS_SECURE_STORAGE_UNLOCKED':
        return this.handleIsSecureStorageUnlocked();
      case 'CHANGE_MASTER_PASSWORD':
        return this.handleChangeMasterPassword(payload);
      case 'SET_DEBUG_LOGGING':
        return this.handleSetDebugLogging(payload);
      case 'GET_DEBUG_LOGGING':
        return this.handleGetDebugLogging();
      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  private setupLifecycleHandlers(): void {
    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstalled(details);
    });
    chrome.runtime.onStartup.addListener(() => {
      this.handleStartup();
    });
    chrome.runtime.onSuspend.addListener(() => {
      this.handleSuspend();
    });
  }

  private handleInstalled(details: chrome.runtime.InstalledDetails): void {
    logger.info('Extension installed', details);
    if (details.reason === 'install') {
      logger.info('First-time installation');
    } else if (details.reason === 'update') {
      logger.info('Extension updated');
    }
  }

  private handleStartup(): void {
    logger.info('Extension startup');
  }

  private handleSuspend(): void {
    logger.info('Extension suspending');
  }

  private async initializeAgents(): Promise<void> {
    logger.debug('Initializing agents...');
    logger.debug('Agents initialized (placeholder)');
  }

  private async handleCreatePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { publicKey: options, origin } = payload;
      const challenge = options?.challenge;
      const user = options?.user;
      const rpId =
        options?.rpId || options?.rp?.id || (origin ? new URL(origin).hostname : 'localhost');

      logger.debug('Creating passkey for', rpId, 'user:', user?.name);

      const existingResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const existingPasskeys: any[] = existingResult[PASSKEY_STORAGE_KEY] || [];
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

      const credentialId = this.generateCredentialId();
      const credentialIdBase64 = this.arrayBufferToBase64URL(credentialId.buffer as ArrayBuffer);

      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );

      const privateKeyExport = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const privateKeyBytes = new Uint8Array(privateKeyExport);
      let privateKeyBinary = '';
      for (let i = 0; i < privateKeyBytes.length; i++) {
        privateKeyBinary += String.fromCharCode(privateKeyBytes[i]);
      }
      const privateKeyBase64 = btoa(privateKeyBinary);

      const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
      const publicKeyBytes = new Uint8Array(publicKeyRaw);
      let publicKeyBinary = '';
      for (let i = 0; i < publicKeyBytes.length; i++) {
        publicKeyBinary += String.fromCharCode(publicKeyBytes[i]);
      }
      const publicKeyBase64 = btoa(publicKeyBinary);

      const prfKeyBytes = crypto.getRandomValues(new Uint8Array(32));
      const prfKeyBase64 = this.arrayBufferToBase64URL(prfKeyBytes.buffer);

      const prfInput = options?.extensions?.prf;
      const prfEvalInput = this.selectPrfEval(prfInput, credentialIdBase64);
      const prfResults = prfEvalInput
        ? await this.computePrfResults(prfKeyBytes.buffer, prfEvalInput)
        : null;
      const extensionsData = prfResults ? this.encodePrfExtension(prfResults) : null;
      const clientExtensionResults = this.buildClientExtensionResults(prfResults);

      const clientData = { type: 'webauthn.create', challenge, origin };
      const clientDataJSONBytes = new TextEncoder().encode(JSON.stringify(clientData));

      const authenticatorData = await this.createAuthenticatorDataAsync(
        rpId,
        credentialId,
        publicKeyRaw,
        true,
        0,
        extensionsData
      );

      const attestationObject = this.createAttestationObjectNone(authenticatorData);

      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];

      passkeys.push({
        id: credentialIdBase64,
        credentialId: credentialIdBase64,
        type: 'public-key',
        rpId,
        origin,
        user: {
          id: user?.id
            ? user.id instanceof ArrayBuffer
              ? this.arrayBufferToBase64URL(user.id)
              : user.id
            : null,
          name: user?.name,
          displayName: user?.displayName,
        },
        privateKey: privateKeyBase64,
        publicKey: publicKeyBase64,
        createdAt: Date.now(),
        counter: 0,
        prfKey: prfKeyBase64,
      });

      await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });
      logger.debug('Created and stored passkey', credentialIdBase64);

      this.logSync('PASSKEY_CREATED', { id: credentialIdBase64, rpId });
      await this.incrementPendingChanges();
      this.triggerSync();

      const rawIdBase64 = this.base64urlToBase64(credentialIdBase64);
      const clientDataJSONBase64 = this.arrayBufferToBase64(clientDataJSONBytes.buffer);
      const attestationObjectBase64 = this.arrayBufferToBase64(attestationObject);

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
    } catch (error: any) {
      logger.error('Error creating passkey:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleGetPasskey(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    try {
      const { publicKey: options, origin, selectedPasskeyId } = payload;
      const challenge = options?.challenge;
      const rpId = options?.rpId || (origin ? new URL(origin).hostname : 'localhost');

      logger.debug('Getting passkey for', rpId, 'selectedId:', selectedPasskeyId);

      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      if (matchingPasskeys.length === 0) {
        logger.debug('No passkeys found for', rpId);
        return {
          success: false,
          error: 'No passkeys found for this site',
          name: 'NotAllowedError',
        };
      }

      let passkey;
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

      let privateKeyBinary;
      try {
        privateKeyBinary = atob(passkey.privateKey);
      } catch (atobError: any) {
        logger.error('Failed to decode private key:', atobError);
        throw new Error('Invalid base64 encoding for private key: ' + atobError.message);
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

      const prfInput = options?.extensions?.prf;
      const prfEvalInput = this.selectPrfEval(prfInput, passkey.id);
      const prfKeyBuffer = await this.getOrCreatePrfKey(passkey);
      const prfResults = prfEvalInput
        ? await this.computePrfResults(prfKeyBuffer, prfEvalInput)
        : null;
      const extensionsData = prfResults ? this.encodePrfExtension(prfResults) : null;
      const clientExtensionResults = this.buildClientExtensionResults(prfResults);

      passkey.counter = (passkey.counter || 0) + 1;
      const authenticatorData = await this.createAuthenticatorDataAsync(
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

      const signatureDER = this.convertP1363ToDER(signatureP1363);

      const index = passkeys.findIndex((p) => p.id === passkey.id);
      if (index >= 0) {
        passkeys[index] = passkey;
        await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });
      }

      logger.debug('Signed assertion for', passkey.id);

      const rawIdBase64 = this.base64urlToBase64(passkey.id);
      const clientDataJSONBase64 = this.arrayBufferToBase64(clientDataJSONBytes.buffer);
      const authenticatorDataBase64 = this.arrayBufferToBase64(authenticatorData);
      const signatureBase64 = this.arrayBufferToBase64(signatureDER);
      const userHandleBase64 = passkey.user?.id
        ? typeof passkey.user.id === 'string'
          ? this.base64urlToBase64(passkey.user.id)
          : this.arrayBufferToBase64(passkey.user.id)
        : null;

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
    } catch (error: any) {
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

  private generateCredentialId(): Uint8Array {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return array;
  }

  private arrayBufferToBase64URL(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary);
  }

  private base64urlToBase64(base64url: string): string {
    if (!base64url || typeof base64url !== 'string') {
      throw new Error('base64urlToBase64 requires a string input');
    }
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = (4 - (base64.length % 4)) % 4;
    if (padding > 0) {
      base64 += '='.repeat(padding);
    }
    return base64;
  }

  private base64URLToArrayBuffer(base64url: any): ArrayBuffer {
    if (base64url instanceof ArrayBuffer) return base64url;
    if (base64url instanceof Uint8Array) return base64url.buffer as ArrayBuffer;
    if (ArrayBuffer.isView(base64url)) return base64url.buffer as ArrayBuffer;
    if (base64url?.type === 'Buffer' && Array.isArray(base64url.data)) {
      return new Uint8Array(base64url.data).buffer;
    }
    if (base64url == null) throw new TypeError('Unsupported base64 input type: null/undefined');
    if (typeof base64url !== 'string') base64url = String(base64url);
    if (base64url.length === 0) throw new Error('Empty base64 string provided');

    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i) & 0xff;
    }
    return bytes.buffer;
  }

  private selectPrfEval(prfInput: any, credentialId?: string): any | null {
    if (!prfInput) return null;
    if (prfInput.eval) return prfInput.eval;
    const map = prfInput.evalByCredential;
    if (!map) return null;

    const candidates = new Set<string>();
    if (credentialId) {
      candidates.add(credentialId);
      try {
        candidates.add(this.base64urlToBase64(credentialId));
      } catch {
        /* ignore */
      }
    }

    for (const key of Object.keys(map)) {
      if (candidates.has(key)) return map[key];
      try {
        const decoded = this.base64URLToArrayBuffer(key);
        const asUrl = this.arrayBufferToBase64URL(decoded);
        if (asUrl && candidates.has(asUrl)) return map[key];
      } catch {
        /* ignore */
      }
    }
    return null;
  }

  private async getOrCreatePrfKey(passkey: any): Promise<ArrayBuffer> {
    if (passkey.prfKey) return this.decodeBase64Flexible(passkey.prfKey);
    const privateKeyBytes = this.base64URLToArrayBuffer(passkey.privateKey);
    const derived = await crypto.subtle.digest('SHA-256', privateKeyBytes);
    passkey.prfKey = this.arrayBufferToBase64URL(derived);
    return derived;
  }

  private normalizePrfInput(input: any): ArrayBuffer | null {
    if (!input) return null;
    if (input instanceof ArrayBuffer) return input;
    if (ArrayBuffer.isView(input)) return input.buffer as ArrayBuffer;
    if (input?.type === 'Buffer' && Array.isArray(input.data)) {
      return new Uint8Array(input.data).buffer;
    }
    if (Array.isArray(input)) return new Uint8Array(input).buffer;

    if (typeof input === 'string') {
      try {
        return this.base64URLToArrayBuffer(input);
      } catch {
        try {
          return this.decodeBase64Flexible(input);
        } catch {
          return null;
        }
      }
    }

    if (typeof input === 'object' && input !== null) {
      const keys = Object.keys(input);
      if (keys.length > 0 && keys.every((k) => !isNaN(Number(k)))) {
        const maxIndex = Math.max(...keys.map(Number));
        const arr = new Uint8Array(maxIndex + 1);
        for (const key of keys) arr[Number(key)] = input[key];
        return arr.buffer;
      }
    }
    return null;
  }

  private async computePrfResults(prfKey: ArrayBuffer, evalInput: any): Promise<any | null> {
    if (!evalInput) return null;
    const results: any = { results: {} };
    const first = this.normalizePrfInput(evalInput.first);
    const second = this.normalizePrfInput(evalInput.second);

    if (first) results.results.first = await this.hmacSha256(prfKey, first);
    if (second) results.results.second = await this.hmacSha256(prfKey, second);

    if (!results.results.first && !results.results.second) return null;
    return results;
  }

  private async hmacSha256(keyBytes: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return crypto.subtle.sign('HMAC', key, data);
  }

  private buildClientExtensionResults(prfResults: any | null): any {
    const baseResults: any = { credProps: { rk: true } };
    if (!prfResults?.results) return baseResults;

    const encoded: any = { results: {} };
    if (prfResults.results.first) {
      encoded.results.first = this.arrayBufferToBase64URL(prfResults.results.first);
    }
    if (prfResults.results.second) {
      encoded.results.second = this.arrayBufferToBase64URL(prfResults.results.second);
    }
    if (encoded.results.first || encoded.results.second) baseResults.prf = encoded;
    return baseResults;
  }

  private encodePrfExtension(prfResults: any | null): Uint8Array | null {
    if (!prfResults?.results) return null;

    const resultEntries: number[] = [];
    let resultCount = 0;

    if (prfResults.results.first) {
      resultEntries.push(...this.encodeTextString('first'));
      resultEntries.push(...this.encodeByteString(new Uint8Array(prfResults.results.first)));
      resultCount++;
    }
    if (prfResults.results.second) {
      resultEntries.push(...this.encodeTextString('second'));
      resultEntries.push(...this.encodeByteString(new Uint8Array(prfResults.results.second)));
      resultCount++;
    }
    if (resultCount === 0) return null;

    const resultsMap = [...this.encodeMapHeader(resultCount), ...resultEntries];
    const prfMap = [...this.encodeMapHeader(1), ...this.encodeTextString('results'), ...resultsMap];
    const extensions = [...this.encodeMapHeader(1), ...this.encodeTextString('prf'), ...prfMap];
    return new Uint8Array(extensions);
  }

  private encodeMapHeader(length: number): number[] {
    if (length < 24) return [0xa0 + length];
    if (length < 256) return [0xb8, length];
    return [0xb9, (length >> 8) & 0xff, length & 0xff];
  }

  private encodeTextString(value: string): number[] {
    const bytes = new TextEncoder().encode(value);
    const header =
      bytes.length < 24
        ? [0x60 + bytes.length]
        : bytes.length < 256
          ? [0x78, bytes.length]
          : [0x79, (bytes.length >> 8) & 0xff, bytes.length & 0xff];
    return [...header, ...bytes];
  }

  private encodeByteString(bytes: Uint8Array): number[] {
    if (bytes.length < 24) return [0x40 + bytes.length, ...bytes];
    if (bytes.length < 256) return [0x58, bytes.length, ...bytes];
    return [0x59, (bytes.length >> 8) & 0xff, bytes.length & 0xff, ...bytes];
  }

  private decodeBase64Flexible(value: any): ArrayBuffer {
    if (value instanceof ArrayBuffer) return value;
    if (ArrayBuffer.isView(value)) return value.buffer as ArrayBuffer;
    if (value?.type === 'Buffer' && Array.isArray(value.data)) {
      return new Uint8Array(value.data).buffer;
    }
    if (typeof value !== 'string') throw new TypeError('Invalid base64 input type');

    try {
      return this.base64URLToArrayBuffer(value);
    } catch {
      /* fall through */
    }

    const padded =
      value.length % 4 === 0 ? value : value + '='.repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i) & 0xff;
    }
    return bytes.buffer;
  }

  private async createAuthenticatorDataAsync(
    rpId: string,
    credentialId: Uint8Array | null,
    publicKeyRaw: ArrayBuffer | null,
    includeAttestedCredentialData: boolean,
    counter: number = 0,
    extensionsData?: Uint8Array | null
  ): Promise<ArrayBuffer> {
    const rpIdBytes = new TextEncoder().encode(rpId);
    const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', rpIdBytes));

    let flagsByte = includeAttestedCredentialData ? 0x45 : 0x05;
    if (extensionsData && extensionsData.length > 0) flagsByte |= 0x80;
    const flags = new Uint8Array([flagsByte]);

    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);

    if (includeAttestedCredentialData && credentialId && publicKeyRaw) {
      const aaguid = new Uint8Array(16);
      const credentialIdLength = new Uint8Array(2);
      new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length, false);
      const cosePublicKey = this.rawPublicKeyToCose(publicKeyRaw);

      const authData = new Uint8Array(
        rpIdHash.length +
          flags.length +
          counterBytes.length +
          aaguid.length +
          credentialIdLength.length +
          credentialId.length +
          cosePublicKey.length +
          (extensionsData?.length || 0)
      );

      let offset = 0;
      authData.set(rpIdHash, offset);
      offset += rpIdHash.length;
      authData.set(flags, offset);
      offset += flags.length;
      authData.set(counterBytes, offset);
      offset += counterBytes.length;
      authData.set(aaguid, offset);
      offset += aaguid.length;
      authData.set(credentialIdLength, offset);
      offset += credentialIdLength.length;
      authData.set(credentialId, offset);
      offset += credentialId.length;
      authData.set(cosePublicKey, offset);
      offset += cosePublicKey.length;
      if (extensionsData && extensionsData.length > 0) authData.set(extensionsData, offset);

      return authData.buffer;
    } else {
      const authData = new Uint8Array(
        rpIdHash.length + flags.length + counterBytes.length + (extensionsData?.length || 0)
      );
      let offset = 0;
      authData.set(rpIdHash, offset);
      offset += rpIdHash.length;
      authData.set(flags, offset);
      offset += flags.length;
      authData.set(counterBytes, offset);
      offset += counterBytes.length;
      if (extensionsData && extensionsData.length > 0) authData.set(extensionsData, offset);

      return authData.buffer;
    }
  }

  private rawPublicKeyToCose(rawKey: ArrayBuffer): Uint8Array {
    const raw = new Uint8Array(rawKey);
    const x = raw.slice(1, 33);
    const y = raw.slice(33, 65);

    const coseKey: number[] = [];
    coseKey.push(0xa5);
    coseKey.push(0x01, 0x02);
    coseKey.push(0x03, 0x26);
    coseKey.push(0x20, 0x01);
    coseKey.push(0x21, 0x58, 0x20);
    for (let i = 0; i < x.length; i++) coseKey.push(x[i]);
    coseKey.push(0x22, 0x58, 0x20);
    for (let i = 0; i < y.length; i++) coseKey.push(y[i]);

    return new Uint8Array(coseKey);
  }

  private convertP1363ToDER(p1363Sig: ArrayBuffer): ArrayBuffer {
    const sig = new Uint8Array(p1363Sig);
    const r = sig.slice(0, 32);
    const s = sig.slice(32, 64);
    const rDer = this.encodeDERInteger(r);
    const sDer = this.encodeDERInteger(s);
    const sequenceLength = rDer.length + sDer.length;

    let result;
    if (sequenceLength <= 127) {
      result = new Uint8Array(2 + sequenceLength);
      result[0] = 0x30;
      result[1] = sequenceLength;
      result.set(rDer, 2);
      result.set(sDer, 2 + rDer.length);
    } else {
      result = new Uint8Array(3 + sequenceLength);
      result[0] = 0x30;
      result[1] = 0x81;
      result[2] = sequenceLength;
      result.set(rDer, 3);
      result.set(sDer, 3 + rDer.length);
    }
    return result.buffer;
  }

  private encodeDERInteger(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.slice(start);
    const needsPadding = (trimmed[0] & 0x80) !== 0;
    const length = trimmed.length + (needsPadding ? 1 : 0);

    const result = new Uint8Array(2 + length);
    result[0] = 0x02;
    result[1] = length;
    if (needsPadding) {
      result[2] = 0x00;
      result.set(trimmed, 3);
    } else {
      result.set(trimmed, 2);
    }
    return result;
  }

  private createAttestationObjectNone(authenticatorData: ArrayBuffer): ArrayBuffer {
    const authDataBytes = new Uint8Array(authenticatorData);
    const parts: number[] = [];

    parts.push(0xa3);
    parts.push(0x63);
    parts.push(0x66, 0x6d, 0x74);
    parts.push(0x64);
    parts.push(0x6e, 0x6f, 0x6e, 0x65);
    parts.push(0x67);
    parts.push(0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74);
    parts.push(0xa0);
    parts.push(0x68);
    parts.push(0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61);

    if (authDataBytes.length <= 23) {
      parts.push(0x40 + authDataBytes.length);
    } else if (authDataBytes.length <= 255) {
      parts.push(0x58, authDataBytes.length);
    } else {
      parts.push(0x59, (authDataBytes.length >> 8) & 0xff, authDataBytes.length & 0xff);
    }

    const result = new Uint8Array(parts.length + authDataBytes.length);
    result.set(parts, 0);
    result.set(authDataBytes, parts.length);
    return result.buffer;
  }

  private async handleStorePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { publicKey, origin, options } = payload;
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];
      const rpId = options?.publicKey?.rpId || new URL(origin).hostname;
      const credentialId = publicKey?.id || publicKey?.rawId;

      if (credentialId) {
        const existingIndex = passkeys.findIndex((p) => p.credentialId === credentialId);
        const passkeyData = {
          credentialId,
          id: publicKey.id,
          rawId: publicKey.rawId,
          type: publicKey.type,
          response: publicKey.response,
          rpId,
          origin,
          createdAt: Date.now(),
        };

        if (existingIndex >= 0) {
          passkeys[existingIndex] = passkeyData;
        } else {
          passkeys.push(passkeyData);
        }

        await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });
        logger.debug('Stored passkey', credentialId, 'for', rpId);
        return { success: true, message: 'Passkey stored successfully', count: passkeys.length };
      }
      return { success: false, error: 'No credential ID in payload' };
    } catch (error: any) {
      logger.error('Error storing passkey:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleRetrievePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { publicKey, origin } = payload;
      const rpId = publicKey?.rpId || (origin ? new URL(origin).hostname : null);
      if (!rpId) return { success: false, error: 'No rpId provided' };

      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];
      const matchingPasskeys = passkeys.filter((p) => p.rpId === rpId);

      logger.debug('Found', matchingPasskeys.length, 'passkeys for', rpId);
      return { success: true, passkeys: matchingPasskeys, count: matchingPasskeys.length, rpId };
    } catch (error: any) {
      logger.error('Error retrieving passkey:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleListPasskeys(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];
      return { success: true, passkeys, count: passkeys.length };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async handleListPasskeysForRp(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { rpId } = payload;
      if (!rpId) return { success: false, error: 'No rpId provided' };

      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];
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
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async handleDeletePasskey(
    payload: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    try {
      const { credentialId } = payload;
      const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = result[PASSKEY_STORAGE_KEY] || [];
      const filtered = passkeys.filter(
        (p) => p.credentialId !== credentialId && p.id !== credentialId
      );

      if (filtered.length < passkeys.length) {
        await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: filtered });

        this.logSync('PASSKEY_DELETED', { credentialId });
        await this.incrementPendingChanges();
        this.triggerSync();

        return { success: true, message: 'Passkey deleted' };
      }
      return { success: false, error: 'Passkey not found' };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async handleBackup(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    return { success: true, message: 'Backup placeholder' };
  }

  private async handleRestore(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    return { success: true, message: 'Restore placeholder' };
  }

  private async handleActivateUI(payload: any, sender: chrome.runtime.MessageSender): Promise<any> {
    return { success: true, message: 'Activate UI placeholder' };
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
      const chainId = seedHashHex.substring(0, 32);

      // SECURITY FIX: Generate random salt for PBKDF2 key derivation
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

      // SECURITY FIX: Store config with sync salt
      // NOTE: In production, seedHash should be encrypted with master password
      // using secureStorage.storeSyncConfig() after user sets up master password
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

      // Initialize sync service with the random salt
      await syncService.initialize(chainId, deviceId, seedHashHex, deviceName, syncSalt);
      this.logSync('SYNC_CHAIN_CREATED', { chainId, deviceId });

      return { success: true, mnemonic, deviceId, chainId };
    } catch (error: any) {
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

      // SECURITY FIX: Generate random salt for PBKDF2 key derivation
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

      // SECURITY FIX: Include syncSalt in config
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

      // Initialize sync service with the random salt
      await syncService.initialize(chainId, deviceId, seedHashHex, deviceName, syncSalt);
      await syncService.requestSync();
      this.logSync('SYNC_CHAIN_JOINED', { chainId, deviceId });

      return { success: true, deviceId };
    } catch (error: any) {
      console.error('Failed to join sync chain:', error);
      return { success: false, error: error.message };
    }
  }

  private async leaveSyncChain(): Promise<any> {
    try {
      await syncService.disconnect();

      // SECURITY FIX: Include syncSalt: null when clearing config
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
    } catch (error: any) {
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
    } catch (error: any) {
      console.error('Failed to get sync chain info:', error);
      return { success: false, error: error.message };
    }
  }

  private async removeSyncDevice(deviceId: string): Promise<any> {
    try {
      const result = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain: SyncChain = result[SYNC_DEVICES_KEY];

      if (!chain) return { success: false, error: 'Sync chain not found' };

      const updatedDevices = chain.devices.filter((d) => d.id !== deviceId);
      const updatedChain: SyncChain = { ...chain, devices: updatedDevices };

      await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: updatedChain });
      return { success: true };
    } catch (error: any) {
      console.error('Failed to remove sync device:', error);
      return { success: false, error: error.message };
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

  private async getSyncStatus(): Promise<any> {
    try {
      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];
      const passkeysResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = passkeysResult[PASSKEY_STORAGE_KEY] || [];

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
    } catch (error: any) {
      logger.error('Error getting sync status:', error);
      return { success: false, error: error.message };
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

  private logSync(action: string, details?: any): void {
    const timestamp = new Date().toISOString();
    console.log(`[SYNC ${timestamp}] ${action}`, details || '');
  }

  private async handleTriggerSync(): Promise<any> {
    await this.triggerSync();
    return { success: true };
  }

  private async getSyncDebugInfo(): Promise<any> {
    try {
      const debugInfo = syncService.getDebugInfo();
      return { success: true, debugInfo };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async getSyncDebugLogs(): Promise<any> {
    try {
      const logs = syncService.getDebugLogs();
      return { success: true, logs };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async clearSyncDebugLogs(): Promise<any> {
    try {
      syncService.clearDebugLogs();
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message };
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
      const passkeysResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = passkeysResult[PASSKEY_STORAGE_KEY] || [];

      const syncStatus = syncService.getStatus();
      if (!syncStatus.connected) {
        if (config.chainId && config.deviceId && config.seedHash) {
          // SECURITY FIX: Pass syncSalt to sync service for random PBKDF2 derivation
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

      this.logSync('SYNC_COMPLETE', {
        passkeyCount: passkeys.length,
      });
    } catch (error: any) {
      await this.updateSyncStatus({
        connectionStatus: 'error',
        lastError: error.message,
      });
      this.logSync('SYNC_ERROR', { error: error.message });
    }
  }

  // ==================== SECURE STORAGE HANDLERS ====================
  // These handlers provide secure encrypted storage for sensitive data
  // using a master password with PBKDF2 key derivation

  private async handleSetupMasterPassword(payload: { password: string }): Promise<any> {
    try {
      const { password } = payload;
      if (!password || password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters' };
      }

      // Initialize secure storage with master password
      const unlocked = await secureStorage.initialize(password);
      if (!unlocked) {
        return { success: false, error: 'Failed to initialize secure storage' };
      }

      // Migrate existing sync config to secure storage if present
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

      // Migrate existing passkeys to secure storage
      const passkeysResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
      const passkeys: any[] = passkeysResult[PASSKEY_STORAGE_KEY] || [];
      for (const passkey of passkeys) {
        await secureStorage.upsertPasskey(passkey);
      }
      if (passkeys.length > 0) {
        logger.info(`Migrated ${passkeys.length} passkeys to secure storage`);
      }

      return { success: true, message: 'Master password setup complete' };
    } catch (error: any) {
      console.error('Failed to setup master password:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleUnlockSecureStorage(payload: { password: string }): Promise<any> {
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
    } catch (error: any) {
      console.error('Failed to unlock secure storage:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleLockSecureStorage(): Promise<any> {
    try {
      secureStorage.lock();
      return { success: true, message: 'Secure storage locked' };
    } catch (error: any) {
      console.error('Failed to lock secure storage:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleIsSecureStorageUnlocked(): Promise<any> {
    try {
      const isUnlocked = secureStorage.isStorageUnlocked();
      const isSetup = await secureStorage.isSetup();
      return { success: true, isUnlocked, isSetup };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async handleChangeMasterPassword(payload: {
    currentPassword: string;
    newPassword: string;
  }): Promise<any> {
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
    } catch (error: any) {
      console.error('Failed to change master password:', error);
      return { success: false, error: error.message };
    }
  }

  private async handleSetDebugLogging(payload: { enabled: boolean }): Promise<any> {
    try {
      const { enabled } = payload;
      await logger.setDebugEnabled(enabled);
      logger.info(`Debug logging ${enabled ? 'enabled' : 'disabled'}`);
      return { success: true, enabled };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  private async handleGetDebugLogging(): Promise<any> {
    try {
      const enabled = logger.isDebugEnabled();
      return { success: true, enabled };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }
}

const backgroundService = new BackgroundService();
