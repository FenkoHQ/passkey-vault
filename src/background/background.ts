import { cleanSyncConfig } from '../sync/config';
import {
  restoreRecord,
  mergeRecords,
  mergeDeletions,
  SYNC_DELETIONS_KEY,
  type SyncDeletion,
} from '../sync/merge';
import { repairCredentialIds, toBase64Url } from '../sync/credential-ids';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToBytes,
  deriveEd25519Keypair,
} from '../crypto/bip39';
import {
  syncService,
  type SyncPasskey,
  type SyncTotpEntry,
  type SyncVaultAdapter,
} from '../sync/sync-service';
import { AUTO_LOCK_ALARM, AUTO_LOCK_SETTING_KEY, secureStorage } from '../crypto/secure-storage';
import { encryptWithPassword, decryptWithPassword } from '../crypto/encryption';
import { logger } from '../utils/logger';
import { arrayBufferToBase64, arrayBufferToBase64URL, base64urlToBase64 } from '../utils/base64';
import {
  createAuthenticatorData,
  createAttestationObjectNone,
  convertP1363ToDER,
  ANONYMOUS_AAGUID,
  PASSKEY_VAULT_AAGUID,
  COSE_ALG_ES256,
  type AuthenticatorDataOptions,
} from './cbor';
import {
  ensureBackupFlagsSnapshot,
  loadBackupFlagsSnapshot,
  loadWebAuthnFlags,
  saveWebAuthnFlags,
  transportsFor,
  type WebAuthnFlagSettings,
} from './webauthn-settings';
import {
  applyBackupRepairs,
  backupFlagsOf,
  normalizeBackupFlags,
  stampLegacyBackupFlags,
  withBackupFlags,
  PRE_UPGRADE_BACKUP_FLAGS,
  type BackupFields,
  type BackupFlags,
  type BackupRepair,
} from '../sync/backup-flags';
import { verifyRelatedOrigin } from './related-origins';
import { serializeClientData } from './client-data';
import { acceptsEs256 } from '../utils/algorithms';
import { isRpIdValidForHost } from '../utils/rp-id';
import { needsSiteIcon, saveSiteIcon, clearSiteIcons } from '../site-icons';
import {
  selectPrfEval,
  getOrCreatePrfKey,
  computePrfResults,
  buildClientExtensionResults,
  usablePrfInput,
} from './prf';
import {
  generateTotp as generateTotpCode,
  generateHotp as generateHotpCode,
  parseOtpauth,
} from '../crypto/totp';
import {
  loadTotpEntries,
  saveTotpEntries,
  addTotpEntry as addTotpEntryStore,
  deleteTotpEntry as deleteTotpEntryStore,
  issueHotpCode,
  entryToSecretBytes,
  generateTotpId,
  TOTP_STORAGE_KEY,
  type StoredTotpEntry,
} from '../crypto/totp-store';

const PASSKEY_STORAGE_KEY = 'passkeys';
const SYNC_CONFIG_KEY = 'sync_config';
const SYNC_DEVICES_KEY = 'sync_devices';
const SYNC_STATUS_KEY = 'sync_status';
const UPGRADE_BACKUP_REQUIRED_KEY = 'upgrade_backup_required_0_9_5';

/**
 * The content script's account of the calling frame, for clientData
 * crossOrigin/topOrigin. Absent fields mean a top-level, same-origin call.
 */
function callerFrame(payload: MessagePayload): { crossOrigin: boolean; topOrigin?: string } {
  const crossOrigin = payload.crossOrigin === true;
  const topOrigin = typeof payload.topOrigin === 'string' ? payload.topOrigin : undefined;
  return crossOrigin && topOrigin ? { crossOrigin, topOrigin } : { crossOrigin };
}

/**
 * Translate the user's Advanced settings, and the passkey's own backup flags,
 * into authenticator data flags.
 */
function toAuthenticatorDataOptions(
  flags: WebAuthnFlagSettings,
  backup: BackupFlags
): AuthenticatorDataOptions {
  return {
    userVerified: flags.userVerification === 'always',
    backupEligible: backup.backupEligible,
    backupState: backup.backupState,
    aaguid: flags.aaguid === 'zero' ? ANONYMOUS_AAGUID : PASSKEY_VAULT_AAGUID,
  };
}

interface StoredPasskey extends BackupFields {
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
  updatedAt?: number;
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
  /**
   * Written by older builds only. Nothing reads it, and it put the seed in
   * cleartext; stripCleartextChainSeed() removes it from PIN'd vaults.
   */
  seedHash?: string;
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

/**
 * What a content script may ask for. A content script runs in the web
 * page's renderer process, which a browser exploit can take over and use to
 * send any message the content script could, so these are the only
 * messages accepted from a web page: the ceremony itself, and nothing that
 * reads, exports, changes or deletes the vault or its settings.
 */
const WEB_PAGE_MESSAGES = new Set([
  'CREATE_PASSKEY',
  'GET_PASSKEY',
  'LIST_PASSKEYS_FOR_RP',
  'VERIFY_RELATED_ORIGIN',
  'NEEDS_SITE_ICON',
  'SAVE_SITE_ICON',
  'ACTIVATE_UI',
]);

/** The popup, options and other pages bundled with the extension. */
function isExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return typeof sender?.url === 'string' && sender.url.startsWith(chrome.runtime.getURL(''));
}

/** The web origin Chrome says a message came from, or null if it has none. */
function webOrigin(sender: chrome.runtime.MessageSender): string | null {
  try {
    const origin = sender.origin || new URL(sender.url || '').origin;
    return /^https?:\/\//.test(origin) ? origin : null;
  } catch {
    return null;
  }
}

/** Refuse an RP ID the sending origin may not use, as the content script does. */
async function requireRpIdFor(rpId: string, origin: string): Promise<void> {
  if (isRpIdValidForHost(rpId, new URL(origin).hostname)) return;
  if (await verifyRelatedOrigin(rpId, origin)) return;
  throw new Error(`RP ID ${rpId} is not valid for ${origin}`);
}

/**
 * Check a content script's message against Chrome's account of the sender,
 * and rewrite what the page could otherwise lie about: the origin written
 * into clientDataJSON, the RP ID it signs for, and whether it runs in a
 * cross-origin frame. Throws for anything a web page may not ask.
 */
async function bindToWebPage(
  message: ExtensionMessage,
  sender: chrome.runtime.MessageSender
): Promise<ExtensionMessage> {
  if (!WEB_PAGE_MESSAGES.has(message.type)) {
    throw new Error(`${message.type} is not available to web pages`);
  }
  const origin = webOrigin(sender);
  if (!origin) {
    throw new Error('Message from an unknown sender');
  }
  const host = new URL(origin).hostname;
  const payload: MessagePayload = { ...(message.payload || {}) };

  switch (message.type) {
    case 'CREATE_PASSKEY':
    case 'GET_PASSKEY': {
      const publicKey = { ...((payload.publicKey as MessagePayload) || {}) };
      const rp = publicKey.rp as Record<string, unknown> | undefined;
      const rpId = String(publicKey.rpId || rp?.id || host);
      await requireRpIdFor(rpId, origin);
      publicKey.rpId = rpId;
      payload.publicKey = publicKey;
      payload.origin = origin;
      // A frame whose origin differs from the tab's top-level page is
      // cross-origin whatever the page claims.
      let tabOrigin: string | null = null;
      try {
        tabOrigin = sender.tab?.url ? new URL(sender.tab.url).origin : null;
      } catch {
        tabOrigin = null;
      }
      if (sender.frameId !== 0 && tabOrigin && tabOrigin !== origin) {
        payload.crossOrigin = true;
        payload.topOrigin = tabOrigin;
      } else if (sender.frameId === 0) {
        payload.crossOrigin = false;
        delete payload.topOrigin;
      }
      break;
    }
    case 'LIST_PASSKEYS_FOR_RP':
      await requireRpIdFor(String(payload.rpId || ''), origin);
      break;
    case 'NEEDS_SITE_ICON':
    case 'SAVE_SITE_ICON':
      // Only a page of the site itself may supply its icon.
      if (!isRpIdValidForHost(String(payload.rpId || ''), host)) {
        throw new Error('A page may only supply its own site icon');
      }
      break;
    case 'VERIFY_RELATED_ORIGIN':
      payload.origin = origin;
      break;
  }
  return { ...message, payload };
}

/**
 * The vault has a PIN and is locked. Responses carry `code: 'VAULT_LOCKED'`
 * so the content script can tell this apart from an empty vault.
 */
class VaultLockedError extends Error {
  readonly code = 'VAULT_LOCKED';

  constructor() {
    super('Secure storage is locked. Please unlock with master password.');
    this.name = 'VaultLockedError';
  }
}

class BackgroundService {
  private isInitialized: boolean;
  private sessionRestored: Promise<unknown>;
  private vaultJobs: Promise<unknown> = Promise.resolve();

  private withVault<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.vaultJobs.then(operation);
    this.vaultJobs = result.catch(() => {});
    return result;
  }
  private syncStatus: SyncStatus;
  private syncStatusLoaded: Promise<void>;

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
    // A restarted worker must build on the persisted status, not the defaults.
    this.syncStatusLoaded = this.loadSyncStatus();
    // MV3: listeners must be attached synchronously at SW wake, before any
    // await — otherwise the first message after a cold start is dropped with
    // "Could not establish connection. Receiving end does not exist."
    secureStorage.onAutoLock = () => void syncService.disconnect();
    // Messages wait for this, so a worker restarted by a request answers it
    // with the unlock the previous worker held.
    this.sessionRestored = secureStorage.restoreSession().catch((error) => {
      console.error('Failed to restore the unlocked session:', error);
    });
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
    if (await secureStorage.isSetup()) {
      throw new VaultLockedError();
    }
    const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
    return result[PASSKEY_STORAGE_KEY] || [];
  }

  private async savePasskeys(passkeys: StoredPasskey[]): Promise<void> {
    if (this.useSecureStorage) {
      await secureStorage.storePasskeys(passkeys as unknown as Record<string, unknown>[]);
      return;
    }
    if (await secureStorage.isSetup()) {
      throw new VaultLockedError();
    }
    await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: passkeys });
  }

  /**
   * Copy the raw passkey/TOTP/sync state into the (just-unlocked) encrypted
   * store. Raw is written by every mutation regardless of lock state, so it is
   * the authoritative freshest copy; the encrypted store can be stale after
   * changes made while locked. Called on setup and unlock to prevent those
   * changes from being lost when a later save reads back the encrypted copy.
   */
  private async reconcileSecureStorageFromRaw(): Promise<void> {
    if (!secureStorage.isStorageUnlocked()) return;

    const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
    const config: SyncConfig = configResult[SYNC_CONFIG_KEY];
    if (config?.seedHash) {
      await secureStorage.storeSyncConfig({
        chainId: config.chainId || '',
        deviceId: config.deviceId || '',
        deviceName: config.deviceName || '',
        seedHash: config.seedHash,
        enabled: config.enabled || false,
      });
    }

    // A missing raw key means the encrypted copy is the only one (a migrated
    // vault), not that the vault is empty, so leave that store alone.
    const passkeysResult = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
    const passkeys: StoredPasskey[] = passkeysResult[PASSKEY_STORAGE_KEY] || [];
    if (passkeysResult[PASSKEY_STORAGE_KEY] !== undefined) {
      await secureStorage.storePasskeys(passkeys as unknown as Record<string, unknown>[]);
    }

    const totpResult = await chrome.storage.local.get('totp_entries');
    const totpEntries: StoredTotpEntry[] = totpResult['totp_entries'] || [];
    if (totpResult['totp_entries'] !== undefined) {
      await secureStorage.storeTotpEntries(totpEntries as unknown as Record<string, unknown>[]);
    }

    if (passkeys.length > 0 || totpEntries.length > 0) {
      logger.info(
        `Reconciled secure storage from raw (${passkeys.length} passkeys, ${totpEntries.length} TOTP)`
      );
    }
  }

  /**
   * One-shot upgrade for vaults created before the encrypted store became
   * authoritative. Those builds wrote every mutation to raw storage and only
   * mirrored it into the encrypted copy while unlocked, so on upgrade the raw
   * keys can hold credentials the encrypted store never saw. Merge those in
   * (raw wins on conflict — it was the freshest copy) and then delete the
   * cleartext keys, which is what makes the PIN protect anything at rest.
   *
   * Deliberately not a plain reconcileSecureStorageFromRaw(): that overwrites
   * the encrypted store with raw wholesale and would wipe an already-migrated
   * vault, whose raw copy is legitimately absent. No-op once the keys are gone.
   */
  private async migrateLegacyRawStorage(): Promise<void> {
    if (!secureStorage.isStorageUnlocked()) return;

    const raw = await chrome.storage.local.get([
      PASSKEY_STORAGE_KEY,
      TOTP_STORAGE_KEY,
      SYNC_CONFIG_KEY,
    ]);
    const rawConfig = raw[SYNC_CONFIG_KEY] as SyncConfig | undefined;
    const hasLegacyState =
      raw[PASSKEY_STORAGE_KEY] !== undefined ||
      raw[TOTP_STORAGE_KEY] !== undefined ||
      Boolean(rawConfig?.seedHash);
    if (!hasLegacyState) return;

    const rawPasskeys = (raw[PASSKEY_STORAGE_KEY] || []) as StoredPasskey[];
    const rawTotp = (raw[TOTP_STORAGE_KEY] || []) as StoredTotpEntry[];

    if (rawPasskeys.length > 0) {
      const stored = (await secureStorage.getPasskeys()) as unknown as StoredPasskey[];
      const merged = new Map(stored.map((entry) => [entry.credentialId, entry]));
      for (const passkey of rawPasskeys) merged.set(passkey.credentialId, passkey);
      await secureStorage.storePasskeys([...merged.values()] as unknown as Record<
        string,
        unknown
      >[]);
    }

    if (rawTotp.length > 0) {
      const stored = (await secureStorage.getTotpEntries()) as unknown as StoredTotpEntry[];
      const merged = new Map(stored.map((entry) => [entry.id, entry]));
      for (const entry of rawTotp) merged.set(entry.id, entry);
      await secureStorage.storeTotpEntries([...merged.values()] as unknown as Record<
        string,
        unknown
      >[]);
    }

    if (rawConfig?.seedHash) {
      await secureStorage.storeSyncConfig({
        chainId: rawConfig.chainId || '',
        deviceId: rawConfig.deviceId || '',
        deviceName: rawConfig.deviceName || '',
        seedHash: rawConfig.seedHash,
        enabled: rawConfig.enabled || false,
      });
      const publicConfig = { ...rawConfig };
      delete publicConfig.seedHash;
      await chrome.storage.local.set({ [SYNC_CONFIG_KEY]: publicConfig });
    }

    await chrome.storage.local.remove([PASSKEY_STORAGE_KEY, TOTP_STORAGE_KEY]);
    logger.info(
      `Migrated legacy cleartext vault into the encrypted store ` +
        `(${rawPasskeys.length} passkeys, ${rawTotp.length} TOTP); cleartext copies removed`
    );
  }

  /**
   * Give every passkey from before per-credential backup flags the flags it
   * was already being signed with, so a site that stored them sees no change.
   * Needs the vault readable, so it runs at start-up and again on unlock. A
   * no-op once every record carries flags.
   */
  private stampLegacyBackupFlags(): Promise<void> {
    return this.withVault(async () => {
      if ((await secureStorage.isSetup()) && !secureStorage.isStorageUnlocked()) return;
      const snapshot = await ensureBackupFlagsSnapshot();
      const { records, stamped } = stampLegacyBackupFlags(await this.loadPasskeys(), snapshot);
      if (stamped === 0) return;
      await this.savePasskeys(records);
      logger.info(`Recorded pre-upgrade backup flags on ${stamped} passkeys`);
      await this.noteVaultChange();
    });
  }

  /** Flags for a passkey that has none of its own yet: what it was signed with before. */
  private async fallbackBackupFlags(): Promise<BackupFlags> {
    return (await loadBackupFlagsSnapshot()) ?? PRE_UPGRADE_BACKUP_FLAGS;
  }

  /** Whether this device is part of a sync chain, so a new passkey is already backed up. */
  private async isSyncConfigured(): Promise<boolean> {
    const config = (await chrome.storage.local.get(SYNC_CONFIG_KEY))[SYNC_CONFIG_KEY] as
      | SyncConfig
      | undefined;
    return Boolean(config?.enabled && config.chainId);
  }

  /**
   * Older builds also kept the sync seed in the cleartext `sync_devices` chain
   * record, and PIN setup never stripped it. Strip it once the encrypted sync
   * config is known to hold that seed, which needs the key, so stripping never
   * drops the only copy. When the record is for the device's current chain
   * and the encrypted config lacks the seed, the seed is moved there first.
   * A record for any other chain is left alone. Run inside a vault job, after
   * migrateLegacyRawStorage(); a no-op while locked or without a PIN.
   */
  private async stripCleartextChainSeed(): Promise<void> {
    if (!secureStorage.isStorageUnlocked()) return;
    const chain = (await chrome.storage.local.get(SYNC_DEVICES_KEY))[SYNC_DEVICES_KEY] as
      | SyncChain
      | null
      | undefined;
    if (!chain?.seedHash) return;

    const stored = await secureStorage.getSyncConfig();
    if (stored?.seedHash !== chain.seedHash) {
      const config = (await chrome.storage.local.get(SYNC_CONFIG_KEY))[SYNC_CONFIG_KEY] as
        | SyncConfig
        | undefined;
      const currentChain =
        !!config?.chainId &&
        config.chainId === chain.id &&
        !config.seedHash &&
        chain.seedHash.startsWith(chain.id);
      if (!currentChain) return;
      await secureStorage.storeSyncConfig({
        chainId: config.chainId,
        deviceId: config.deviceId || '',
        deviceName: config.deviceName || '',
        seedHash: chain.seedHash,
        enabled: config.enabled || false,
      });
    }

    const publicChain = { ...chain };
    delete publicChain.seedHash;
    await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: publicChain });
    logger.info('Removed the cleartext sync seed from the chain record');
  }

  private async initialize(): Promise<void> {
    try {
      const saved = (await chrome.storage.local.get(SYNC_CONFIG_KEY))[SYNC_CONFIG_KEY];
      if (saved) {
        await chrome.storage.local.set({ [SYNC_CONFIG_KEY]: cleanSyncConfig(saved) });
      }
      await logger.init();
      logger.info('Background service initializing...');
      await this.sessionRestored;
      await this.withVault(() => this.repairStoredCredentialIds());
      // Before anything else reads the Advanced toggles: from this build on
      // they only describe new passkeys, so record what they meant until now.
      await ensureBackupFlagsSnapshot();
      await this.stampLegacyBackupFlags();
      await this.initializeSyncService();
      this.isInitialized = true;
      logger.info('Background service initialized successfully');
    } catch (error) {
      logger.error('Background service initialization failed:', error);
    }
  }

  /**
   * Resolve the sync seed. Once a PIN is set the seed lives only in the
   * encrypted store — raw `sync_config` keeps every other field so the sync UI
   * still works while locked, but the seed derives the chain keys and must not
   * sit in cleartext. A PIN'd vault can therefore only start sync while
   * unlocked, which is why the unlock handler re-runs initializeSyncService().
   */
  private async resolveSyncSeedHash(config: SyncConfig | undefined): Promise<string | null> {
    if (config?.seedHash) return config.seedHash;
    if (!secureStorage.isStorageUnlocked()) return null;
    const stored = (await secureStorage.getSyncConfig()) as { seedHash?: string } | null;
    return stored?.seedHash || null;
  }

  private async initializeSyncService(): Promise<void> {
    try {
      const configResult = await chrome.storage.local.get(SYNC_CONFIG_KEY);
      const config: SyncConfig = configResult[SYNC_CONFIG_KEY];
      const seedHash = await this.resolveSyncSeedHash(config);

      if (config?.enabled && config.chainId && config.deviceId && seedHash) {
        logger.info('Starting sync service...');
        await syncService.initialize(
          config.chainId,
          config.deviceId,
          seedHash,
          config.deviceName || undefined,
          this.syncVaultAdapter()
        );
        await this.updateSyncStatus({
          connectionStatus: syncService.getStatus().connected ? 'connected' : 'disconnected',
        });
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

  /**
   * Re-key passkeys imported with a Bitwarden-encoded credential ID (issue
   * #17). Runs at startup, on unlock and after every sync merge, because a
   * peer on an older build can still send them. Callers hold the vault lock.
   */
  private async repairStoredCredentialIds(): Promise<void> {
    if (!secureStorage.isStorageUnlocked() && (await secureStorage.isSetup())) return;
    const repair = repairCredentialIds(await this.loadPasskeys());
    if (repair.deletions.length === 0) return;
    await this.recordDeletions(repair.deletions);
    await this.savePasskeys(repair.passkeys);
    logger.info(`Re-keyed ${repair.deletions.length} passkeys with Bitwarden credential IDs`);
    await this.noteVaultChange();
  }

  private async loadDeletions(): Promise<SyncDeletion[]> {
    const data = await chrome.storage.local.get(SYNC_DELETIONS_KEY);
    return data[SYNC_DELETIONS_KEY] || [];
  }

  private async recordDeletions(entries: SyncDeletion[]): Promise<void> {
    await chrome.storage.local.set({
      [SYNC_DELETIONS_KEY]: mergeDeletions(await this.loadDeletions(), entries),
    });
  }

  private async readVaultSnapshot() {
    return {
      passkeys: (await this.loadPasskeys()) as SyncPasskey[],
      totpEntries: (await loadTotpEntries()) as SyncTotpEntry[],
      deletions: await this.loadDeletions(),
    };
  }

  private syncVaultAdapter(): SyncVaultAdapter {
    return {
      getSnapshot: () => this.withVault(() => this.readVaultSnapshot()),
      onPublished: (snapshot) =>
        this.withVault(async () => {
          const current = await this.readVaultSnapshot();
          if (JSON.stringify(current) !== JSON.stringify(snapshot)) {
            return;
          }
          // A relay accepted the snapshot, also when the socket reconnected
          // on its own after triggerSync had reported it disconnected.
          await this.updateSyncStatus({
            lastSyncSuccess: Date.now(),
            pendingChanges: 0,
            syncedPasskeyCount: current.passkeys.length,
            connectionStatus: 'connected',
            lastError: null,
          });
        }),
      mergeRemote: (remotePasskeys, remoteTotpEntries, sourceDeviceId, remoteDeletions = []) =>
        this.withVault(async () => {
          void sourceDeviceId;
          const deletions = mergeDeletions(await this.loadDeletions(), remoteDeletions);
          // Persist deletion records first, so interrupted merges cannot resurrect entries.
          await chrome.storage.local.set({ [SYNC_DELETIONS_KEY]: deletions });
          await this.savePasskeys(
            mergeRecords(
              await this.loadPasskeys(),
              remotePasskeys as StoredPasskey[],
              deletions,
              'passkey'
            )
          );
          await saveTotpEntries(
            mergeRecords(await loadTotpEntries(), remoteTotpEntries, deletions, 'totp')
          );
          await this.repairStoredCredentialIds();
        }),
    };
  }

  private setupMessageHandlers(): void {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sendResponse, sender);
      return true;
    });
  }

  private async handleMessage(
    message: ExtensionMessage,
    sendResponse: (response?: unknown) => void,
    sender: chrome.runtime.MessageSender
  ): Promise<void> {
    try {
      const response = await this.routeMessage(message, sender);
      sendResponse(response);
    } catch (error: unknown) {
      const message_str = error instanceof Error ? error.message : String(error);
      console.error('Message handling error:', error);
      const code = error instanceof VaultLockedError ? error.code : undefined;
      sendResponse({ success: false, error: message_str, ...(code && { code }) });
    }
  }

  private async routeMessage(
    received: ExtensionMessage,
    sender: chrome.runtime.MessageSender
  ): Promise<unknown> {
    await this.sessionRestored;
    const message = isExtensionPage(sender) ? received : await bindToWebPage(received, sender);
    const { type } = message;

    const lockedTypes = new Set([
      'CREATE_PASSKEY',
      'GET_PASSKEY',
      'RETRIEVE_PASSKEY',
      'LIST_PASSKEYS',
      'GET_PASSKEYS',
      'LIST_PASSKEYS_FOR_RP',
      'DELETE_PASSKEY',
      'SET_PASSKEY_BACKUP',
      'ENCRYPT_BACKUP',
      'LIST_TOTP_ENTRIES',
      'ADD_TOTP_ENTRY',
      'DELETE_TOTP_ENTRY',
      'GENERATE_TOTP_CODE',
      'NEXT_HOTP_CODE',
      'IMPORT_VAULT',
      'EXPORT_VAULT',
      'CLEAR_VAULT',
      'FACTORY_RESET',
      'CHANGE_MASTER_PASSWORD',
      'REMOVE_MASTER_PASSWORD',
    ]);
    const upgradeBlockedTypes = new Set([
      'CREATE_PASSKEY',
      'DELETE_PASSKEY',
      'SET_PASSKEY_BACKUP',
      'ADD_TOTP_ENTRY',
      'DELETE_TOTP_ENTRY',
      'IMPORT_VAULT',
      'CLEAR_VAULT',
      'FACTORY_RESET',
      'CHANGE_MASTER_PASSWORD',
      'REMOVE_MASTER_PASSWORD',
    ]);
    if (
      lockedTypes.has(type) &&
      (await secureStorage.isSetup()) &&
      !secureStorage.isStorageUnlocked()
    ) {
      throw new VaultLockedError();
    }
    if (upgradeBlockedTypes.has(type) && (await this.isUpgradeBackupRequired())) {
      throw new Error('Export an encrypted backup before changing this upgraded vault.');
    }

    // Serialize read/modify/write operations. Lookups and relay waits stay independent.
    const mutations = new Set([
      'CREATE_PASSKEY',
      'GET_PASSKEY',
      'DELETE_PASSKEY',
      'SET_PASSKEY_BACKUP',
      'ADD_TOTP_ENTRY',
      'DELETE_TOTP_ENTRY',
      'GENERATE_TOTP_CODE',
      'NEXT_HOTP_CODE',
      'IMPORT_VAULT',
      'CLEAR_VAULT',
      'FACTORY_RESET',
      'SETUP_MASTER_PASSWORD',
      'LOCK_SECURE_STORAGE',
      'RECONCILE_STORAGE',
      'CHANGE_MASTER_PASSWORD',
      'REMOVE_MASTER_PASSWORD',
    ]);
    if (mutations.has(type)) {
      return this.withVault(() => this.dispatchMessage(message));
    }
    return this.dispatchMessage(message);
  }

  private async dispatchMessage(message: ExtensionMessage): Promise<unknown> {
    const { type, payload } = message;
    switch (type) {
      case 'CREATE_PASSKEY':
        return this.handleCreatePasskey(payload || {});
      case 'GET_PASSKEY':
        return this.handleGetPasskey(payload || {});
      case 'RETRIEVE_PASSKEY':
        return this.handleRetrievePasskey(payload || {});
      case 'LIST_PASSKEYS':
      case 'GET_PASSKEYS':
        return this.handleListPasskeys();
      case 'LIST_PASSKEYS_FOR_RP':
        return this.handleListPasskeysForRp(payload || {});
      case 'VERIFY_RELATED_ORIGIN':
        return this.handleVerifyRelatedOrigin(payload || {});
      case 'NEEDS_SITE_ICON':
        return this.handleNeedsSiteIcon(payload || {});
      case 'SAVE_SITE_ICON':
        return this.handleSaveSiteIcon(payload || {});
      case 'DELETE_PASSKEY':
        return this.handleDeletePasskey(payload || {});
      case 'SET_PASSKEY_BACKUP':
        return this.handleSetPasskeyBackup(payload || {});
      case 'ENCRYPT_BACKUP':
        return this.handleEncryptBackup(payload as { data: string; password: string });
      case 'LIST_TOTP_ENTRIES':
        return this.handleListTotpEntries();
      case 'ADD_TOTP_ENTRY':
        return this.handleAddTotpEntry(payload || {});
      case 'DELETE_TOTP_ENTRY':
        return this.handleDeleteTotpEntry(payload || {});
      case 'GENERATE_TOTP_CODE':
        return this.handleGenerateTotpCode(payload || {});
      case 'NEXT_HOTP_CODE':
        return this.handleNextHotpCode(payload || {});
      case 'IMPORT_VAULT':
        return this.handleImportVault(payload || {});
      case 'EXPORT_VAULT':
        return this.handleExportVault();
      case 'CLEAR_VAULT':
        return this.handleClearVault();
      case 'FACTORY_RESET':
        return this.handleFactoryReset();
      case 'GET_UPGRADE_BACKUP_STATUS':
        return this.handleUpgradeBackupStatus();
      case 'COMPLETE_UPGRADE_BACKUP':
        return this.handleCompleteUpgradeBackup();
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
      case 'RECONCILE_STORAGE':
        return this.handleReconcileStorage();
      case 'CHANGE_MASTER_PASSWORD':
        return this.handleChangeMasterPassword(
          payload as { currentPassword: string; newPassword: string }
        );
      case 'REMOVE_MASTER_PASSWORD':
        return this.handleRemoveMasterPassword(payload as { currentPassword: string });
      case 'SET_DEBUG_LOGGING':
        return this.handleSetDebugLogging(payload as { enabled: boolean });
      case 'GET_DEBUG_LOGGING':
        return this.handleGetDebugLogging();
      case 'GET_WEBAUTHN_FLAGS':
        return this.handleGetWebAuthnFlags();
      case 'SET_WEBAUTHN_FLAGS':
        return this.handleSetWebAuthnFlags(payload as { flags: unknown });
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
        void this.requireUpgradeBackupIfNeeded(details.previousVersion);
      }
    });
    chrome.runtime.onStartup.addListener(() => {
      logger.info('Extension startup');
    });
    chrome.runtime.onSuspend.addListener(() => {
      logger.info('Extension suspending');
    });
    chrome.alarms?.onAlarm.addListener((alarm) => {
      if (alarm.name !== AUTO_LOCK_ALARM) return;
      void this.sessionRestored.then(() => secureStorage.lockIfIdle());
    });
  }

  private async requireUpgradeBackupIfNeeded(previousVersion?: string): Promise<void> {
    if (!previousVersion || !this.isVersionBefore(previousVersion, '0.9.5')) return;
    if (!(await secureStorage.isSetup())) return;
    const legacy = await chrome.storage.local.get([PASSKEY_STORAGE_KEY, TOTP_STORAGE_KEY]);
    if ((legacy[PASSKEY_STORAGE_KEY] || []).length || (legacy[TOTP_STORAGE_KEY] || []).length) {
      await chrome.storage.local.set({ [UPGRADE_BACKUP_REQUIRED_KEY]: true });
    }
  }

  private isVersionBefore(version: string, target: string): boolean {
    const parse = (value: string) => value.split('.').map((part) => Number.parseInt(part, 10) || 0);
    const current = parse(version);
    const expected = parse(target);
    for (let index = 0; index < Math.max(current.length, expected.length); index += 1) {
      const delta = (current[index] || 0) - (expected[index] || 0);
      if (delta !== 0) return delta < 0;
    }
    return false;
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

      // The content script hands these to the browser; refuse here too rather
      // than mint a key type the relying party did not offer.
      if (!acceptsEs256(options?.pubKeyCredParams)) {
        return {
          success: false,
          error: 'None of the requested algorithms is supported',
          name: 'NotSupportedError',
        };
      }

      // Refuse only a credential the RP says this account already has. A site
      // can hold several accounts, and an account several passkeys.
      const excluded = new Set(
        ((options?.excludeCredentials as Array<{ id?: unknown }> | undefined) || [])
          .map((credential) =>
            typeof credential?.id === 'string' ? toBase64Url(credential.id) : ''
          )
          .filter(Boolean)
      );
      const existingPasskeys = await this.loadPasskeys();
      const existingPasskey = existingPasskeys.find(
        (p) => p.rpId === rpId && excluded.has(toBase64Url(p.credentialId || p.id))
      );

      if (existingPasskey) {
        logger.debug('Passkey already registered with', rpId);
        return {
          success: false,
          error: 'This passkey is already registered with this site',
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

      // SPKI DER for AuthenticatorAttestationResponse.getPublicKey()
      const publicKeySpki = await crypto.subtle.exportKey('spki', keyPair.publicKey);

      const prfKeyBytes = crypto.getRandomValues(new Uint8Array(32));
      const prfKeyBase64 = arrayBufferToBase64URL(prfKeyBytes.buffer);

      const extensions = options?.extensions as Record<string, unknown> | undefined;
      const prfEvalInput = selectPrfEval(usablePrfInput(extensions, 'create'), credentialIdBase64);
      const prfResults = prfEvalInput
        ? await computePrfResults(prfKeyBytes.buffer, prfEvalInput)
        : null;
      // SECURITY: the PRF/hmac-secret output is a client-only secret. It is
      // returned to the page via clientExtensionResults (below), but must NOT
      // be embedded in authenticatorData, which is forwarded to the RP server.
      const clientExtensionResults = buildClientExtensionResults(extensions, 'create', prfResults);

      const clientDataJSONBytes = new TextEncoder().encode(
        serializeClientData({
          type: 'webauthn.create',
          challenge: challenge as string,
          origin: origin as string,
          ...callerFrame(payload),
        })
      );

      const flagSettings = await loadWebAuthnFlags();
      // Fixed for the life of the credential: the site may store BE and
      // reject any later sign-in that disagrees.
      const backupFlags = normalizeBackupFlags(
        flagSettings.backupEligible,
        flagSettings.backupState || (await this.isSyncConfigured())
      );
      const authenticatorData = await createAuthenticatorData(
        rpId,
        credentialId,
        publicKeyRaw,
        true,
        0,
        null,
        toAuthenticatorDataOptions(flagSettings, backupFlags)
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
        ...withBackupFlags({}, backupFlags, 'created'),
      });

      await this.savePasskeys(passkeys);
      logger.debug('Created and stored passkey', credentialIdBase64);

      this.logWebAuthn('CREATE', 'info', `Created passkey for ${rpId}`, {
        rpId,
        credentialId: credentialIdBase64,
        user: (user?.name as string) || '',
      });
      this.logSync('PASSKEY_CREATED', { id: credentialIdBase64, rpId });
      await this.noteVaultChange();

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
            authenticatorData: arrayBufferToBase64(authenticatorData),
            publicKey: arrayBufferToBase64(publicKeySpki),
            publicKeyAlgorithm: COSE_ALG_ES256,
            transports: transportsFor(flagSettings.attachment),
          },
          authenticatorAttachment: flagSettings.attachment,
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

      const clientDataJSONBytes = new TextEncoder().encode(
        serializeClientData({
          type: 'webauthn.get',
          challenge: challenge as string,
          origin: origin as string,
          ...callerFrame(payload),
        })
      );

      const extensions = options?.extensions as Record<string, unknown> | undefined;
      const prfEvalInput = selectPrfEval(usablePrfInput(extensions, 'get'), passkey.id);
      const prfKeyBuffer = await getOrCreatePrfKey(passkey);
      const prfResults = prfEvalInput ? await computePrfResults(prfKeyBuffer, prfEvalInput) : null;
      // SECURITY: keep the PRF secret out of the RP-bound authenticatorData;
      // it is returned only via clientExtensionResults.
      const clientExtensionResults = buildClientExtensionResults(extensions, 'get', prfResults);

      const flagSettings = await loadWebAuthnFlags();
      passkey.counter = (passkey.counter || 0) + 1;
      // A synced credential lives on several devices, each with its own
      // counter, which looks like a cloned authenticator to an RP doing clone
      // detection. Sending zero is what platform passkey providers do; the
      // stored counter keeps moving either way so the UI still shows use.
      const reportedCounter = flagSettings.signCounter === 'zero' ? 0 : passkey.counter;
      const backupFlags = backupFlagsOf(passkey, await this.fallbackBackupFlags());
      const authenticatorData = await createAuthenticatorData(
        rpId,
        null,
        null,
        false,
        reportedCounter,
        null,
        toAuthenticatorDataOptions(flagSettings, backupFlags)
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
        backupEligible: backupFlags.backupEligible,
        backupState: backupFlags.backupState,
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
          authenticatorAttachment: flagSettings.attachment,
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
      const code = error instanceof VaultLockedError ? error.code : undefined;
      return { success: false, error: message, ...(code && { code }) };
    }
  }

  // WebAuthn Related Origin Requests: the content script asks whether an origin
  // that is not same-site with the requested RP ID is nonetheless authorized by
  // the RP's /.well-known/webauthn file. Done here (not in the content script)
  // so the fetch has host permissions and isn't blocked by the page's CSP.
  private async handleVerifyRelatedOrigin(payload: MessagePayload): Promise<unknown> {
    const rpId = typeof payload.rpId === 'string' ? payload.rpId : '';
    const origin = typeof payload.origin === 'string' ? payload.origin : '';
    const authorized = await verifyRelatedOrigin(rpId, origin);
    return { authorized };
  }

  private async handleNeedsSiteIcon(payload: MessagePayload): Promise<unknown> {
    const rpId = typeof payload.rpId === 'string' ? payload.rpId : '';
    return { needed: await needsSiteIcon(rpId) };
  }

  // Decoding happens here rather than in the content script: the worker has no
  // page DOM to be tricked by, and OffscreenCanvas re-encoding is what makes
  // site-supplied bytes safe to keep.
  private async handleSaveSiteIcon(payload: MessagePayload): Promise<unknown> {
    const rpId = typeof payload.rpId === 'string' ? payload.rpId : '';
    const saved = await saveSiteIcon(rpId, payload.data, payload.mimeType);
    return { success: saved };
  }

  /**
   * The user's answer to "is this a synced passkey?" for one credential. Sets
   * both flags together, the way syncing managers report them, and marks the
   * choice as the user's so later imports leave it alone.
   */
  private async handleSetPasskeyBackup(payload: MessagePayload): Promise<unknown> {
    try {
      const credentialId = payload.credentialId as string | undefined;
      if (!credentialId || typeof payload.synced !== 'boolean') {
        return { success: false, error: 'credentialId and synced are required' };
      }
      const synced = payload.synced;
      const passkeys = await this.loadPasskeys();
      const index = passkeys.findIndex(
        (p) => p.id === credentialId || p.credentialId === credentialId
      );
      if (index < 0) return { success: false, error: 'Passkey not found' };

      const current = passkeys[index];
      const flags = normalizeBackupFlags(synced, synced);
      passkeys[index] = {
        ...withBackupFlags(current, flags, 'manual'),
        updatedAt: Math.max(Date.now(), (current.updatedAt ?? current.createdAt) + 1),
      };
      await this.savePasskeys(passkeys);
      this.logWebAuthn(
        'BACKUP',
        'info',
        `Marked passkey for ${current.rpId} as ${synced ? 'synced' : 'device-bound'}`,
        { rpId: current.rpId, credentialId: current.id }
      );
      await this.noteVaultChange();
      const { backupEligible, backupState, backupSource, updatedAt } = passkeys[index];
      return { success: true, passkey: { backupEligible, backupState, backupSource, updatedAt } };
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
        await this.recordDeletions(
          passkeys
            .filter((entry) => !filtered.includes(entry))
            .map(({ id }) => ({ kind: 'passkey', id, deletedAt: Date.now() }))
        );
        await this.savePasskeys(filtered);
        this.logSync('PASSKEY_DELETED', { credentialId });
        await this.noteVaultChange();
        return { success: true, message: 'Passkey deleted' };
      }
      return { success: false, error: 'Passkey not found' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  // ==================== TOTP OPERATIONS ====================

  private async handleListTotpEntries(): Promise<unknown> {
    try {
      const entries = await loadTotpEntries();
      return { success: true, entries, count: entries.length };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error listing TOTP entries:', error);
      return { success: false, error: message };
    }
  }

  private async handleImportVault(payload: MessagePayload): Promise<unknown> {
    const rawPasskeys = Array.isArray(payload.passkeys)
      ? (payload.passkeys as StoredPasskey[])
      : [];
    const incomingTotp = Array.isArray(payload.totpEntries)
      ? (payload.totpEntries as StoredTotpEntry[])
      : [];
    if (rawPasskeys.some((entry) => !entry?.id || !entry.rpId || !entry.privateKey)) {
      return { success: false, error: 'Backup contains an invalid passkey' };
    }
    // A Fenko backup taken before issue #17 was fixed still holds Bitwarden IDs.
    const repair = repairCredentialIds(rawPasskeys);
    const incomingPasskeys = repair.passkeys;
    if (repair.deletions.length > 0) await this.recordDeletions(repair.deletions);
    const deletions = await this.loadDeletions();
    for (const item of incomingPasskeys) {
      Object.assign(item, restoreRecord(item, deletions, 'passkey'));
    }
    for (const item of incomingTotp) {
      if (item?.id) {
        Object.assign(item, restoreRecord(item, deletions, 'totp'));
      }
    }
    const backupRepairs = Array.isArray(payload.backupRepairs)
      ? (payload.backupRepairs as BackupRepair[])
      : [];
    const { records: passkeys, repaired } = applyBackupRepairs(
      await this.loadPasskeys(),
      backupRepairs
    );
    const knownPasskeys = new Set(passkeys.map((entry) => entry.id));
    const newPasskeys = incomingPasskeys.filter((entry) => !knownPasskeys.has(entry.id));
    if (newPasskeys.length > 0 || repaired > 0) {
      await this.savePasskeys([...passkeys, ...newPasskeys]);
    }

    const totpEntries = await loadTotpEntries();
    const knownTotp = new Set(totpEntries.map((entry) => entry.id));
    const newTotp = incomingTotp.filter((entry) => entry?.id && !knownTotp.has(entry.id));
    if (newTotp.length > 0) await saveTotpEntries([...totpEntries, ...newTotp]);

    if (newPasskeys.length > 0 || newTotp.length > 0 || repaired > 0) {
      await this.noteVaultChange();
    }
    return {
      success: true,
      passkeys: newPasskeys.length,
      totpEntries: newTotp.length,
      backupRepaired: repaired,
    };
  }

  private async handleExportVault(): Promise<unknown> {
    return {
      success: true,
      exportedAt: new Date().toISOString(),
      deletions: await this.loadDeletions(),
      passkeys: await this.loadPasskeys(),
      totpEntries: await loadTotpEntries(),
    };
  }

  private async handleClearVault(): Promise<unknown> {
    const deletedAt = Date.now();
    await this.recordDeletions([
      ...(await this.loadPasskeys()).map(({ id }) => ({ kind: 'passkey' as const, id, deletedAt })),
      ...(await loadTotpEntries()).map(({ id }) => ({ kind: 'totp' as const, id, deletedAt })),
    ]);
    await this.savePasskeys([]);
    await saveTotpEntries([]);
    await clearSiteIcons();
    await this.noteVaultChange();
    return { success: true };
  }

  private async handleFactoryReset(): Promise<unknown> {
    await syncService.disconnect();
    secureStorage.lock();
    await chrome.storage.local.clear();
    return { success: true };
  }

  private async handleUpgradeBackupStatus(): Promise<unknown> {
    return { success: true, required: await this.isUpgradeBackupRequired() };
  }

  /**
   * The post-upgrade gate only protects entries that exist. Once the vault
   * holds nothing to back up (emptied by a sync merge, say) the gate is moot,
   * and keeping it would leave the vault read-only for good, because there is
   * no backup to export that would clear it. While the vault is locked its
   * contents are unknown, so the gate stays.
   */
  private async isUpgradeBackupRequired(): Promise<boolean> {
    const result = await chrome.storage.local.get(UPGRADE_BACKUP_REQUIRED_KEY);
    if (result[UPGRADE_BACKUP_REQUIRED_KEY] !== true) return false;
    try {
      const [passkeys, totpEntries] = await Promise.all([this.loadPasskeys(), loadTotpEntries()]);
      if (passkeys.length > 0 || totpEntries.length > 0) return true;
    } catch {
      return true;
    }
    await chrome.storage.local.remove(UPGRADE_BACKUP_REQUIRED_KEY);
    return false;
  }

  private async handleCompleteUpgradeBackup(): Promise<unknown> {
    await chrome.storage.local.remove(UPGRADE_BACKUP_REQUIRED_KEY);
    return { success: true };
  }

  private async handleAddTotpEntry(payload: MessagePayload): Promise<unknown> {
    try {
      const otpauthUri = payload.otpauthUri as string | undefined;
      const entryInput = payload.entry as Partial<StoredTotpEntry> | undefined;

      let entry: StoredTotpEntry;

      if (otpauthUri) {
        const parsed = parseOtpauth(otpauthUri);
        const secretB64 = arrayBufferToBase64(parsed.secret.buffer as ArrayBuffer);
        entry = {
          id: generateTotpId(),
          type: parsed.type,
          issuer: parsed.issuer,
          account: parsed.account,
          secretB64,
          algorithm: parsed.algorithm,
          digits: parsed.digits,
          period: parsed.period,
          counter: parsed.counter,
          createdAt: Date.now(),
        };
      } else if (entryInput && entryInput.issuer && entryInput.secretB64) {
        entry = {
          id: entryInput.id || generateTotpId(),
          type: entryInput.type || 'totp',
          issuer: entryInput.issuer,
          account: entryInput.account || '',
          secretB64: entryInput.secretB64,
          algorithm: entryInput.algorithm || 'SHA1',
          digits: entryInput.digits || 6,
          period: entryInput.period || 30,
          counter: entryInput.counter || 0,
          createdAt: entryInput.createdAt || Date.now(),
        };
      } else {
        return { success: false, error: 'Provide otpauthUri or a complete entry' };
      }

      await addTotpEntryStore(entry);
      this.logSync('TOTP_CREATED', { id: entry.id, issuer: entry.issuer });
      await this.noteVaultChange();
      return { success: true, entry };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error adding TOTP entry:', error);
      return { success: false, error: message };
    }
  }

  private async handleDeleteTotpEntry(payload: MessagePayload): Promise<unknown> {
    try {
      const id = payload.id as string;
      if (!id) return { success: false, error: 'Missing id' };
      if (!(await loadTotpEntries()).some((entry) => entry.id === id)) {
        return { success: false, error: 'Entry not found' };
      }
      await this.recordDeletions([{ kind: 'totp', id, deletedAt: Date.now() }]);
      const deleted = await deleteTotpEntryStore(id);
      if (!deleted) return { success: false, error: 'Entry not found' };
      this.logSync('TOTP_DELETED', { id });
      await this.noteVaultChange();
      return { success: true };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error deleting TOTP entry:', error);
      return { success: false, error: message };
    }
  }

  private async handleGenerateTotpCode(payload: MessagePayload): Promise<unknown> {
    try {
      const id = payload.id as string;
      const counter = payload.counter as number | undefined;
      const timestamp = (payload.timestamp as number | undefined) ?? Date.now();
      if (!id) return { success: false, error: 'Missing id' };

      const entries = await loadTotpEntries();
      const entry = entries.find((e) => e.id === id);
      if (!entry) return { success: false, error: 'Entry not found' };

      const secret = entryToSecretBytes(entry);
      const code =
        entry.type === 'hotp'
          ? generateHotpCode({
              secret,
              algorithm: entry.algorithm,
              digits: entry.digits,
              counter: counter ?? entry.counter,
            })
          : generateTotpCode({
              secret,
              algorithm: entry.algorithm,
              digits: entry.digits,
              period: entry.period,
              timestamp,
            });

      return {
        success: true,
        code,
        algorithm: entry.algorithm,
        digits: entry.digits,
        type: entry.type,
        timestamp,
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error generating TOTP code:', error);
      return { success: false, error: message };
    }
  }

  // An HOTP code is single-use, so issuing one advances the stored counter.
  // GENERATE_TOTP_CODE stays a pure read and never consumes a counter value.
  private async handleNextHotpCode(payload: MessagePayload): Promise<unknown> {
    try {
      const id = payload.id as string;
      if (!id) return { success: false, error: 'Missing id' };
      const issued = await issueHotpCode(id);
      if (!issued) return { success: false, error: 'Entry not found' };
      this.logSync('HOTP_COUNTER_ADVANCED', { id, counter: issued.entry.counter });
      await this.noteVaultChange();
      return {
        success: true,
        code: issued.code,
        counter: issued.counter,
        entry: issued.entry,
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error issuing HOTP code:', error);
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
        devices: [newDevice],
      };

      await this.saveSyncChain(
        { enabled: true, chainId, deviceId, deviceName, seedHash: seedHashHex },
        chain
      );

      await syncService.initialize(
        chainId,
        deviceId,
        seedHashHex,
        deviceName,
        this.syncVaultAdapter()
      );
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
        devices: [newDevice],
      };

      const config: SyncConfig = {
        enabled: true,
        chainId,
        deviceId,
        deviceName,
        seedHash: seedHashHex,
      };

      await this.saveSyncChain(config, chain);

      await syncService.initialize(
        chainId,
        deviceId,
        seedHashHex,
        deviceName,
        this.syncVaultAdapter()
      );
      await syncService.requestSync();
      this.logSync('SYNC_CHAIN_JOINED', { chainId, deviceId });

      return { success: true, deviceId };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to join sync chain:', error);
      return { success: false, error: message };
    }
  }

  /**
   * Save a chain this device just created or joined. With a PIN set, the seed
   * goes only into the encrypted store, which needs the vault unlocked, in the
   * same storage write as the cleartext config that keeps every other field.
   * Serialized with PIN setup and removal, which read both sync configs.
   */
  private saveSyncChain(config: SyncConfig, chain: SyncChain): Promise<void> {
    return this.withVault(async () => {
      if (!(await secureStorage.isSetup())) {
        await chrome.storage.local.set({ [SYNC_CONFIG_KEY]: config, [SYNC_DEVICES_KEY]: chain });
        return;
      }
      const publicConfig = { ...config };
      delete publicConfig.seedHash;
      await secureStorage.storeSyncConfig(
        {
          chainId: config.chainId,
          deviceId: config.deviceId,
          deviceName: config.deviceName,
          seedHash: config.seedHash,
          enabled: config.enabled,
        },
        { [SYNC_CONFIG_KEY]: publicConfig, [SYNC_DEVICES_KEY]: chain }
      );
    });
  }

  private async leaveSyncChain(): Promise<unknown> {
    try {
      await syncService.disconnect();

      // Serialized with PIN setup and removal, which read both sync configs.
      await this.withVault(async () => {
        await chrome.storage.local.set({
          [SYNC_CONFIG_KEY]: {
            enabled: false,
            chainId: null,
            deviceId: null,
            deviceName: null,
            seedHash: null,
          },
          [SYNC_DEVICES_KEY]: null,
        });
        // Removing the PIN would otherwise bring the left chain back from the
        // encrypted copy.
        await secureStorage.deleteSyncConfig();
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

      // The in-memory status is loaded from storage at startup and is the only
      // writer since; re-reading storage here could undo a concurrent update.
      await this.syncStatusLoaded;
      this.syncStatus = { ...this.syncStatus, localPasskeyCount: passkeys.length };

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
          lastError: syncService.getStatus().lastError || this.syncStatus.lastError,
        },
      };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Error getting sync status:', error);
      return { success: false, error: message };
    }
  }

  private async loadSyncStatus(): Promise<void> {
    try {
      const persisted = (await chrome.storage.local.get(SYNC_STATUS_KEY))[SYNC_STATUS_KEY];
      if (persisted && typeof persisted === 'object') {
        this.syncStatus = { ...this.syncStatus, ...persisted };
      }
    } catch (error) {
      logger.error('Failed to load sync status:', error);
    }
  }

  /**
   * Every write goes through here once the persisted status is loaded. Pass a
   * function to derive the update from the current status, so concurrent
   * read-modify-write updates (pending change counts) are not lost.
   */
  private async updateSyncStatus(
    updates: Partial<SyncStatus> | ((current: SyncStatus) => Partial<SyncStatus>)
  ): Promise<void> {
    await this.syncStatusLoaded;
    const changes = typeof updates === 'function' ? updates(this.syncStatus) : updates;
    this.syncStatus = { ...this.syncStatus, ...changes };
    await chrome.storage.local.set({ [SYNC_STATUS_KEY]: this.syncStatus });
    this.logSync('SYNC_STATUS_UPDATE', changes);
  }

  /**
   * Count a saved vault change for sync and push it out. This is
   * bookkeeping: the change is already stored, so a failure here (a full
   * storage quota, an unreachable relay) is logged instead of turning the
   * caller's success into an error. A registration reported as failed after
   * its passkey was saved leaves a passkey the site never received.
   */
  private async noteVaultChange(): Promise<void> {
    try {
      await this.incrementPendingChanges();
    } catch (error) {
      logger.error('Failed to count a pending sync change:', error);
    }
    void Promise.resolve(this.triggerSync()).catch((error) =>
      logger.error('Failed to start a sync:', error)
    );
  }

  private async incrementPendingChanges(): Promise<void> {
    await this.updateSyncStatus((current) => ({
      pendingChanges: current.pendingChanges + 1,
    }));
  }

  private logSync(action: string, details?: Record<string, unknown>): void {
    // Gate behind the debug toggle so sync activity (chainId, credential IDs,
    // device names) is not streamed to the console when debug logging is off.
    logger.debug(`[SYNC] ${action}`, details || '');
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
    syncService.retryPending();
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

    await this.updateSyncStatus((current) => ({
      lastSyncAttempt: Date.now(),
      connectionStatus: 'connecting',
      pendingChanges: Math.max(1, current.pendingChanges),
    }));

    try {
      const passkeys = await this.loadPasskeys();

      const syncStatus = syncService.getStatus();
      if (!syncStatus.connected) {
        // A PIN-protected vault keeps the seed only in the encrypted store.
        const seedHash = await this.resolveSyncSeedHash(config);
        if (config.chainId && config.deviceId && seedHash) {
          await syncService.initialize(
            config.chainId,
            config.deviceId,
            seedHash,
            config.deviceName || undefined,
            this.syncVaultAdapter()
          );
        }
      }

      await syncService.broadcastPasskeyUpdate(
        passkeys as SyncPasskey[],
        (await loadTotpEntries()) as SyncTotpEntry[]
      );
      await syncService.requestSync();

      // Both calls return quietly when no relay is open, and initialize()
      // gives up waiting after a grace period. Report what actually happened.
      if (!syncService.getStatus().connected) {
        await this.updateSyncStatus({
          connectionStatus: 'disconnected',
          localPasskeyCount: passkeys.length,
        });
        this.logSync('SYNC_NOT_CONNECTED', { passkeyCount: passkeys.length });
        return;
      }

      await this.updateSyncStatus({
        connectionStatus: 'connected',
        lastError: null,
        localPasskeyCount: passkeys.length,
      });

      this.logSync('SYNC_QUEUED', { passkeyCount: passkeys.length });
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
      if (!/^\d{4,12}$/.test(password || '')) {
        return { success: false, error: 'PIN must be 4 to 12 digits' };
      }

      // Runs serialized with the other vault jobs, so this cannot race a
      // concurrent setup. On a configured vault initialize() would just unlock
      // it, and the reconcile below would then overwrite the encrypted store
      // with raw storage that the first setup already emptied.
      if (await secureStorage.isSetup()) {
        return { success: false, error: 'A PIN is already set' };
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
          enabled: config.enabled || false,
        });
        logger.info('Migrated sync config to secure storage');
      }

      await this.reconcileSecureStorageFromRaw();
      await chrome.storage.local.remove([PASSKEY_STORAGE_KEY, 'totp_entries']);
      if (config?.seedHash) {
        const publicConfig = { ...config };
        delete publicConfig.seedHash;
        await chrome.storage.local.set({ [SYNC_CONFIG_KEY]: publicConfig });
      }
      await this.stripCleartextChainSeed();

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

      const unlocked = await this.withVault(async () => {
        const ready = await secureStorage.initialize(password);
        if (ready) {
          await this.migrateLegacyRawStorage();
          await this.repairStoredCredentialIds();
          await this.stripCleartextChainSeed();
        }
        return ready;
      });
      if (!unlocked) {
        return { success: false, error: 'Invalid password or storage not initialized' };
      }
      await this.stampLegacyBackupFlags();
      // The seed lives in the encrypted store, so sync could not have started
      // while locked. Now that the key is in memory, bring it up.
      await this.initializeSyncService();

      return { success: true, message: 'Secure storage unlocked' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to unlock secure storage:', error);
      return { success: false, error: message };
    }
  }

  /**
   * Push the freshest raw storage into the encrypted store. UI pages (popup
   * delete, import) run in a separate context without the in-memory key, so
   * they write only raw; they call this afterwards so the encrypted copy does
   * not go stale and clobber their change on the next background save. No-op
   * when locked or when no master password is configured.
   */
  private async handleReconcileStorage(): Promise<unknown> {
    try {
      await this.reconcileSecureStorageFromRaw();
      return { success: true };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Failed to reconcile storage:', error);
      return { success: false, error: message };
    }
  }

  private async handleLockSecureStorage(): Promise<unknown> {
    try {
      await syncService.disconnect();
      secureStorage.lock();
      return { success: true, message: 'Secure storage locked' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to lock secure storage:', error);
      return { success: false, error: message };
    }
  }

  private async handleRemoveMasterPassword(payload: { currentPassword: string }): Promise<unknown> {
    try {
      const { currentPassword } = payload;
      if (!currentPassword) {
        return { success: false, error: 'Current PIN is required' };
      }
      // The cleartext copy is written before the encrypted vault is removed,
      // so an interrupted removal always leaves at least one of them.
      const removed = await secureStorage.removeMasterPassword(currentPassword, async (vault) => {
        // Raw sync_config holds the live chain membership. The encrypted copy
        // only gives back the seed it kept out of cleartext, and only for
        // that same chain: it can be older than a leave or a join.
        const live = (await chrome.storage.local.get(SYNC_CONFIG_KEY))[SYNC_CONFIG_KEY] as
          | SyncConfig
          | undefined;
        const seedHash = vault.syncConfig?.seedHash;
        const restoreSeed =
          !live?.seedHash &&
          !!live?.chainId &&
          !!seedHash &&
          vault.syncConfig.chainId === live.chainId;
        await chrome.storage.local.set({
          [PASSKEY_STORAGE_KEY]: vault.passkeys,
          totp_entries: vault.totpEntries,
          ...(restoreSeed ? { [SYNC_CONFIG_KEY]: { ...live, seedHash } } : {}),
        });
      });
      if (!removed) {
        return { success: false, error: 'Failed to remove PIN — check your current PIN' };
      }
      return { success: true, message: 'Master PIN removed' };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to remove master password:', error);
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
        return { success: false, error: 'Both current and new PINs are required' };
      }
      if (!/^\d{4,12}$/.test(newPassword)) {
        return { success: false, error: 'PIN must be 4 to 12 digits' };
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

  private async handleGetWebAuthnFlags(): Promise<unknown> {
    try {
      return { success: true, flags: await loadWebAuthnFlags() };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }

  private async handleSetWebAuthnFlags(payload: { flags: unknown }): Promise<unknown> {
    try {
      // Normalized on the way in, so a malformed value can never reach a
      // ceremony — the caller gets back what was actually stored.
      const flags = await saveWebAuthnFlags(payload?.flags);
      logger.info('WebAuthn ceremony settings updated');
      return { success: true, flags };
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      return { success: false, error: message };
    }
  }
  private async handleSetAutoLockTimeout(payload: { minutes: number }): Promise<unknown> {
    try {
      secureStorage.setAutoLockTimeout(payload.minutes * 60 * 1000);
      await chrome.storage.local.set({ [AUTO_LOCK_SETTING_KEY]: payload.minutes });
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
