import {
  NOSTR_EVENT_KIND,
  SYNC_BUNDLE_VERSION,
  SYNC_SEND_INTERVAL_MS,
  SYNC_LOOKBACK_SECONDS,
} from './protocol';
import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { logger } from '../utils/logger';
import { type SyncDeletion } from './merge';

const RECONNECT_DELAY = 5000;
const MAX_RECONNECT_DELAY = 60000;
const HEARTBEAT_INTERVAL = 300000; // 5 minutes - relays rate limit aggressively
const MIN_BROADCAST_INTERVAL = SYNC_SEND_INTERVAL_MS; // Minimum 10s between broadcasts
const SYNC_DEVICES_KEY = 'sync_devices';
const MAX_DEBUG_LOGS = 200;
const MAX_PROCESSED_EVENTS = 1000; // Track last N event IDs for replay protection

// Fenko-operated relay first (restricted egress environments can whitelist it),
// public relays for redundancy. Events are published to ALL relays and
// subscriptions run on ALL relays — relays don't federate, so devices that
// only share one working relay still sync.
export const DEFAULT_RELAYS = [
  'wss://vaultsync.fenko.nz',
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
];
const CUSTOM_RELAYS_KEY = 'custom_relays';

// Passkey data structure for sync
export interface SyncPasskey {
  id: string;
  credentialId?: string;
  type: string;
  rpId: string;
  origin?: string;
  user?: {
    id: string | null;
    name?: string;
    displayName?: string;
  };
  privateKey: string;
  publicKey: string;
  createdAt: number;
  counter: number;
  prfKey?: string;
  syncSource?: string;
  syncTimestamp?: number;
}

// Nostr event structure (NIP-01)
export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

// Sync chain device info
export interface SyncDevice {
  id: string;
  name: string;
  deviceType: string;
  publicKey: string;
  createdAt: number;
  lastSeen: number;
  isThisDevice: boolean;
}

// Sync chain storage structure
export interface SyncChain {
  id: string;
  createdAt: number;
  seedHash: string;
  devices: SyncDevice[];
}

// TOTP entry synced between devices (same shape as the local store, minus
// sync metadata fields which get attached on the receiving side)
export interface SyncTotpEntry {
  id: string;
  type: 'totp' | 'hotp';
  issuer: string;
  account: string;
  secretB64: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: number;
  period: number;
  counter: number;
  createdAt: number;
  lastUsed?: number;
}

export interface SyncVaultSnapshot {
  passkeys: SyncPasskey[];
  totpEntries: SyncTotpEntry[];
  deletions?: SyncDeletion[];
}

/** The background service owns vault persistence. Sync only transports records. */
export interface SyncVaultAdapter {
  getSnapshot(): Promise<SyncVaultSnapshot>;
  onPublished?(snapshot: SyncVaultSnapshot): Promise<void>;
  mergeRemote(
    passkeys: SyncPasskey[],
    totpEntries: SyncTotpEntry[],
    sourceDeviceId: string,
    deletions?: SyncDeletion[]
  ): Promise<void>;
}

// Per-relay state exposed in debug info
export interface RelayDebugState {
  url: string;
  state: 'CONNECTING' | 'OPEN' | 'CLOSING' | 'CLOSED' | 'DISCONNECTED';
}

// Debug info returned by getDebugInfo
export interface SyncDebugInfo {
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  isConnected: boolean;
  relays: RelayDebugState[];
  connectedRelayCount: number;
  hasEncryptionKey: boolean;
  hasNostrKeys: boolean;
  logsCount: number;
  processedEventsCount: number;
  messageSequence: number;
}

export interface DebugLogEntry {
  timestamp: number;
  level: 'info' | 'warn' | 'error' | 'debug';
  category: string;
  message: string;
  data?: Record<string, unknown>;
}

export interface SyncMessage {
  type: 'announce' | 'request' | 'response' | 'update' | 'device_info';
  chainId: string;
  deviceId: string;
  deviceName?: string;
  deviceType?: string;
  timestamp: number;
  payload: SyncMessagePayload;
  // Add sequence number for ordering
  sequence?: number;
}

// Payload types for different message types
export interface SyncMessagePayload {
  action?: string;
  requestId?: string;
  bundle?: EncryptedPasskeyBundle;
}

export interface EncryptedPasskeyBundle {
  version: string;
  deviceId: string;
  timestamp: number;
  nonce: string;
  ciphertext: string;
  // SECURITY FIX: Removed passkeyIds from outside encrypted payload
  // passkeyIds are now only inside the encrypted ciphertext
  passkeyCount: number; // Only expose count, not IDs
  totpCount: number; // TOTP entry count (also only inside ciphertext)
}

// One WebSocket per relay, each with its own subscription and reconnect loop
interface RelayConnection {
  url: string;
  ws: WebSocket | null;
  subId: string | null;
  reconnectTimer: ReturnType<typeof setTimeout> | null;
  reconnectDelay: number;
}

export class SyncService {
  private relayConnections: RelayConnection[] = [];
  private chainId: string | null = null;
  private deviceId: string | null = null;
  private deviceName: string | null = null;
  private seedHash: string | null = null;
  private syncSalt: string | null = null; // SECURITY FIX: Random salt for PBKDF2
  private encryptionKey: CryptoKey | null = null;
  private nostrPrivateKey: Uint8Array | null = null;
  private nostrPublicKey: string | null = null;
  private isConnected = false;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private firstConnectResolve: (() => void) | null = null;
  private debugLogs: DebugLogEntry[] = [];
  private lastBroadcastTime = 0;
  private pendingMessages = new Map<string, SyncMessage>();
  private broadcastTimer: ReturnType<typeof setTimeout> | null = null;
  private sending = false;
  private awaitingAck = new Map<string, { id: string; msg: SyncMessage }>();
  private incoming = Promise.resolve();
  private knownDevices = new Set<string>(); // Track devices we've already seen
  private processedEventIds = new Set<string>(); // SECURITY FIX: Replay protection
  private messageSequence = 0; // SECURITY FIX: Sequence numbers for ordering
  private vaultAdapter: SyncVaultAdapter | null = null;

  private log(
    level: DebugLogEntry['level'],
    category: string,
    message: string,
    data?: Record<string, unknown>
  ): void {
    const entry: DebugLogEntry = {
      timestamp: Date.now(),
      level,
      category,
      message,
      // SECURITY FIX: Sanitize logged data to avoid exposing sensitive info
      data: this.sanitizeLogData(data),
    };
    this.debugLogs.push(entry);
    if (this.debugLogs.length > MAX_DEBUG_LOGS) {
      this.debugLogs = this.debugLogs.slice(-MAX_DEBUG_LOGS);
    }
    const prefix = `[SyncService:${category}]`;
    // Always surface errors; gate warn/info behind the debug toggle. Print the
    // sanitized copy (entry.data), never the raw data, so secrets/metadata are
    // not leaked to the console.
    if (level === 'error') {
      console.error(prefix, message, entry.data || '');
    } else if (logger.isDebugEnabled()) {
      if (level === 'warn') {
        console.warn(prefix, message, entry.data || '');
      } else {
        console.log(prefix, message, entry.data || '');
      }
    }
  }

  // SECURITY FIX: Sanitize data before logging to avoid exposing sensitive information
  private sanitizeLogData(
    data: Record<string, unknown> | undefined
  ): Record<string, unknown> | undefined {
    if (!data) return data;
    if (typeof data !== 'object') return data;

    const sanitized = { ...data };
    const sensitiveKeys = [
      'seedHash',
      'privateKey',
      'encryptionKey',
      'nostrPrivateKey',
      'mnemonic',
      'seed',
    ];

    for (const key of sensitiveKeys) {
      if (key in sanitized) {
        sanitized[key] = '[REDACTED]';
      }
    }

    // Truncate long strings that might be keys
    for (const [key, value] of Object.entries(sanitized)) {
      if (typeof value === 'string' && value.length > 64) {
        sanitized[key] = value.substring(0, 8) + '...[truncated]';
      }
    }

    return sanitized;
  }

  getDebugLogs(): DebugLogEntry[] {
    return [...this.debugLogs];
  }

  clearDebugLogs(): void {
    this.debugLogs = [];
  }

  getDebugInfo(): SyncDebugInfo {
    // SECURITY FIX: Reduced exposure of sensitive data
    const wsStateNames: RelayDebugState['state'][] = ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'];
    const relays: RelayDebugState[] = this.relayConnections.map((conn) => ({
      url: conn.url,
      state: conn.ws ? wsStateNames[conn.ws.readyState] : 'DISCONNECTED',
    }));
    return {
      chainId: this.chainId ? this.chainId.substring(0, 8) + '...' : null,
      deviceId: this.deviceId ? this.deviceId.substring(0, 8) + '...' : null,
      deviceName: this.deviceName,
      isConnected: this.isConnected,
      relays,
      connectedRelayCount: this.openConnections().length,
      hasEncryptionKey: !!this.encryptionKey,
      hasNostrKeys: !!this.nostrPrivateKey && !!this.nostrPublicKey,
      logsCount: this.debugLogs.length,
      processedEventsCount: this.processedEventIds.size,
      messageSequence: this.messageSequence,
    };
  }

  async initialize(
    chainId: string,
    deviceId: string,
    seedHash: string,
    deviceName?: string,
    syncSalt?: string,
    vaultAdapter?: SyncVaultAdapter
  ): Promise<void> {
    if (vaultAdapter) this.vaultAdapter = vaultAdapter;
    if (this.chainId === chainId && this.isConnected) {
      this.log('info', 'init', 'Already initialized for this chain');
      return;
    }

    this.chainId = chainId;
    this.deviceId = deviceId;
    this.seedHash = seedHash;
    this.deviceName = deviceName || 'Unknown Device';
    this.syncSalt = syncSalt || null;

    this.log('info', 'init', 'Initializing sync service', {
      chainId: chainId.substring(0, 8) + '...',
      deviceId: deviceId.substring(0, 8) + '...',
      deviceName: this.deviceName,
      hasSyncSalt: !!syncSalt,
    });

    await this.deriveKeys(seedHash);
    this.log('info', 'crypto', 'Derived encryption and signing keys');

    const relayUrls = await this.loadRelayUrls();
    await this.connectAll(relayUrls);

    this.log('info', 'init', 'Initialized for chain', { chainId: chainId.substring(0, 8) + '...' });
  }

  private async vaultSnapshot(): Promise<{
    passkeys: SyncPasskey[];
    totpEntries: SyncTotpEntry[];
    deletions?: SyncDeletion[];
  }> {
    if (!this.vaultAdapter) throw new Error('Sync vault adapter is not configured');
    return this.vaultAdapter.getSnapshot();
  }

  private async deriveKeys(seedHash: string): Promise<void> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(seedHash),
      'PBKDF2',
      false,
      ['deriveKey', 'deriveBits']
    );

    // The PBKDF2 salt MUST be deterministic from the shared chain so that every
    // device holding the mnemonic derives the SAME encryption/signing keys.
    // A previous "random salt per device" attempt broke this: the salt was
    // generated independently on each device and never transmitted, so peers
    // derived different keys and could never decrypt each other's events.
    // Different chains still get different keys because chainId derives from the
    // seed. (Per-chain, not per-device — that is the whole point of sync.)
    const encryptionSalt = encoder.encode(`pkvault-sync-${this.chainId}-enc`);
    const nostrSalt = encoder.encode(`pkvault-sync-${this.chainId}-nostr`);

    // Derive AES encryption key for message encryption
    this.encryptionKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encryptionSalt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Derive secp256k1 private key for Nostr signing
    const nostrKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: nostrSalt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    );

    this.nostrPrivateKey = new Uint8Array(nostrKeyBits);

    // Use schnorr.getPublicKey for x-only pubkey (32 bytes, required by Nostr/BIP340)
    const xOnlyPubKey = secp256k1.schnorr.getPublicKey(this.nostrPrivateKey);
    this.nostrPublicKey = bytesToHex(xOnlyPubKey);

    this.log('info', 'crypto', 'Derived Nostr keypair', {
      pubkeyPrefix: this.nostrPublicKey.substring(0, 8) + '...',
    });
  }

  // User-managed relay list from options, falling back to defaults
  private async loadRelayUrls(): Promise<string[]> {
    try {
      const result = await chrome.storage.local.get(CUSTOM_RELAYS_KEY);
      const stored = result[CUSTOM_RELAYS_KEY];
      if (Array.isArray(stored) && stored.length > 0) {
        return stored.filter((u): u is string => typeof u === 'string' && u.startsWith('wss://'));
      }
    } catch {
      // Fall through to defaults
    }
    return DEFAULT_RELAYS;
  }

  // Connect to every relay concurrently. Resolves when the FIRST relay opens
  // (sync is usable); remaining relays keep connecting/retrying in background.
  private connectAll(urls: string[]): Promise<void> {
    this.relayConnections = urls.map((url) => ({
      url,
      ws: null,
      subId: null,
      reconnectTimer: null,
      reconnectDelay: RECONNECT_DELAY,
    }));

    this.log('info', 'ws', 'Connecting to all relays', { count: urls.length, relays: urls });

    return new Promise((resolve) => {
      let settled = false;
      const settle = () => {
        if (settled) return;
        settled = true;
        this.firstConnectResolve = null;
        resolve();
      };
      this.firstConnectResolve = settle;
      // Do not hang forever when no relay is reachable (offline/firewalled).
      // The config is already persisted and the connections keep retrying in
      // the background, so resolve after a grace period and connect later.
      setTimeout(() => {
        if (!settled) {
          this.log('warn', 'ws', 'No relay connected yet; continuing in background');
          settle();
        }
      }, 12000);
      for (const conn of this.relayConnections) {
        this.connectRelay(conn);
      }
    });
  }

  private openConnections(): RelayConnection[] {
    return this.relayConnections.filter((c) => c.ws?.readyState === WebSocket.OPEN);
  }

  private connectRelay(conn: RelayConnection): void {
    if (!this.chainId) return; // Disconnected while a reconnect timer was pending

    if (
      conn.ws &&
      (conn.ws.readyState === WebSocket.OPEN || conn.ws.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    this.log('info', 'ws', 'Connecting to relay', { relay: conn.url });

    const timeoutId = setTimeout(() => {
      this.log('warn', 'ws', 'Connection timeout after 10s', { relay: conn.url });
      conn.ws?.close();
    }, 10000);

    let ws: WebSocket;
    try {
      ws = new WebSocket(conn.url);
    } catch (error: unknown) {
      clearTimeout(timeoutId);
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log('error', 'ws', 'Failed to create WebSocket', {
        relay: conn.url,
        error: errorMessage,
      });
      this.scheduleRelayReconnect(conn);
      return;
    }
    conn.ws = ws;

    ws.onopen = () => {
      clearTimeout(timeoutId);
      this.log('info', 'ws', 'WebSocket connected', { relay: conn.url });
      conn.reconnectDelay = RECONNECT_DELAY;
      this.isConnected = true;
      this.subscribeToChain(conn);
      void this.sendToRelay(conn, this.buildAnnounceMessage());
      void this.refreshSnapshot().catch((error) => this.log('error', 'sync', String(error)));
      void this.requestSync();
      this.scheduleBroadcast();
      this.startHeartbeat();
      if (this.firstConnectResolve) {
        this.firstConnectResolve();
        this.firstConnectResolve = null;
      }
    };

    ws.onmessage = (event) => {
      this.incoming = this.incoming
        .then(() => this.handleWebSocketMessage(event.data, conn))
        .catch((error) => this.log('error', 'sync', String(error)));
    };

    ws.onclose = (event) => {
      clearTimeout(timeoutId);
      if (conn.ws !== ws) return; // A newer socket replaced this one
      conn.ws = null;
      this.isConnected = this.openConnections().length > 0;
      this.log('warn', 'ws', 'WebSocket disconnected', {
        relay: conn.url,
        code: event.code,
        reason: event.reason,
        stillConnected: this.isConnected,
      });
      if (this.chainId) {
        this.scheduleRelayReconnect(conn);
      }
    };

    ws.onerror = () => {
      // onclose follows with the reconnect; just record it
      this.log('error', 'ws', 'WebSocket error', { relay: conn.url });
    };
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer) return; // One global heartbeat across all relays
    this.heartbeatTimer = setInterval(() => {
      if (this.openConnections().length > 0) {
        this.log('debug', 'heartbeat', 'Sending presence announcement');
        void this.announcePresence();
        void this.refreshSnapshot().catch((error) => this.log('error', 'sync', String(error)));
        void this.requestSync();
      }
    }, HEARTBEAT_INTERVAL);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  // Per-relay reconnect with exponential backoff (reset on successful open)
  private scheduleRelayReconnect(conn: RelayConnection): void {
    if (conn.reconnectTimer) {
      clearTimeout(conn.reconnectTimer);
    }
    const delay = conn.reconnectDelay;
    conn.reconnectDelay = Math.min(conn.reconnectDelay * 2, MAX_RECONNECT_DELAY);
    this.log('info', 'ws', 'Scheduling reconnect', { relay: conn.url, delayMs: delay });
    conn.reconnectTimer = setTimeout(() => {
      conn.reconnectTimer = null;
      this.connectRelay(conn);
    }, delay);
  }

  private subscribeToChain(conn: RelayConnection): void {
    if (!conn.ws || !this.chainId) return;

    conn.subId = `pk_${this.chainId.substring(0, 8)}_${Date.now()}`;

    const filter = {
      kinds: [NOSTR_EVENT_KIND],
      '#d': [`pksync-${this.chainId}`],
      since: Math.floor(Date.now() / 1000) - SYNC_LOOKBACK_SECONDS,
      limit: 50,
    };

    // Retain one snapshot per device, independent of transient announcements.
    const snapshots = {
      kinds: [NOSTR_EVENT_KIND],
      authors: [this.nostrPublicKey],
      '#h': [this.chainId],
    };
    const subscribeMsg = JSON.stringify(['REQ', conn.subId, filter, snapshots]);

    conn.ws.send(subscribeMsg);
    this.log('info', 'nostr', 'Subscribed to chain events', {
      relay: conn.url,
      subId: conn.subId,
      filter,
      chainId: this.chainId.substring(0, 8) + '...',
    });
  }

  private buildAnnounceMessage(): SyncMessage {
    return {
      type: 'announce',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      sequence: ++this.messageSequence,
      payload: {
        action: 'online',
      },
    };
  }

  private async announcePresence(): Promise<void> {
    this.log('debug', 'msg', 'Broadcasting presence announcement', {
      deviceId: this.deviceId?.substring(0, 8),
      deviceName: this.deviceName,
    });

    await this.broadcastMessage(this.buildAnnounceMessage());
  }

  // Send one message to one relay, bypassing the global broadcast rate limit.
  // Used to announce on a relay the moment its socket opens.
  private async sendToRelay(conn: RelayConnection, msg: SyncMessage): Promise<void> {
    if (!conn.ws || conn.ws.readyState !== WebSocket.OPEN) return;
    try {
      const encrypted = await this.encryptMessage(msg);
      const event = await this.createNostrEvent(encrypted);
      conn.ws.send(JSON.stringify(['EVENT', event]));
      this.log('debug', 'nostr', 'Sent event to relay', {
        relay: conn.url,
        eventId: event.id?.substring(0, 8),
        msgType: msg.type,
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log('error', 'nostr', 'Failed to send to relay', {
        relay: conn.url,
        error: errorMessage,
      });
    }
  }

  private getDeviceType(): string {
    if (typeof navigator === 'undefined') return 'Desktop';
    const platform = navigator.platform?.toLowerCase() || '';
    if (platform.includes('mac')) return 'Desktop (macOS)';
    if (platform.includes('win')) return 'Desktop (Windows)';
    if (platform.includes('linux')) return 'Desktop (Linux)';
    return 'Desktop';
  }

  private async handleWebSocketMessage(data: string, conn: RelayConnection): Promise<void> {
    let receivedId: string | undefined;
    try {
      const parsed = JSON.parse(data);
      const msgType = parsed[0];

      if (msgType === 'EVENT' && parsed[2]) {
        const event = parsed[2];

        // SECURITY FIX: Verify Nostr event signature before processing
        const isValidSignature = await this.verifyNostrEventSignature(event);
        if (!isValidSignature) {
          this.log('warn', 'nostr', 'Rejected event with invalid signature', {
            eventId: event.id?.substring(0, 8),
          });
          return;
        }

        // SECURITY FIX: Replay protection - check if we've seen this event.
        // Also dedups the same event arriving from multiple relays.
        if (this.processedEventIds.has(event.id)) {
          this.log('debug', 'nostr', 'Ignoring already processed event', {
            eventId: event.id?.substring(0, 8),
            relay: conn.url,
          });
          return;
        }

        // Reserve the ID while applying the event; release it if persistence fails.
        receivedId = event.id;
        this.processedEventIds.add(event.id);
        if (this.processedEventIds.size > MAX_PROCESSED_EVENTS) {
          // Remove oldest entries (convert to array, slice, convert back)
          const entries = Array.from(this.processedEventIds);
          this.processedEventIds = new Set(entries.slice(-MAX_PROCESSED_EVENTS / 2));
        }

        this.log('debug', 'nostr', 'Received verified EVENT', {
          eventId: event.id?.substring(0, 8),
          pubkey: event.pubkey?.substring(0, 8),
          kind: event.kind,
          relay: conn.url,
        });

        if (event?.content) {
          const syncMsg = await this.decryptMessage(event.content);
          if (syncMsg) {
            if (syncMsg.deviceId === this.deviceId) {
              this.log('debug', 'msg', 'Ignoring own message');
            } else if (syncMsg.chainId !== this.chainId) {
              this.log('debug', 'msg', 'Ignoring message from different chain');
            } else {
              this.log('info', 'msg', 'Received sync message', {
                type: syncMsg.type,
                fromDevice: syncMsg.deviceId?.substring(0, 8),
                deviceName: syncMsg.deviceName,
                sequence: syncMsg.sequence,
              });
              await this.processSyncMessage(syncMsg);
            }
          } else {
            this.log('debug', 'crypto', 'Failed to decrypt message (wrong key or not our message)');
          }
        }
      } else if (msgType === 'OK') {
        const [, eventId, success, message] = parsed;
        if (success) {
          for (const [type, pending] of this.awaitingAck) {
            if (pending.id !== eventId) {
              continue;
            }
            this.awaitingAck.delete(type);
            if (this.pendingMessages.get(type) === pending.msg) {
              this.pendingMessages.delete(type);
            }
            if (type === 'update' && pending.msg.payload.bundle && this.vaultAdapter?.onPublished) {
              await this.vaultAdapter.onPublished(
                await this.decryptBundle(pending.msg.payload.bundle)
              );
            }
          }
          this.log('info', 'nostr', 'Event published successfully', {
            eventId: eventId?.substring(0, 8),
            relay: conn.url,
          });
        } else {
          this.log('warn', 'nostr', 'Event rejected by relay', {
            eventId: eventId?.substring(0, 8),
            relay: conn.url,
            message,
          });
        }
      } else if (msgType === 'EOSE') {
        this.log('info', 'nostr', 'End of stored events', { relay: conn.url });
      } else if (msgType === 'NOTICE') {
        this.log('info', 'nostr', 'Relay notice', { relay: conn.url, notice: parsed[1] });
      } else {
        this.log('debug', 'nostr', 'Unknown message type', {
          msgType,
          dataPreview: data.substring(0, 50),
        });
      }
    } catch (error) {
      if (receivedId) {
        this.processedEventIds.delete(receivedId);
      }
      this.log('warn', 'sync', 'Failed to process relay message');
    }
  }

  // SECURITY FIX: Verify Nostr event BIP340 Schnorr signature
  private async verifyNostrEventSignature(event: NostrEvent): Promise<boolean> {
    try {
      if (
        !event.id ||
        !event.pubkey ||
        !event.sig ||
        !event.created_at ||
        event.kind === undefined
      ) {
        return false;
      }

      // Reconstruct event data for hashing (NIP-01 format)
      const eventData = [
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags || [],
        event.content || '',
      ];
      const eventJson = JSON.stringify(eventData);
      const eventHash = sha256(new TextEncoder().encode(eventJson));
      const expectedId = bytesToHex(eventHash);

      // Verify event ID matches hash
      if (event.id !== expectedId) {
        this.log('warn', 'crypto', 'Event ID mismatch', {
          expected: expectedId.substring(0, 8),
          received: event.id.substring(0, 8),
        });
        return false;
      }

      // Verify BIP340 Schnorr signature
      const sigBytes = hexToBytes(event.sig);
      const pubkeyBytes = hexToBytes(event.pubkey);

      const isValid = await secp256k1.schnorr.verifyAsync(sigBytes, eventHash, pubkeyBytes);

      if (!isValid) {
        this.log('warn', 'crypto', 'Invalid Schnorr signature');
      }

      return isValid;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log('error', 'crypto', 'Signature verification failed', { error: errorMessage });
      return false;
    }
  }

  private async processSyncMessage(msg: SyncMessage): Promise<void> {
    this.log('info', 'sync', 'Processing message', {
      type: msg.type,
      from: msg.deviceId?.substring(0, 8),
      deviceName: msg.deviceName,
      sequence: msg.sequence,
    });

    await this.updateRemoteDevice(msg);

    switch (msg.type) {
      case 'announce':
        if (msg.payload.action === 'online') {
          await this.handlePeerOnline(msg);
        }
        break;

      case 'request':
        if (msg.payload.action === 'sync') {
          await this.handleSyncRequest(msg);
        }
        break;

      case 'response':
      case 'update':
        await this.handlePasskeyUpdate(msg);
        break;
    }
  }

  private async updateRemoteDevice(msg: SyncMessage): Promise<void> {
    try {
      const result = await chrome.storage.local.get(SYNC_DEVICES_KEY);
      const chain = result[SYNC_DEVICES_KEY];
      if (!chain) {
        this.log('warn', 'device', 'No chain found in storage');
        return;
      }

      const existingIndex = chain.devices.findIndex((d: SyncDevice) => d.id === msg.deviceId);

      const deviceInfo = {
        id: msg.deviceId,
        name: msg.deviceName || `Device ${msg.deviceId.substring(0, 8)}`,
        deviceType: msg.deviceType || 'Desktop',
        publicKey: '',
        createdAt: existingIndex >= 0 ? chain.devices[existingIndex].createdAt : msg.timestamp,
        lastSeen: msg.timestamp,
        isThisDevice: msg.deviceId === this.deviceId,
      };

      if (existingIndex >= 0) {
        chain.devices[existingIndex] = {
          ...chain.devices[existingIndex],
          ...deviceInfo,
          lastSeen: msg.timestamp,
        };
        this.log('debug', 'device', 'Updated existing device', {
          deviceId: msg.deviceId.substring(0, 8),
        });
      } else if (msg.deviceId !== this.deviceId) {
        chain.devices.push(deviceInfo);
        this.log('info', 'device', 'Discovered NEW device!', {
          deviceId: msg.deviceId.substring(0, 8),
          deviceName: msg.deviceName,
          deviceType: msg.deviceType,
        });
      }

      await chrome.storage.local.set({ [SYNC_DEVICES_KEY]: chain });
      this.log('debug', 'device', 'Saved device list', { deviceCount: chain.devices.length });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log('error', 'device', 'Failed to update remote device', { error: errorMessage });
    }
  }

  private async handlePeerOnline(msg: SyncMessage): Promise<void> {
    // Only share passkeys with NEW devices we haven't seen before
    if (this.knownDevices.has(msg.deviceId)) {
      this.log('debug', 'sync', 'Peer already known, skipping passkey share', {
        peer: msg.deviceId?.substring(0, 8),
      });
      return;
    }

    this.knownDevices.add(msg.deviceId);
    this.log('info', 'sync', 'New peer discovered, sharing passkeys', {
      peer: msg.deviceId?.substring(0, 8),
      peerName: msg.deviceName,
    });

    const { passkeys, totpEntries } = await this.vaultSnapshot();
    if (passkeys.length > 0 || totpEntries.length > 0) {
      await this.broadcastPasskeyUpdate(passkeys, totpEntries);
    } else {
      this.log('info', 'sync', 'No passkeys to share with peer');
    }
  }

  private async handleSyncRequest(msg: SyncMessage): Promise<void> {
    this.log('info', 'sync', 'Sync requested by peer', {
      peer: msg.deviceId?.substring(0, 8),
      requestId: msg.payload.requestId,
    });

    const { passkeys, totpEntries } = await this.vaultSnapshot();

    const bundle = await this.createEncryptedBundle(passkeys, totpEntries);

    const response: SyncMessage = {
      type: 'response',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      sequence: ++this.messageSequence,
      payload: {
        requestId: msg.payload.requestId,
        bundle,
      },
    };

    this.log('info', 'sync', 'Sending passkeys in response', { passkeyCount: passkeys.length });
    await this.broadcastMessage(response);
  }

  private async handlePasskeyUpdate(msg: SyncMessage): Promise<void> {
    const { bundle } = msg.payload;
    if (bundle) {
      try {
        this.log('info', 'sync', 'Received passkey bundle', {
          from: msg.deviceId?.substring(0, 8),
          passkeyCount: bundle.passkeyCount,
          totpCount: bundle.totpCount || 0,
        });
        const {
          passkeys: remotePasskeys,
          totpEntries: remoteTotp,
          deletions,
        } = await this.decryptBundle(bundle);
        if (!this.vaultAdapter) throw new Error('Sync vault adapter is not configured');
        await this.vaultAdapter.mergeRemote(remotePasskeys, remoteTotp, msg.deviceId, deletions);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.log('error', 'sync', 'Failed to decrypt/merge bundle', { error: errorMessage });
        throw error;
      }
    }
  }

  async requestSync(): Promise<void> {
    if (!this.isConnected) {
      this.log('warn', 'sync', 'Not connected, cannot request sync');
      return;
    }

    const request: SyncMessage = {
      type: 'request',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      sequence: ++this.messageSequence,
      payload: {
        action: 'sync',
        requestId: crypto.randomUUID(),
      },
    };

    this.log('info', 'sync', 'Requesting sync from peers', {
      requestId: request.payload.requestId,
    });
    await this.broadcastMessage(request);
  }

  async broadcastPasskeyUpdate(
    passkeys: SyncPasskey[],
    totpEntries: SyncTotpEntry[]
  ): Promise<void> {
    if (!this.isConnected || !this.chainId) {
      this.log('warn', 'sync', 'Not connected, skipping passkey broadcast');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys, totpEntries);

    const update: SyncMessage = {
      type: 'update',
      chainId: this.chainId,
      deviceId: this.deviceId!,
      deviceName: this.deviceName || undefined,
      deviceType: this.getDeviceType(),
      timestamp: Date.now(),
      sequence: ++this.messageSequence,
      payload: { bundle },
    };

    await this.broadcastMessage(update);
    this.log('info', 'sync', 'Broadcasted passkey update', { passkeyCount: passkeys.length });
  }

  // Sign the event once, send the same frame to every open relay.
  // Receivers dedup by event ID, so multi-relay delivery is idempotent.
  private async refreshSnapshot(): Promise<void> {
    if (!this.vaultAdapter || !this.isConnected) {
      return;
    }
    const { passkeys, totpEntries } = await this.vaultSnapshot();
    await this.broadcastPasskeyUpdate(passkeys, totpEntries);
  }

  private scheduleBroadcast(): void {
    if (this.broadcastTimer || this.pendingMessages.size === 0 || !this.chainId) {
      return;
    }
    const delay = Math.max(0, MIN_BROADCAST_INTERVAL - (Date.now() - this.lastBroadcastTime));
    this.broadcastTimer = setTimeout(() => {
      this.broadcastTimer = null;
      void this.flushBroadcast();
    }, delay);
  }

  private async broadcastMessage(msg: SyncMessage): Promise<void> {
    // Full snapshots supersede queued snapshots; other message types keep their slots.
    this.pendingMessages.set(msg.type, msg);
    await this.flushBroadcast();
  }

  private async flushBroadcast(): Promise<void> {
    if (this.sending || this.openConnections().length === 0 || !this.chainId) {
      return;
    }
    if (Date.now() - this.lastBroadcastTime < MIN_BROADCAST_INTERVAL) {
      this.scheduleBroadcast();
      return;
    }
    const msg = this.pendingMessages.values().next().value as SyncMessage | undefined;
    if (!msg) {
      return;
    }
    this.sending = true;
    this.lastBroadcastTime = Date.now();
    try {
      const encrypted = await this.encryptMessage(msg);
      const event = await this.createNostrEvent(encrypted, msg.type);
      const frame = JSON.stringify(['EVENT', event]);
      this.awaitingAck.set(msg.type, { id: event.id, msg });
      let sent = 0;
      for (const conn of this.openConnections()) {
        try {
          conn.ws!.send(frame);
          sent++;
        } catch (error) {
          this.log('warn', 'nostr', String(error));
        }
      }
      if (sent > 0 && this.pendingMessages.get(msg.type) === msg) {
        this.pendingMessages.delete(msg.type);
        this.pendingMessages.set(msg.type, msg);
      }
    } catch (error) {
      this.log('error', 'nostr', String(error));
    } finally {
      this.sending = false;
      this.scheduleBroadcast();
    }
  }

  private async createNostrEvent(content: string, type?: SyncMessage['type']): Promise<NostrEvent> {
    if (!this.nostrPrivateKey || !this.nostrPublicKey) {
      throw new Error('Nostr keys not initialized');
    }

    const created_at = Math.floor(Date.now() / 1000);
    const pubkey = this.nostrPublicKey;
    const snapshot = type === 'update';
    const tags = snapshot
      ? [
          ['d', `pksync-${this.chainId}-${this.deviceId}`],
          ['h', this.chainId!],
        ]
      : [['d', `pksync-${this.chainId}`]];

    // Create the event data for hashing (NIP-01 format)
    const eventData = [0, pubkey, created_at, NOSTR_EVENT_KIND, tags, content];
    const eventJson = JSON.stringify(eventData);

    // Hash the serialized event to get the event ID
    const eventHash = sha256(new TextEncoder().encode(eventJson));
    const id = bytesToHex(eventHash);

    // Sign the event ID with BIP340 Schnorr signature
    const sig = await secp256k1.schnorr.signAsync(eventHash, this.nostrPrivateKey);
    const sigHex = bytesToHex(sig);

    this.log('debug', 'nostr', 'Created signed event', {
      id: id.substring(0, 8),
      pubkey: pubkey.substring(0, 8),
      sigLen: sigHex.length,
    });

    return {
      id,
      pubkey,
      created_at,
      kind: NOSTR_EVENT_KIND,
      tags,
      content,
      sig: sigHex,
    };
  }

  private async encryptMessage(msg: SyncMessage): Promise<string> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(msg));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      data
    );

    return JSON.stringify({
      n: this.arrayBufferToBase64(nonce),
      c: this.arrayBufferToBase64(ciphertext),
    });
  }

  private async decryptMessage(encrypted: string): Promise<SyncMessage | null> {
    if (!this.encryptionKey) {
      return null;
    }

    try {
      const { n, c } = JSON.parse(encrypted);
      const nonce = this.base64ToArrayBuffer(n);
      const ciphertext = this.base64ToArrayBuffer(c);

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer },
        this.encryptionKey,
        ciphertext.buffer as ArrayBuffer
      );

      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decrypted));
    } catch {
      return null;
    }
  }

  // SECURITY FIX: passkeyIds no longer exposed outside encrypted payload
  private async createEncryptedBundle(
    passkeys: SyncPasskey[],
    totpEntries: SyncTotpEntry[]
  ): Promise<EncryptedPasskeyBundle> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    // Include passkeyIds INSIDE the encrypted payload
    const bundlePayload = {
      passkeys,
      deletions: this.vaultAdapter ? (await this.vaultSnapshot()).deletions || [] : [],
      passkeyIds: passkeys.map((p) => p.id),
      totpEntries,
      totpIds: totpEntries.map((e) => e.id),
      timestamp: Date.now(),
      deviceId: this.deviceId,
    };

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(bundlePayload));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      data
    );

    return {
      version: SYNC_BUNDLE_VERSION, // Version bump for new format
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      nonce: this.arrayBufferToBase64(nonce),
      ciphertext: this.arrayBufferToBase64(ciphertext),
      // SECURITY FIX: Only expose count, not individual IDs
      passkeyCount: passkeys.length,
      totpCount: totpEntries.length,
    };
  }

  private async decryptBundle(bundle: EncryptedPasskeyBundle): Promise<{
    passkeys: SyncPasskey[];
    totpEntries: SyncTotpEntry[];
    deletions?: SyncDeletion[];
  }> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const nonce = this.base64ToArrayBuffer(bundle.nonce);
    const ciphertext = this.base64ToArrayBuffer(bundle.ciphertext);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer },
      this.encryptionKey,
      ciphertext.buffer as ArrayBuffer
    );

    const decoder = new TextDecoder();
    const payload = JSON.parse(decoder.decode(decrypted));

    // Handle both old format (direct passkeys array) and new format (bundlePayload object)
    if (Array.isArray(payload)) {
      return { passkeys: payload, totpEntries: [], deletions: [] };
    }
    return {
      passkeys: payload.passkeys || [],
      totpEntries: payload.totpEntries || [],
      deletions: payload.deletions || [],
    };
  }

  private arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  getStatus(): { connected: boolean; chainId: string | null; deviceId: string | null } {
    return {
      connected: this.isConnected,
      chainId: this.chainId,
      deviceId: this.deviceId,
    };
  }

  async disconnect(): Promise<void> {
    this.log('info', 'ws', 'Disconnecting...');
    this.stopHeartbeat();
    if (this.broadcastTimer) {
      clearTimeout(this.broadcastTimer);
    }
    this.broadcastTimer = null;
    this.pendingMessages.clear();
    this.awaitingAck.clear();
    this.knownDevices.clear();
    this.lastBroadcastTime = 0;

    // chainId is cleared below, which stops onclose handlers from reconnecting,
    // but clear it before closing sockets so no handler races us
    this.chainId = null;

    for (const conn of this.relayConnections) {
      if (conn.reconnectTimer) {
        clearTimeout(conn.reconnectTimer);
        conn.reconnectTimer = null;
      }
      if (conn.ws) {
        if (conn.subId && conn.ws.readyState === WebSocket.OPEN) {
          try {
            conn.ws.send(JSON.stringify(['CLOSE', conn.subId]));
          } catch {
            // Ignore errors when closing subscription - socket may already be closing
          }
        }
        conn.ws.close();
        conn.ws = null;
      }
    }
    this.relayConnections = [];
    this.firstConnectResolve = null;

    // SECURITY FIX: Wipe sensitive keys from memory
    if (this.nostrPrivateKey) {
      crypto.getRandomValues(this.nostrPrivateKey);
      this.nostrPrivateKey.fill(0);
      this.nostrPrivateKey = null;
    }
    this.encryptionKey = null;
    this.seedHash = null;
    this.syncSalt = null;

    this.deviceId = null;
    this.isConnected = false;
    this.processedEventIds.clear();
    this.messageSequence = 0;

    this.log('info', 'ws', 'Disconnected');
  }
}

export const syncService = new SyncService();
