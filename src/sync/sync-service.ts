import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const RECONNECT_DELAY = 5000;
const HEARTBEAT_INTERVAL = 300000; // 5 minutes - relays rate limit aggressively
const MIN_BROADCAST_INTERVAL = 10000; // Minimum 10s between broadcasts
const PASSKEY_STORAGE_KEY = 'passkeys';
const TOTP_STORAGE_KEY = 'totp_entries';
const SYNC_DEVICES_KEY = 'sync_devices';
const MAX_DEBUG_LOGS = 200;
const MAX_PROCESSED_EVENTS = 1000; // Track last N event IDs for replay protection

const NOSTR_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.nostr.band'];

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

// Debug info returned by getDebugInfo
export interface SyncDebugInfo {
  chainId: string | null;
  deviceId: string | null;
  deviceName: string | null;
  isConnected: boolean;
  currentRelay: string;
  currentRelayIndex: number;
  wsReadyState: number | undefined;
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

export class SyncService {
  private ws: WebSocket | null = null;
  private chainId: string | null = null;
  private deviceId: string | null = null;
  private deviceName: string | null = null;
  private seedHash: string | null = null;
  private syncSalt: string | null = null; // SECURITY FIX: Random salt for PBKDF2
  private encryptionKey: CryptoKey | null = null;
  private nostrPrivateKey: Uint8Array | null = null;
  private nostrPublicKey: string | null = null;
  private isConnected = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private currentRelayIndex = 0;
  private subId: string | null = null;
  private connectionPromise: Promise<void> | null = null;
  private debugLogs: DebugLogEntry[] = [];
  private lastBroadcastTime = 0;
  private knownDevices = new Set<string>(); // Track devices we've already seen
  private processedEventIds = new Set<string>(); // SECURITY FIX: Replay protection
  private messageSequence = 0; // SECURITY FIX: Sequence numbers for ordering

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
    if (level === 'error') {
      console.error(prefix, message, data || '');
    } else if (level === 'warn') {
      console.warn(prefix, message, data || '');
    } else {
      console.log(prefix, message, data || '');
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
    return {
      chainId: this.chainId ? this.chainId.substring(0, 8) + '...' : null,
      deviceId: this.deviceId ? this.deviceId.substring(0, 8) + '...' : null,
      deviceName: this.deviceName,
      isConnected: this.isConnected,
      currentRelay: NOSTR_RELAYS[this.currentRelayIndex],
      currentRelayIndex: this.currentRelayIndex,
      wsReadyState: this.ws?.readyState,
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
    syncSalt?: string // SECURITY FIX: Accept random salt
  ): Promise<void> {
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

    await this.connectWithRetry();

    this.log('info', 'init', 'Initialized for chain', { chainId: chainId.substring(0, 8) + '...' });
  }

  // SECURITY FIX: Use random or chain-derived salt instead of static strings
  private async deriveKeys(seedHash: string): Promise<void> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(seedHash),
      'PBKDF2',
      false,
      ['deriveKey', 'deriveBits']
    );

    // SECURITY FIX: Use chain-derived salt if no random salt provided
    // This ensures different chains get different keys even with static fallback
    const encryptionSalt = this.syncSalt
      ? encoder.encode(this.syncSalt)
      : encoder.encode(`pkvault-sync-${this.chainId}-enc`);

    const nostrSalt = this.syncSalt
      ? encoder.encode(this.syncSalt + '-nostr')
      : encoder.encode(`pkvault-sync-${this.chainId}-nostr`);

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

  private async connectWithRetry(): Promise<void> {
    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = new Promise((resolve) => {
      const tryConnect = () => {
        this.connectWebSocket()
          .then(() => {
            this.connectionPromise = null;
            resolve();
          })
          .catch((err) => {
            this.log('warn', 'ws', 'Connection failed, trying next relay', { error: err.message });
            this.currentRelayIndex = (this.currentRelayIndex + 1) % NOSTR_RELAYS.length;
            setTimeout(tryConnect, RECONNECT_DELAY);
          });
      };
      tryConnect();
    });

    return this.connectionPromise;
  }

  private connectWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      if (this.ws) {
        this.ws.close();
        this.ws = null;
      }

      const relayUrl = NOSTR_RELAYS[this.currentRelayIndex];
      this.log('info', 'ws', 'Connecting to relay', {
        relay: relayUrl,
        index: this.currentRelayIndex,
      });

      const timeoutId = setTimeout(() => {
        this.log('warn', 'ws', 'Connection timeout after 10s', { relay: relayUrl });
        if (this.ws) {
          this.ws.close();
        }
        reject(new Error('Connection timeout'));
      }, 10000);

      try {
        this.ws = new WebSocket(relayUrl);

        this.ws.onopen = () => {
          clearTimeout(timeoutId);
          this.log('info', 'ws', 'WebSocket connected', { relay: relayUrl });
          this.isConnected = true;
          this.subscribeToChain();
          this.announcePresence();
          this.startHeartbeat();
          resolve();
        };

        this.ws.onmessage = (event) => {
          this.handleWebSocketMessage(event.data);
        };

        this.ws.onclose = (event) => {
          clearTimeout(timeoutId);
          this.log('warn', 'ws', 'WebSocket disconnected', {
            code: event.code,
            reason: event.reason,
          });
          this.isConnected = false;
          this.stopHeartbeat();
          if (this.chainId) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          clearTimeout(timeoutId);
          this.log('error', 'ws', 'WebSocket error', { error: String(error) });
          reject(error);
        };
      } catch (error: unknown) {
        clearTimeout(timeoutId);
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.log('error', 'ws', 'Failed to create WebSocket', { error: errorMessage });
        reject(error);
      }
    });
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.log('debug', 'heartbeat', 'Sending presence announcement');
        this.announcePresence();
      }
    }, HEARTBEAT_INTERVAL);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    this.log('info', 'ws', 'Scheduling reconnect in 5s');
    this.reconnectTimer = setTimeout(() => {
      this.log('info', 'ws', 'Attempting reconnect...');
      this.currentRelayIndex = (this.currentRelayIndex + 1) % NOSTR_RELAYS.length;
      this.connectWithRetry();
    }, RECONNECT_DELAY);
  }

  private subscribeToChain(): void {
    if (!this.ws || !this.chainId) return;

    this.subId = `pk_${this.chainId.substring(0, 8)}_${Date.now()}`;

    const filter = {
      kinds: [30078],
      '#d': [`pksync-${this.chainId}`],
      since: Math.floor(Date.now() / 1000) - 3600,
      limit: 50,
    };

    const subscribeMsg = JSON.stringify(['REQ', this.subId, filter]);

    this.ws.send(subscribeMsg);
    this.log('info', 'nostr', 'Subscribed to chain events', {
      subId: this.subId,
      filter,
      chainId: this.chainId.substring(0, 8) + '...',
    });
  }

  private async announcePresence(): Promise<void> {
    const announcement: SyncMessage = {
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

    this.log('debug', 'msg', 'Broadcasting presence announcement', {
      deviceId: this.deviceId?.substring(0, 8),
      deviceName: this.deviceName,
    });

    await this.broadcastMessage(announcement);
  }

  private getDeviceType(): string {
    if (typeof navigator === 'undefined') return 'Desktop';
    const platform = navigator.platform?.toLowerCase() || '';
    if (platform.includes('mac')) return 'Desktop (macOS)';
    if (platform.includes('win')) return 'Desktop (Windows)';
    if (platform.includes('linux')) return 'Desktop (Linux)';
    return 'Desktop';
  }

  private async handleWebSocketMessage(data: string): Promise<void> {
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

        // SECURITY FIX: Replay protection - check if we've seen this event
        if (this.processedEventIds.has(event.id)) {
          this.log('debug', 'nostr', 'Ignoring already processed event', {
            eventId: event.id?.substring(0, 8),
          });
          return;
        }

        // Track processed events (with size limit)
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
          this.log('info', 'nostr', 'Event published successfully', {
            eventId: eventId?.substring(0, 8),
          });
        } else {
          this.log('warn', 'nostr', 'Event rejected by relay', {
            eventId: eventId?.substring(0, 8),
            message,
          });
        }
      } else if (msgType === 'EOSE') {
        this.log('info', 'nostr', 'End of stored events');
      } else if (msgType === 'NOTICE') {
        this.log('info', 'nostr', 'Relay notice', { notice: parsed[1] });
      } else {
        this.log('debug', 'nostr', 'Unknown message type', {
          msgType,
          dataPreview: data.substring(0, 50),
        });
      }
    } catch (error) {
      // Silently ignore parse errors for non-JSON messages
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

      const isValid = await secp256k1.schnorr.verify(sigBytes, eventHash, pubkeyBytes);

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

    const passkeys = await this.getLocalPasskeys();
    if (passkeys.length > 0) {
      await this.broadcastPasskeyUpdate(passkeys);
    } else {
      this.log('info', 'sync', 'No passkeys to share with peer');
    }
  }

  private async handleSyncRequest(msg: SyncMessage): Promise<void> {
    this.log('info', 'sync', 'Sync requested by peer', {
      peer: msg.deviceId?.substring(0, 8),
      requestId: msg.payload.requestId,
    });

    const passkeys = await this.getLocalPasskeys();
    if (passkeys.length === 0) {
      this.log('info', 'sync', 'No passkeys to share');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys);

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
        const { passkeys: remotePasskeys, totpEntries: remoteTotp } =
          await this.decryptBundle(bundle);
        await this.mergePasskeys(remotePasskeys, msg.deviceId);
        if (remoteTotp.length > 0) {
          await this.mergeTotpEntries(remoteTotp, msg.deviceId);
        }
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.log('error', 'sync', 'Failed to decrypt/merge bundle', { error: errorMessage });
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

  async broadcastPasskeyUpdate(passkeys: SyncPasskey[]): Promise<void> {
    if (!this.isConnected || !this.chainId) {
      this.log('warn', 'sync', 'Not connected, skipping passkey broadcast');
      return;
    }

    if (passkeys.length === 0) {
      this.log('info', 'sync', 'No passkeys to broadcast');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys);

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

  private async broadcastMessage(msg: SyncMessage, bypassRateLimit = false): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.log('warn', 'ws', 'WebSocket not ready for broadcast', {
        readyState: this.ws?.readyState,
      });
      return;
    }

    // Rate limiting - prevent broadcast storms
    const now = Date.now();
    if (!bypassRateLimit && now - this.lastBroadcastTime < MIN_BROADCAST_INTERVAL) {
      this.log('debug', 'nostr', 'Rate limited, skipping broadcast', {
        msgType: msg.type,
        timeSinceLastMs: now - this.lastBroadcastTime,
      });
      return;
    }
    this.lastBroadcastTime = now;

    try {
      const encrypted = await this.encryptMessage(msg);
      const event = await this.createNostrEvent(encrypted);
      this.log('debug', 'nostr', 'Sending Nostr event', {
        eventId: event.id?.substring(0, 8),
        pubkey: event.pubkey?.substring(0, 8),
        msgType: msg.type,
      });
      this.ws.send(JSON.stringify(['EVENT', event]));
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log('error', 'nostr', 'Failed to broadcast message', {
        error: errorMessage,
      });
    }
  }

  private async createNostrEvent(content: string): Promise<NostrEvent> {
    if (!this.nostrPrivateKey || !this.nostrPublicKey) {
      throw new Error('Nostr keys not initialized');
    }

    const created_at = Math.floor(Date.now() / 1000);
    const pubkey = this.nostrPublicKey;
    const tags = [['d', `pksync-${this.chainId}`]];

    // Create the event data for hashing (NIP-01 format)
    const eventData = [0, pubkey, created_at, 30078, tags, content];
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
      kind: 30078,
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
  private async createEncryptedBundle(passkeys: SyncPasskey[]): Promise<EncryptedPasskeyBundle> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const totpResult = await chrome.storage.local.get(TOTP_STORAGE_KEY);
    const totpEntries = (totpResult[TOTP_STORAGE_KEY] || []) as SyncTotpEntry[];

    // Include passkeyIds INSIDE the encrypted payload
    const bundlePayload = {
      passkeys,
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
      version: '2.0', // Version bump for new format
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      nonce: this.arrayBufferToBase64(nonce),
      ciphertext: this.arrayBufferToBase64(ciphertext),
      // SECURITY FIX: Only expose count, not individual IDs
      passkeyCount: passkeys.length,
      totpCount: totpEntries.length,
    };
  }

  private async decryptBundle(
    bundle: EncryptedPasskeyBundle
  ): Promise<{ passkeys: SyncPasskey[]; totpEntries: SyncTotpEntry[] }> {
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
      return { passkeys: payload, totpEntries: [] };
    }
    return {
      passkeys: payload.passkeys || [],
      totpEntries: payload.totpEntries || [],
    };
  }

  private async getLocalPasskeys(): Promise<SyncPasskey[]> {
    const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
    return result[PASSKEY_STORAGE_KEY] || [];
  }

  // SECURITY FIX: Improved merge with source device tracking
  private async mergePasskeys(
    remotePasskeys: SyncPasskey[],
    sourceDeviceId: string
  ): Promise<void> {
    const localPasskeys = await this.getLocalPasskeys();
    const localMap = new Map(localPasskeys.map((p) => [p.id, p]));

    let addedCount = 0;
    let updatedCount = 0;

    this.log('info', 'merge', 'Merging passkeys', {
      localCount: localPasskeys.length,
      remoteCount: remotePasskeys.length,
      sourceDevice: sourceDeviceId.substring(0, 8),
    });

    for (const remote of remotePasskeys) {
      const local = localMap.get(remote.id);

      if (!local) {
        // New passkey - add it with source tracking
        remote.syncSource = sourceDeviceId;
        remote.syncTimestamp = Date.now();
        localMap.set(remote.id, remote);
        addedCount++;
        this.log('info', 'merge', 'Added new passkey', {
          id: remote.id?.substring(0, 8),
          rpId: remote.rpId,
        });
      } else if (remote.createdAt > local.createdAt) {
        // Remote is newer - update with source tracking
        remote.syncSource = sourceDeviceId;
        remote.syncTimestamp = Date.now();
        localMap.set(remote.id, remote);
        updatedCount++;
        this.log('info', 'merge', 'Updated passkey (newer)', {
          id: remote.id?.substring(0, 8),
          rpId: remote.rpId,
        });
      }
    }

    if (addedCount > 0 || updatedCount > 0) {
      const merged = Array.from(localMap.values());
      await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: merged });
      this.log('info', 'merge', 'Merge complete', {
        added: addedCount,
        updated: updatedCount,
        total: merged.length,
      });
    } else {
      this.log('info', 'merge', 'No changes needed');
    }
  }

  private async mergeTotpEntries(
    remoteEntries: SyncTotpEntry[],
    sourceDeviceId: string
  ): Promise<void> {
    const result = await chrome.storage.local.get(TOTP_STORAGE_KEY);
    const local = (result[TOTP_STORAGE_KEY] || []) as SyncTotpEntry[];
    const localMap = new Map(local.map((e) => [e.id, e]));

    let added = 0;
    let updated = 0;

    for (const remote of remoteEntries) {
      const existing = localMap.get(remote.id);
      if (!existing) {
        localMap.set(remote.id, remote);
        added++;
      } else if (remote.createdAt > existing.createdAt) {
        localMap.set(remote.id, remote);
        updated++;
      }
    }

    if (added > 0 || updated > 0) {
      const merged = Array.from(localMap.values());
      await chrome.storage.local.set({ [TOTP_STORAGE_KEY]: merged });
      this.log('info', 'merge', 'TOTP merge complete', {
        added,
        updated,
        total: merged.length,
        sourceDevice: sourceDeviceId.substring(0, 8),
      });
    }
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

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      if (this.subId && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify(['CLOSE', this.subId]));
        } catch {
          // Ignore errors when closing subscription - socket may already be closing
        }
      }
      this.ws.close();
      this.ws = null;
    }

    // SECURITY FIX: Wipe sensitive keys from memory
    if (this.nostrPrivateKey) {
      crypto.getRandomValues(this.nostrPrivateKey);
      this.nostrPrivateKey.fill(0);
      this.nostrPrivateKey = null;
    }
    this.encryptionKey = null;
    this.seedHash = null;
    this.syncSalt = null;

    this.chainId = null;
    this.deviceId = null;
    this.isConnected = false;
    this.connectionPromise = null;
    this.processedEventIds.clear();
    this.messageSequence = 0;

    this.log('info', 'ws', 'Disconnected');
  }
}

export const syncService = new SyncService();
