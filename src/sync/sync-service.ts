const RECONNECT_DELAY = 5000;
const PASSKEY_STORAGE_KEY = 'passkeys';

const NOSTR_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.nostr.band'];

export interface SyncMessage {
  type: 'announce' | 'request' | 'response' | 'update';
  chainId: string;
  deviceId: string;
  timestamp: number;
  payload: any;
}

export interface EncryptedPasskeyBundle {
  version: string;
  deviceId: string;
  timestamp: number;
  nonce: string;
  ciphertext: string;
  passkeyIds: string[];
}

export class SyncService {
  private ws: WebSocket | null = null;
  private chainId: string | null = null;
  private deviceId: string | null = null;
  private seedHash: string | null = null;
  private encryptionKey: CryptoKey | null = null;
  private isConnected = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private currentRelayIndex = 0;
  private subId: string | null = null;

  async initialize(chainId: string, deviceId: string, seedHash: string): Promise<void> {
    this.chainId = chainId;
    this.deviceId = deviceId;
    this.seedHash = seedHash;

    await this.deriveEncryptionKey(seedHash);
    this.connectWebSocket();

    console.log('[SyncService] Initialized for chain:', chainId);
  }

  private async deriveEncryptionKey(seedHash: string): Promise<void> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(seedHash),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    this.encryptionKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('passkey-vault-sync-v1'),
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private connectWebSocket(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    const relayUrl = NOSTR_RELAYS[this.currentRelayIndex];
    console.log('[SyncService] Connecting to relay:', relayUrl);

    try {
      this.ws = new WebSocket(relayUrl);

      this.ws.onopen = () => {
        console.log('[SyncService] WebSocket connected to', relayUrl);
        this.isConnected = true;
        this.subscribeToChain();
        this.announcePresence();
      };

      this.ws.onmessage = (event) => {
        this.handleWebSocketMessage(event.data);
      };

      this.ws.onclose = () => {
        console.log('[SyncService] WebSocket disconnected');
        this.isConnected = false;
        this.scheduleReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('[SyncService] WebSocket error:', error);
        this.currentRelayIndex = (this.currentRelayIndex + 1) % NOSTR_RELAYS.length;
      };
    } catch (error) {
      console.error('[SyncService] Failed to connect WebSocket:', error);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    this.reconnectTimer = setTimeout(() => {
      console.log('[SyncService] Attempting reconnect...');
      this.currentRelayIndex = (this.currentRelayIndex + 1) % NOSTR_RELAYS.length;
      this.connectWebSocket();
    }, RECONNECT_DELAY);
  }

  private subscribeToChain(): void {
    if (!this.ws || !this.chainId) return;

    this.subId = `passkey_${this.chainId.substring(0, 8)}_${Date.now()}`;

    const subscribeMsg = JSON.stringify([
      'REQ',
      this.subId,
      {
        kinds: [30078],
        '#d': [`passkey-sync-${this.chainId}`],
        since: Math.floor(Date.now() / 1000) - 86400,
        limit: 100,
      },
    ]);

    this.ws.send(subscribeMsg);
    console.log('[SyncService] Subscribed to chain:', this.chainId);
  }

  private async announcePresence(): Promise<void> {
    const announcement: SyncMessage = {
      type: 'announce',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      payload: {
        action: 'online',
      },
    };

    await this.broadcastMessage(announcement);
  }

  private async handleWebSocketMessage(data: string): Promise<void> {
    try {
      const parsed = JSON.parse(data);

      if (parsed[0] === 'EVENT' && parsed[2]) {
        const event = parsed[2];
        if (event?.content) {
          const syncMsg = await this.decryptMessage(event.content);
          if (syncMsg && syncMsg.deviceId !== this.deviceId && syncMsg.chainId === this.chainId) {
            await this.processSyncMessage(syncMsg);
          }
        }
      } else if (parsed[0] === 'OK') {
        console.log('[SyncService] Event published:', parsed[1]);
      } else if (parsed[0] === 'EOSE') {
        console.log('[SyncService] End of stored events');
      }
    } catch (error) {
      console.error('[SyncService] Error handling message:', error);
    }
  }

  private async processSyncMessage(msg: SyncMessage): Promise<void> {
    console.log('[SyncService] Received message:', msg.type, 'from:', msg.deviceId);

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
        await this.handleSyncResponse(msg);
        break;

      case 'update':
        await this.handlePasskeyUpdate(msg);
        break;
    }
  }

  private async handlePeerOnline(msg: SyncMessage): Promise<void> {
    console.log('[SyncService] Peer came online:', msg.deviceId);
    const passkeys = await this.getLocalPasskeys();
    if (passkeys.length > 0) {
      await this.broadcastPasskeyUpdate(passkeys);
    }
  }

  private async handleSyncRequest(msg: SyncMessage): Promise<void> {
    console.log('[SyncService] Sync requested by:', msg.deviceId);

    const passkeys = await this.getLocalPasskeys();
    if (passkeys.length === 0) {
      console.log('[SyncService] No passkeys to share');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys);

    const response: SyncMessage = {
      type: 'response',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      payload: {
        requestId: msg.payload.requestId,
        bundle,
      },
    };

    await this.broadcastMessage(response);
  }

  private async handleSyncResponse(msg: SyncMessage): Promise<void> {
    console.log('[SyncService] Received sync response from:', msg.deviceId);

    const { bundle } = msg.payload;
    if (bundle) {
      const remotePasskeys = await this.decryptBundle(bundle);
      await this.mergePasskeys(remotePasskeys);
    }
  }

  private async handlePasskeyUpdate(msg: SyncMessage): Promise<void> {
    console.log('[SyncService] Received passkey update from:', msg.deviceId);

    const { bundle } = msg.payload;
    if (bundle) {
      const remotePasskeys = await this.decryptBundle(bundle);
      await this.mergePasskeys(remotePasskeys);
    }
  }

  async requestSync(): Promise<void> {
    if (!this.isConnected) {
      console.log('[SyncService] Not connected, cannot request sync');
      return;
    }

    const requestId = crypto.randomUUID();

    const request: SyncMessage = {
      type: 'request',
      chainId: this.chainId!,
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      payload: {
        action: 'sync',
        requestId,
      },
    };

    await this.broadcastMessage(request);
  }

  async broadcastPasskeyUpdate(passkeys: any[]): Promise<void> {
    if (!this.isConnected || !this.chainId) {
      console.log('[SyncService] Not connected, skipping broadcast');
      return;
    }

    if (passkeys.length === 0) {
      console.log('[SyncService] No passkeys to broadcast');
      return;
    }

    const bundle = await this.createEncryptedBundle(passkeys);

    const update: SyncMessage = {
      type: 'update',
      chainId: this.chainId,
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      payload: { bundle },
    };

    await this.broadcastMessage(update);
    console.log('[SyncService] Broadcasted', passkeys.length, 'passkeys');
  }

  private async broadcastMessage(msg: SyncMessage): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.log('[SyncService] WebSocket not ready, cannot broadcast');
      return;
    }

    const encrypted = await this.encryptMessage(msg);
    const event = await this.createNostrEvent(encrypted);

    this.ws.send(JSON.stringify(['EVENT', event]));
  }

  private async createNostrEvent(content: string): Promise<any> {
    const created_at = Math.floor(Date.now() / 1000);
    const pubkey = this.seedHash!.substring(0, 64);
    const tags = [['d', `passkey-sync-${this.chainId}`]];

    const eventData = [0, pubkey, created_at, 30078, tags, content];
    const eventString = JSON.stringify(eventData);
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(eventString));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const id = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    const sig = id;

    return {
      id,
      pubkey,
      created_at,
      kind: 30078,
      tags,
      content,
      sig,
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

  private async createEncryptedBundle(passkeys: any[]): Promise<EncryptedPasskeyBundle> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(passkeys));
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      data
    );

    return {
      version: '1.0',
      deviceId: this.deviceId!,
      timestamp: Date.now(),
      nonce: this.arrayBufferToBase64(nonce),
      ciphertext: this.arrayBufferToBase64(ciphertext),
      passkeyIds: passkeys.map((p) => p.id),
    };
  }

  private async decryptBundle(bundle: EncryptedPasskeyBundle): Promise<any[]> {
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
    return JSON.parse(decoder.decode(decrypted));
  }

  private async getLocalPasskeys(): Promise<any[]> {
    const result = await chrome.storage.local.get(PASSKEY_STORAGE_KEY);
    return result[PASSKEY_STORAGE_KEY] || [];
  }

  private async mergePasskeys(remotePasskeys: any[]): Promise<void> {
    const localPasskeys = await this.getLocalPasskeys();
    const localMap = new Map(localPasskeys.map((p) => [p.id, p]));

    let hasChanges = false;
    let addedCount = 0;
    let updatedCount = 0;

    for (const remote of remotePasskeys) {
      const local = localMap.get(remote.id);

      if (!local) {
        localMap.set(remote.id, remote);
        hasChanges = true;
        addedCount++;
        console.log('[SyncService] Added new passkey:', remote.id, 'for', remote.rpId);
      } else if (remote.createdAt > local.createdAt) {
        localMap.set(remote.id, remote);
        hasChanges = true;
        updatedCount++;
        console.log('[SyncService] Updated passkey:', remote.id);
      }
    }

    if (hasChanges) {
      const merged = Array.from(localMap.values());
      await chrome.storage.local.set({ [PASSKEY_STORAGE_KEY]: merged });
      console.log(
        '[SyncService] Merged passkeys - added:',
        addedCount,
        'updated:',
        updatedCount,
        'total:',
        merged.length
      );
    } else {
      console.log('[SyncService] No new passkeys to merge');
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
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    if (this.ws) {
      if (this.subId) {
        try {
          this.ws.send(JSON.stringify(['CLOSE', this.subId]));
        } catch {}
      }
      this.ws.close();
      this.ws = null;
    }

    this.isConnected = false;
    console.log('[SyncService] Disconnected');
  }
}

export const syncService = new SyncService();
