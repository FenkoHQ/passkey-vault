import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToBytes,
  deriveEd25519Keypair,
} from '../../../src/crypto/bip39';
import {
  generateHotp,
  generateTotp,
  parseOtpauth,
  timeRemaining,
} from '../../../src/crypto/totp';

declare const jsQR:
  | undefined
  | ((data: Uint8ClampedArray, width: number, height: number) => { data: string } | null);

declare const __APP_VERSION__: string;

declare global {
  interface Window {
    AndroidBridge?: {
      copyText(value: string): void;
      toast(value: string): void;
      loadVaultSnapshot?(): string;
      saveVaultSnapshot?(
        passkeysJson: string,
        totpJson: string,
        syncConfigJson: string,
        syncDevicesJson: string,
        customRelaysJson: string
      ): void;
      canUseBiometrics?(): boolean;
      requestBiometricUnlock?(): void;
    };
    __fenkoBiometricResult?: (ok: boolean) => void;
  }
}

type Tab = 'vault' | 'add' | 'sync' | 'tools';
type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

interface StoredTotpEntry {
  id: string;
  type: 'totp' | 'hotp';
  issuer: string;
  account: string;
  secretB64: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  counter: number;
  createdAt: number;
  lastUsed?: number;
}

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
  syncSource?: string;
  syncTimestamp?: number;
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
  seedHash: string;
  devices: SyncDevice[];
}

interface SyncMessage {
  type: 'announce' | 'request' | 'response' | 'update' | 'device_info';
  chainId: string;
  deviceId: string;
  deviceName?: string;
  deviceType?: string;
  timestamp: number;
  sequence?: number;
  payload: {
    action?: string;
    requestId?: string;
    bundle?: EncryptedPasskeyBundle;
  };
}

interface EncryptedPasskeyBundle {
  version: string;
  deviceId: string;
  timestamp: number;
  nonce: string;
  ciphertext: string;
  passkeyCount: number;
  totpCount: number;
}

const PASSKEY_STORAGE_KEY = 'passkeys';
const TOTP_STORAGE_KEY = 'totp_entries';
const SYNC_CONFIG_KEY = 'sync_config';
const SYNC_DEVICES_KEY = 'sync_devices';
const CUSTOM_RELAYS_KEY = 'custom_relays';
const LEGACY_LOCK_KEY = 'android_vault_lock';
const LOCKED_FLAG_KEY = 'android_vault_locked';
const AUTOLOCK_KEY = 'android_auto_lock_minutes';
const RECYCLE_BIN_KEY = 'recycle_bin';
const RECYCLE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

let lastActivityAt = Date.now();
const DEFAULT_RELAYS = [
  'wss://vaultsync.fenko.nz',
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
];

const state = {
  tab: 'vault' as Tab,
  unlocked: true,
  status: '',
  statusKind: 'status' as 'status' | 'bad' | 'warn',
  search: '',
  sync: null as AndroidSync | null,
  scannerStop: null as (() => void) | null,
  expanded: new Set<string>(),
};

const app = document.getElementById('app') as HTMLElement;

function loadJson<T>(key: string, fallback: T): T {
  const raw = localStorage.getItem(key);
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function saveJson(key: string, value: unknown): void {
  localStorage.setItem(key, JSON.stringify(value));
  if (
    key === PASSKEY_STORAGE_KEY ||
    key === TOTP_STORAGE_KEY ||
    key === SYNC_CONFIG_KEY ||
    key === SYNC_DEVICES_KEY ||
    key === CUSTOM_RELAYS_KEY
  ) {
    mirrorVaultToAndroid();
  }
}

function mirrorVaultToAndroid(): void {
  const bridge = window.AndroidBridge;
  if (!bridge?.saveVaultSnapshot) return;
  bridge.saveVaultSnapshot(
    localStorage.getItem(PASSKEY_STORAGE_KEY) || '[]',
    localStorage.getItem(TOTP_STORAGE_KEY) || '[]',
    localStorage.getItem(SYNC_CONFIG_KEY) || '{}',
    localStorage.getItem(SYNC_DEVICES_KEY) || 'null',
    localStorage.getItem(CUSTOM_RELAYS_KEY) || '[]'
  );
}

function mergeById<T extends { id?: string; credentialId?: string; createdAt?: number }>(
  local: T[],
  incoming: T[]
): T[] {
  const items = new Map<string, T>();
  for (const item of local) items.set(item.id || item.credentialId || uuid(), item);
  for (const item of incoming) {
    const key = item.id || item.credentialId || uuid();
    const current = items.get(key);
    if (!current || (item.createdAt || 0) >= (current.createdAt || 0)) items.set(key, item);
  }
  return Array.from(items.values());
}

function mergeNativeSnapshot(): void {
  const bridge = window.AndroidBridge;
  if (!bridge?.loadVaultSnapshot) return;
  try {
    const snapshot = JSON.parse(bridge.loadVaultSnapshot());
    if (Array.isArray(snapshot.passkeys)) {
      saveJson(PASSKEY_STORAGE_KEY, mergeById(getPasskeys(), snapshot.passkeys));
    }
    if (Array.isArray(snapshot.totpEntries)) {
      saveJson(TOTP_STORAGE_KEY, mergeById(getTotpEntries(), snapshot.totpEntries));
    }
    if (snapshot.syncConfig && !getSyncConfig().enabled) {
      saveJson(SYNC_CONFIG_KEY, snapshot.syncConfig);
    }
    if (snapshot.syncDevices && !localStorage.getItem(SYNC_DEVICES_KEY)) {
      saveJson(SYNC_DEVICES_KEY, snapshot.syncDevices);
    }
    if (Array.isArray(snapshot.customRelays) && !localStorage.getItem(CUSTOM_RELAYS_KEY)) {
      saveJson(CUSTOM_RELAYS_KEY, snapshot.customRelays);
    }
  } catch {
    // A bad native snapshot must not stop the WebView app from opening.
  }
}

function getTotpEntries(): StoredTotpEntry[] {
  return loadJson<StoredTotpEntry[]>(TOTP_STORAGE_KEY, []);
}

function setTotpEntries(entries: StoredTotpEntry[]): void {
  saveJson(TOTP_STORAGE_KEY, entries);
}

function getPasskeys(): StoredPasskey[] {
  return loadJson<StoredPasskey[]>(PASSKEY_STORAGE_KEY, []);
}

function setPasskeys(passkeys: StoredPasskey[]): void {
  saveJson(PASSKEY_STORAGE_KEY, passkeys);
}

function getSyncConfig(): SyncConfig {
  return loadJson<SyncConfig>(SYNC_CONFIG_KEY, {
    enabled: false,
    chainId: null,
    deviceId: null,
    deviceName: null,
    seedHash: null,
    syncSalt: null,
  });
}

function setSyncConfig(config: SyncConfig): void {
  saveJson(SYNC_CONFIG_KEY, config);
}

function getRelays(): string[] {
  const relays = loadJson<string[]>(CUSTOM_RELAYS_KEY, DEFAULT_RELAYS);
  const cleaned = relays
    .map((relay) => relay.trim())
    .filter((relay, index, items) => relay.startsWith('wss://') && items.indexOf(relay) === index);
  return cleaned.length ? cleaned : DEFAULT_RELAYS;
}

function setRelays(raw: string): void {
  const relays = raw
    .split(/\s+/)
    .map((relay) => relay.trim())
    .filter(Boolean);
  const invalid = relays.find((relay) => !relay.startsWith('wss://'));
  if (invalid) {
    setStatus('Relays must use wss:// URLs.', 'bad');
    return;
  }
  saveJson(CUSTOM_RELAYS_KEY, relays.length ? Array.from(new Set(relays)) : DEFAULT_RELAYS);
  void bootSync().then(() => setStatus('Relays saved.'));
}

let statusTimer = 0;

function setStatus(message: string, kind: 'status' | 'bad' | 'warn' = 'status'): void {
  state.status = message;
  state.statusKind = kind;
  render();
  if (window.AndroidBridge && message) window.AndroidBridge.toast(message);
  window.clearTimeout(statusTimer);
  if (message) {
    statusTimer = window.setTimeout(
      () => {
        state.status = '';
        if (!state.scannerStop) render();
      },
      kind === 'status' ? 3000 : 6000
    );
  }
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return bytesToBase64(new Uint8Array(buffer));
}

function base64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function uuid(): string {
  return crypto.randomUUID ? crypto.randomUUID() : base64Url(crypto.getRandomValues(new Uint8Array(16)));
}

function randomHex(bytes: number): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

function copyText(value: string): void {
  if (window.AndroidBridge) {
    window.AndroidBridge.copyText(value);
    return;
  }
  void navigator.clipboard?.writeText(value);
}

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const input = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', input);
  return bytesToHex(new Uint8Array(digest));
}


interface RecycleEntry {
  kind: 'passkey' | 'totp';
  deletedAt: number;
  passkey?: StoredPasskey;
  totp?: StoredTotpEntry;
}

function getRecycleBin(): RecycleEntry[] {
  return loadJson<RecycleEntry[]>(RECYCLE_BIN_KEY, []);
}

function purgeRecycleBin(): void {
  const bin = getRecycleBin();
  const fresh = bin.filter((entry) => Date.now() - entry.deletedAt < RECYCLE_TTL_MS);
  if (fresh.length !== bin.length) saveJson(RECYCLE_BIN_KEY, fresh);
}

function recycleLabel(entry: RecycleEntry): string {
  if (entry.kind === 'passkey') {
    const passkey = entry.passkey;
    return `${passkey?.rpId || 'Passkey'} (${passkey?.user?.name || passkey?.user?.displayName || 'passkey'})`;
  }
  return `${entry.totp?.issuer || '2FA'} (${entry.totp?.account || 'code'})`;
}

function confirmDialog(title: string, message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal panel stack">
        <h3>${escapeHtml(title)}</h3>
        <p class="muted">${escapeHtml(message)}</p>
        <div class="row">
          <button id="modal-cancel">Cancel</button>
          <button class="danger" id="modal-confirm">Delete</button>
        </div>
      </div>
    `;
    const close = (answer: boolean) => {
      overlay.remove();
      resolve(answer);
    };
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) close(false);
    });
    overlay.querySelector('#modal-cancel')?.addEventListener('click', () => close(false));
    overlay.querySelector('#modal-confirm')?.addEventListener('click', () => close(true));
    document.body.appendChild(overlay);
  });
}

async function requestDelete(kind: 'passkey' | 'totp', id: string): Promise<void> {
  if (kind === 'passkey') {
    const passkey = getPasskeys().find((item) => item.id === id || item.credentialId === id);
    if (!passkey) return;
    const ok = await confirmDialog(
      `Delete passkey for ${passkey.rpId}?`,
      'It moves to the recycle bin in Tools and is gone for good after 7 days. ' +
        'You may lose access to this account.'
    );
    if (!ok) return;
    const bin = getRecycleBin();
    bin.push({ kind: 'passkey', deletedAt: Date.now(), passkey });
    saveJson(RECYCLE_BIN_KEY, bin);
    setPasskeys(getPasskeys().filter((item) => item.id !== id && item.credentialId !== id));
    void state.sync?.broadcastUpdate();
    setStatus('Passkey moved to recycle bin.');
  } else {
    const totp = getTotpEntries().find((entry) => entry.id === id);
    if (!totp) return;
    const ok = await confirmDialog(
      `Delete 2FA code for ${totp.issuer || totp.account || 'this account'}?`,
      'It moves to the recycle bin in Tools and is gone for good after 7 days. ' +
        'You may lose access to this account.'
    );
    if (!ok) return;
    const bin = getRecycleBin();
    bin.push({ kind: 'totp', deletedAt: Date.now(), totp });
    saveJson(RECYCLE_BIN_KEY, bin);
    setTotpEntries(getTotpEntries().filter((entry) => entry.id !== id));
    void state.sync?.broadcastUpdate();
    setStatus('2FA code moved to recycle bin.');
  }
  render();
}

function restoreFromBin(index: number): void {
  const bin = getRecycleBin();
  const entry = bin[index];
  if (!entry) return;
  if (entry.kind === 'passkey' && entry.passkey) {
    setPasskeys(mergeById(getPasskeys(), [entry.passkey]));
  } else if (entry.kind === 'totp' && entry.totp) {
    setTotpEntries(mergeById(getTotpEntries(), [entry.totp]));
  }
  bin.splice(index, 1);
  saveJson(RECYCLE_BIN_KEY, bin);
  void state.sync?.broadcastUpdate();
  setStatus('Restored from recycle bin.');
}

async function purgeFromBin(index: number): Promise<void> {
  const bin = getRecycleBin();
  const entry = bin[index];
  if (!entry) return;
  const ok = await confirmDialog(
    `Permanently delete ${recycleLabel(entry)}?`,
    'This cannot be undone.'
  );
  if (!ok) return;
  bin.splice(index, 1);
  saveJson(RECYCLE_BIN_KEY, bin);
  setStatus('Permanently deleted.');
  render();
}

async function addTotpFromUri(uri: string): Promise<void> {
  const parsed = parseOtpauth(uri);
  const entry: StoredTotpEntry = {
    id: uuid(),
    type: parsed.type,
    issuer: parsed.issuer,
    account: parsed.account,
    secretB64: bytesToBase64(parsed.secret),
    algorithm: parsed.algorithm,
    digits: parsed.digits,
    period: parsed.period,
    counter: parsed.counter,
    createdAt: Date.now(),
  };
  setTotpEntries([...getTotpEntries(), entry]);
  await state.sync?.broadcastUpdate();
  setStatus('2FA code added.');
}

async function addTotpManual(form: HTMLFormElement): Promise<void> {
  const data = new FormData(form);
  const issuer = String(data.get('issuer') || '').trim();
  const account = String(data.get('account') || '').trim();
  const secret = String(data.get('secret') || '').trim();
  if (!issuer || !secret) {
    setStatus('TOTP needs an issuer and secret.', 'bad');
    return;
  }
  const type = String(data.get('type') || 'totp') as 'totp' | 'hotp';
  const algorithm = String(data.get('algorithm') || 'SHA1') as TotpAlgorithm;
  const digits = Number(data.get('digits') || 6);
  const period = Number(data.get('period') || 30);
  const counter = Number(data.get('counter') || 0);
  const bytes = /^[A-Za-z2-7=\s]+$/.test(secret) ? parseOtpauth(
    `otpauth://${type}/${encodeURIComponent(issuer + ':' + account)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=${algorithm}&digits=${digits}&period=${period}&counter=${counter}`
  ).secret : new TextEncoder().encode(secret);

  const entry: StoredTotpEntry = {
    id: uuid(),
    type,
    issuer,
    account,
    secretB64: bytesToBase64(bytes),
    algorithm,
    digits,
    period,
    counter,
    createdAt: Date.now(),
  };
  setTotpEntries([...getTotpEntries(), entry]);
  await state.sync?.broadcastUpdate();
  form.reset();
  state.tab = 'vault';
  setStatus('2FA code added.');
}

function codeFor(entry: StoredTotpEntry): { code: string; remaining: number } {
  const secret = base64ToBytes(entry.secretB64);
  const code =
    entry.type === 'hotp'
      ? generateHotp({
          secret,
          algorithm: entry.algorithm,
          digits: entry.digits,
          counter: entry.counter,
        })
      : generateTotp({
          secret,
          algorithm: entry.algorithm,
          digits: entry.digits,
          period: entry.period,
          timestamp: Date.now(),
        });
  return { code, remaining: timeRemaining(Date.now(), entry.period || 30) };
}

async function deriveBackupKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function canBiometric(): boolean {
  try {
    return window.AndroidBridge?.canUseBiometrics?.() === true;
  } catch {
    return false;
  }
}

function canLock(): boolean {
  return canBiometric();
}

function lockVault(): void {
  if (!canLock()) {
    setStatus('Enable a screen lock on this device to use the vault lock.', 'warn');
    return;
  }
  localStorage.setItem(LOCKED_FLAG_KEY, '1');
  state.unlocked = false;
  state.status = '';
  state.search = '';
  render();
}

function touchActivity(): void {
  lastActivityAt = Date.now();
}

function autoLockMinutes(): number {
  const raw = Number(localStorage.getItem(AUTOLOCK_KEY) ?? '5');
  return Number.isFinite(raw) && raw >= 0 ? raw : 5;
}

function maybeAutoLock(): void {
  const minutes = autoLockMinutes();
  if (!minutes || !state.unlocked || !canLock()) return;
  if (Date.now() - lastActivityAt >= minutes * 60_000) lockVault();
}

function startBiometricUnlock(): void {
  window.__fenkoBiometricResult = (ok: boolean) => {
    if (!ok) {
      setStatus('Biometric unlock cancelled.', 'warn');
      render();
      return;
    }
    state.unlocked = true;
    localStorage.removeItem(LOCKED_FLAG_KEY);
    touchActivity();
    void bootSync();
    setStatus('Vault unlocked.');
    render();
  };
  window.AndroidBridge?.requestBiometricUnlock?.();
}

function exportVault(): void {
  const payload = {
    version: 'fenko-vault-android-0.1.0',
    exportType: 'full',
    exportedAt: Date.now(),
    passkeys: getPasskeys(),
    totpEntries: getTotpEntries(),
    syncConfig: getSyncConfig(),
    syncDevices: loadJson<SyncChain | null>(SYNC_DEVICES_KEY, null),
    customRelays: getRelays(),
  };
  copyText(JSON.stringify(payload, null, 2));
  setStatus('Backup JSON copied.');
}

async function exportEncryptedVault(): Promise<void> {
  const password = prompt('Backup password');
  if (!password) return;
  const confirm = prompt('Confirm backup password');
  if (password !== confirm) {
    setStatus('Backup passwords do not match.', 'bad');
    return;
  }

  const payload = {
    version: 'fenko-vault-android-0.1.0',
    exportType: 'full',
    exportedAt: new Date().toISOString(),
    passkeys: getPasskeys(),
    totpEntries: getTotpEntries(),
    syncConfig: getSyncConfig(),
    syncDevices: loadJson<SyncChain | null>(SYNC_DEVICES_KEY, null),
    customRelays: getRelays(),
  };
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(password, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(payload))
  );
  const backup = {
    encrypted: true,
    version: '1.0',
    exportedAt: new Date().toISOString(),
    data: arrayBufferToBase64(encrypted),
    iv: bytesToBase64(iv),
    salt: bytesToBase64(salt),
    algorithm: 'AES-256-GCM',
  };
  copyText(JSON.stringify(backup, null, 2));
  setStatus('Encrypted backup JSON copied.');
}

async function importVault(raw: string): Promise<void> {
  let payload = JSON.parse(raw);
  if (payload.encrypted === true && payload.data && payload.iv && payload.salt) {
    const password = prompt('Backup password');
    if (!password) return;
    const key = await deriveBackupKey(password, base64ToBytes(payload.salt));
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(payload.iv) },
      key,
      base64ToBytes(payload.data)
    );
    payload = JSON.parse(new TextDecoder().decode(decrypted));
  }
  const passkeys = Array.isArray(payload.passkeys) ? payload.passkeys : [];
  const totpEntries = Array.isArray(payload.totpEntries)
    ? payload.totpEntries
    : Array.isArray(payload.totp_entries)
      ? payload.totp_entries
      : [];
  const passkeyMap = new Map(getPasskeys().map((item) => [item.id, item]));
  for (const passkey of passkeys) passkeyMap.set(passkey.id || passkey.credentialId, passkey);
  const totpMap = new Map(getTotpEntries().map((item) => [item.id, item]));
  for (const entry of totpEntries) totpMap.set(entry.id, entry);
  setPasskeys(Array.from(passkeyMap.values()));
  setTotpEntries(Array.from(totpMap.values()));
  if (payload.syncConfig) setSyncConfig(payload.syncConfig);
  if (payload.syncDevices) saveJson(SYNC_DEVICES_KEY, payload.syncDevices);
  if (Array.isArray(payload.customRelays)) saveJson(CUSTOM_RELAYS_KEY, payload.customRelays);
  await bootSync();
  await state.sync?.broadcastUpdate();
  setStatus('Backup imported.');
}

class AndroidSync {
  private ws: WebSocket | null = null;
  private relayIndex = 0;
  private encryptionKey: CryptoKey | null = null;
  private nostrPrivateKey: Uint8Array | null = null;
  private nostrPublicKey: string | null = null;
  private sequence = 0;
  private processed = new Set<string>();
  public connected = false;
  public lastError = '';

  constructor(private config: SyncConfig) {}

  async start(): Promise<void> {
    if (!this.config.enabled || !this.config.chainId || !this.config.deviceId || !this.config.seedHash) return;
    await this.deriveKeys();
    this.connect();
  }

  stop(): void {
    this.ws?.close();
    this.ws = null;
    this.connected = false;
  }

  private async deriveKeys(): Promise<void> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.config.seedHash || ''),
      'PBKDF2',
      false,
      ['deriveKey', 'deriveBits']
    );
    const encryptionSalt = this.config.syncSalt
      ? encoder.encode(this.config.syncSalt)
      : encoder.encode(`pkvault-sync-${this.config.chainId}-enc`);
    const nostrSalt = this.config.syncSalt
      ? encoder.encode(`${this.config.syncSalt}-nostr`)
      : encoder.encode(`pkvault-sync-${this.config.chainId}-nostr`);
    this.encryptionKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: encryptionSalt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: nostrSalt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      256
    );
    this.nostrPrivateKey = new Uint8Array(bits);
    this.nostrPublicKey = bytesToHex(secp256k1.schnorr.getPublicKey(this.nostrPrivateKey));
  }

  private connect(): void {
    const relays = getRelays();
    const relay = relays[this.relayIndex % relays.length];
    this.ws = new WebSocket(relay);
    this.ws.onopen = () => {
      this.connected = true;
      this.lastError = '';
      this.subscribe();
      void this.announce();
      render();
    };
    this.ws.onmessage = (event) => void this.handleRelayMessage(String(event.data));
    this.ws.onerror = () => {
      this.lastError = `Relay error: ${relay}`;
      render();
    };
    this.ws.onclose = () => {
      this.connected = false;
      render();
      if (getSyncConfig().enabled) {
        this.relayIndex = (this.relayIndex + 1) % getRelays().length;
        window.setTimeout(() => this.connect(), 5000);
      }
    };
  }

  private subscribe(): void {
    if (!this.ws || !this.config.chainId) return;
    const subId = `android_${this.config.chainId.slice(0, 8)}_${Date.now()}`;
    this.ws.send(
      JSON.stringify([
        'REQ',
        subId,
        {
          kinds: [30078],
          '#d': [`pksync-${this.config.chainId}`],
          since: Math.floor(Date.now() / 1000) - 3600,
          limit: 50,
        },
      ])
    );
  }

  async announce(): Promise<void> {
    await this.broadcast({
      type: 'announce',
      chainId: this.config.chainId!,
      deviceId: this.config.deviceId!,
      deviceName: this.config.deviceName || undefined,
      deviceType: 'Mobile (Android)',
      timestamp: Date.now(),
      sequence: ++this.sequence,
      payload: { action: 'online' },
    });
  }

  async requestSync(): Promise<void> {
    await this.broadcast({
      type: 'request',
      chainId: this.config.chainId!,
      deviceId: this.config.deviceId!,
      deviceName: this.config.deviceName || undefined,
      deviceType: 'Mobile (Android)',
      timestamp: Date.now(),
      sequence: ++this.sequence,
      payload: { action: 'sync', requestId: uuid() },
    });
  }

  async broadcastUpdate(): Promise<void> {
    if (!this.connected) return;
    const bundle = await this.createBundle();
    await this.broadcast({
      type: 'update',
      chainId: this.config.chainId!,
      deviceId: this.config.deviceId!,
      deviceName: this.config.deviceName || undefined,
      deviceType: 'Mobile (Android)',
      timestamp: Date.now(),
      sequence: ++this.sequence,
      payload: { bundle },
    });
  }

  private async broadcast(msg: SyncMessage): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const encrypted = await this.encryptMessage(msg);
    const event = await this.createEvent(encrypted);
    this.ws.send(JSON.stringify(['EVENT', event]));
  }

  private async createEvent(content: string) {
    if (!this.nostrPrivateKey || !this.nostrPublicKey) throw new Error('Sync keys are not ready');
    const created_at = Math.floor(Date.now() / 1000);
    const tags = [['d', `pksync-${this.config.chainId}`]];
    const data = [0, this.nostrPublicKey, created_at, 30078, tags, content];
    const hash = sha256(new TextEncoder().encode(JSON.stringify(data)));
    const sig = await secp256k1.schnorr.signAsync(hash, this.nostrPrivateKey);
    return {
      id: bytesToHex(hash),
      pubkey: this.nostrPublicKey,
      created_at,
      kind: 30078,
      tags,
      content,
      sig: bytesToHex(sig),
    };
  }

  private async encryptMessage(msg: SyncMessage): Promise<string> {
    if (!this.encryptionKey) throw new Error('Encryption key is not ready');
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      new TextEncoder().encode(JSON.stringify(msg))
    );
    return JSON.stringify({ n: bytesToBase64(nonce), c: arrayBufferToBase64(ciphertext) });
  }

  private async decryptMessage(encrypted: string): Promise<SyncMessage | null> {
    if (!this.encryptionKey) return null;
    try {
      const payload = JSON.parse(encrypted);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(payload.n) },
        this.encryptionKey,
        base64ToBytes(payload.c)
      );
      return JSON.parse(new TextDecoder().decode(decrypted));
    } catch {
      return null;
    }
  }

  private async createBundle(): Promise<EncryptedPasskeyBundle> {
    if (!this.encryptionKey) throw new Error('Encryption key is not ready');
    const passkeys = getPasskeys();
    const totpEntries = getTotpEntries();
    const payload = {
      passkeys,
      passkeyIds: passkeys.map((item) => item.id),
      totpEntries,
      totpIds: totpEntries.map((item) => item.id),
      timestamp: Date.now(),
      deviceId: this.config.deviceId,
    };
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      this.encryptionKey,
      new TextEncoder().encode(JSON.stringify(payload))
    );
    return {
      version: '2.0',
      deviceId: this.config.deviceId!,
      timestamp: Date.now(),
      nonce: bytesToBase64(nonce),
      ciphertext: arrayBufferToBase64(ciphertext),
      passkeyCount: passkeys.length,
      totpCount: totpEntries.length,
    };
  }

  private async decryptBundle(bundle: EncryptedPasskeyBundle): Promise<{
    passkeys: StoredPasskey[];
    totpEntries: StoredTotpEntry[];
  }> {
    if (!this.encryptionKey) throw new Error('Encryption key is not ready');
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(bundle.nonce) },
      this.encryptionKey,
      base64ToBytes(bundle.ciphertext)
    );
    const payload = JSON.parse(new TextDecoder().decode(decrypted));
    if (Array.isArray(payload)) return { passkeys: payload, totpEntries: [] };
    return {
      passkeys: payload.passkeys || [],
      totpEntries: payload.totpEntries || [],
    };
  }

  private async handleRelayMessage(raw: string): Promise<void> {
    const parsed = JSON.parse(raw);
    if (parsed[0] !== 'EVENT' || !parsed[2]) return;
    const event = parsed[2];
    if (!event.id || this.processed.has(event.id)) return;
    this.processed.add(event.id);
    const expected = bytesToHex(sha256(new TextEncoder().encode(JSON.stringify([
      0,
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags || [],
      event.content || '',
    ]))));
    if (expected !== event.id) return;
    const ok = await secp256k1.schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey));
    if (!ok) return;
    const msg = await this.decryptMessage(event.content);
    if (!msg || msg.chainId !== this.config.chainId || msg.deviceId === this.config.deviceId) return;
    this.mergeDevice(msg);
    if (msg.type === 'request' && msg.payload.action === 'sync') {
      await this.broadcast({
        type: 'response',
        chainId: this.config.chainId!,
        deviceId: this.config.deviceId!,
        deviceName: this.config.deviceName || undefined,
        deviceType: 'Mobile (Android)',
        timestamp: Date.now(),
        sequence: ++this.sequence,
        payload: {
          requestId: msg.payload.requestId,
          bundle: await this.createBundle(),
        },
      });
    }
    if ((msg.type === 'response' || msg.type === 'update') && msg.payload.bundle) {
      const bundle = await this.decryptBundle(msg.payload.bundle);
      this.mergeVault(bundle.passkeys, bundle.totpEntries, msg.deviceId);
    }
    render();
  }

  private mergeDevice(msg: SyncMessage): void {
    const chain = loadJson<SyncChain | null>(SYNC_DEVICES_KEY, null);
    if (!chain) return;
    const devices = [...chain.devices];
    const index = devices.findIndex((device) => device.id === msg.deviceId);
    const next: SyncDevice = {
      id: msg.deviceId,
      name: msg.deviceName || `Device ${msg.deviceId.slice(0, 8)}`,
      deviceType: msg.deviceType || 'Unknown',
      publicKey: '',
      createdAt: index >= 0 ? devices[index].createdAt : msg.timestamp,
      lastSeen: msg.timestamp,
      isThisDevice: false,
    };
    if (index >= 0) devices[index] = { ...devices[index], ...next };
    else devices.push(next);
    saveJson(SYNC_DEVICES_KEY, { ...chain, devices });
  }

  private mergeVault(passkeys: StoredPasskey[], totpEntries: StoredTotpEntry[], sourceDeviceId: string): void {
    const localPasskeys = new Map(getPasskeys().map((item) => [item.id, item]));
    for (const remote of passkeys) {
      const local = localPasskeys.get(remote.id);
      if (!local || remote.createdAt > local.createdAt) {
        localPasskeys.set(remote.id, { ...remote, syncSource: sourceDeviceId, syncTimestamp: Date.now() });
      }
    }
    const localTotp = new Map(getTotpEntries().map((item) => [item.id, item]));
    for (const remote of totpEntries) {
      const local = localTotp.get(remote.id);
      if (!local || remote.createdAt > local.createdAt) localTotp.set(remote.id, remote);
    }
    setPasskeys(Array.from(localPasskeys.values()));
    setTotpEntries(Array.from(localTotp.values()));
  }
}

async function createSyncChain(form: HTMLFormElement): Promise<void> {
  const data = new FormData(form);
  const deviceName = String(data.get('deviceName') || 'Android phone').trim();
  const mnemonic = await generateMnemonic(12);
  await configureSync(deviceName, mnemonic, true);
  copyText(mnemonic);
  setStatus('Sync chain created. Recovery phrase copied.');
}

async function joinSyncChain(form: HTMLFormElement): Promise<void> {
  const data = new FormData(form);
  const deviceName = String(data.get('deviceName') || 'Android phone').trim();
  const mnemonic = String(data.get('mnemonic') || '').trim().toLowerCase();
  if (!validateMnemonic(mnemonic)) {
    setStatus('Recovery phrase is invalid.', 'bad');
    return;
  }
  await configureSync(deviceName, mnemonic, false);
  await state.sync?.requestSync();
  setStatus('Joined sync chain.');
}

async function configureSync(deviceName: string, mnemonic: string, created: boolean): Promise<void> {
  const seedBytes = mnemonicToBytes(mnemonic);
  const keypair = await deriveEd25519Keypair(seedBytes);
  const seedHash = await sha256Hex(seedBytes);
  const chainId = seedHash.slice(0, 32);
  const syncSalt = localStorage.getItem('android_sync_deterministic_salt') === '1' ? null : randomHex(32);
  const deviceId = uuid();
  const publicKey = bytesToHex(keypair.publicKey);
  const device: SyncDevice = {
    id: deviceId,
    name: deviceName,
    deviceType: 'Mobile (Android)',
    publicKey,
    createdAt: Date.now(),
    lastSeen: Date.now(),
    isThisDevice: true,
  };
  const chain: SyncChain = {
    id: chainId,
    createdAt: Date.now(),
    seedHash,
    devices: [device],
  };
  const config: SyncConfig = {
    enabled: true,
    chainId,
    deviceId,
    deviceName,
    seedHash,
    syncSalt,
  };
  setSyncConfig(config);
  saveJson(SYNC_DEVICES_KEY, chain);
  await bootSync();
  if (created) await state.sync?.broadcastUpdate();
}

async function bootSync(): Promise<void> {
  state.sync?.stop();
  state.sync = null;
  const config = getSyncConfig();
  if (config.enabled) {
    state.sync = new AndroidSync(config);
    await state.sync.start();
  }
}

function leaveSync(): void {
  state.sync?.stop();
  state.sync = null;
  setSyncConfig({
    enabled: false,
    chainId: null,
    deviceId: null,
    deviceName: null,
    seedHash: null,
    syncSalt: null,
  });
  localStorage.removeItem(SYNC_DEVICES_KEY);
  setStatus('Sync disabled.');
}

async function startScanner(): Promise<void> {
  if (!jsQR) {
    setStatus('QR scanner is missing.', 'bad');
    return;
  }
  const video = document.getElementById('qr-video') as HTMLVideoElement | null;
  const canvas = document.getElementById('qr-canvas') as HTMLCanvasElement | null;
  if (!video || !canvas) return;
  let stream: MediaStream | null = null;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    video.srcObject = stream;
    await video.play();
    document.getElementById('qr-scanner')?.classList.remove('hidden');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    let stopped = false;
    state.scannerStop = () => {
      stopped = true;
      stream.getTracks().forEach((track) => track.stop());
      state.scannerStop = null;
      document.getElementById('qr-scanner')?.classList.add('hidden');
    };
    const tick = async () => {
      if (stopped || !ctx || !video.videoWidth) {
        if (!stopped) requestAnimationFrame(tick);
        return;
      }
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(image.data, image.width, image.height);
      if (code?.data) {
        state.scannerStop?.();
        await addTotpFromUri(code.data);
        return;
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  } catch (error) {
    stream?.getTracks().forEach((track) => track.stop());
    state.scannerStop = null;
    setStatus(`Camera failed: ${String(error)}`, 'bad');
  }
}

function stopScanner(): void {
  state.scannerStop?.();
}

function render(): void {
  if (!state.unlocked) {
    app.innerHTML = renderLock();
    bindLock();
    return;
  }

  app.innerHTML = `
    <section class="shell">
      <header class="top">
        <div class="brand">
          <img class="brand-mark" src="icon.png" alt="" aria-hidden="true" />
          <div>
            <h1>Fenko Vault</h1>
            <p class="muted">${getPasskeys().length} passkeys, ${getTotpEntries().length} 2FA codes</p>
          </div>
        </div>
        <button id="lock-btn" class="icon-btn" aria-label="Lock vault" ${canLock() ? '' : 'disabled'}>
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <rect x="4" y="11" width="16" height="10" rx="2"></rect>
            <path d="M8 11V7a4 4 0 0 1 8 0v4"></path>
          </svg>
        </button>
      </header>
      ${state.status ? `<div class="panel ${state.statusKind}">${escapeHtml(state.status)}</div>` : ''}
      <div id="tab-content">${renderTab()}</div>
    </section>
    <div class="bottombar">
      ${
        state.tab === 'vault'
          ? `<div class="search-container">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="11" cy="11" r="8"></circle>
          <path d="m21 21-4.35-4.35"></path>
        </svg>
        <input type="text" id="search-input" class="search-input" placeholder="Search vault"
          autocomplete="off" autocapitalize="off" value="${escapeHtml(state.search)}" />
        <button id="search-clear" class="search-clear" aria-label="Clear search" ${state.search.trim() ? '' : 'hidden'}>&times;</button>
      </div>`
          : ''
      }
      <nav class="tabs">
        ${tabButton('vault', 'Vault')}
        ${tabButton('add', 'Add')}
        ${tabButton('sync', 'Sync')}
        ${tabButton('tools', 'Tools')}
      </nav>
    </div>
  `;
  bindCommon();
  bindTabContent();
}

function bindTabContent(): void {
  if (state.tab === 'vault') bindVault();
  if (state.tab === 'add') bindAdd();
  if (state.tab === 'sync') bindSync();
  if (state.tab === 'tools') bindTools();
}

function updateTabContent(): void {
  const content = document.getElementById('tab-content');
  if (!content) return;
  content.innerHTML = renderTab();
  bindTabContent();
}

function tabButton(tab: Tab, label: string): string {
  return `<button class="${state.tab === tab ? 'active' : ''}" data-tab="${tab}">${label}</button>`;
}

function renderTab(): string {
  if (state.tab === 'vault') return renderVault();
  if (state.tab === 'add') return renderAdd();
  if (state.tab === 'sync') return renderSync();
  return renderTools();
}

function matchesSearch(parts: Array<string | null | undefined>): boolean {
  const query = state.search.trim().toLowerCase();
  if (!query) return true;
  return parts.filter(Boolean).join(' ').toLowerCase().includes(query);
}

function renderVault(): string {
  const searching = Boolean(state.search.trim());
  const totp = getTotpEntries()
    .filter((entry) => matchesSearch([entry.issuer, entry.account]))
    .sort((a, b) =>
      (a.issuer || a.account || '').toLowerCase().localeCompare((b.issuer || b.account || '').toLowerCase())
    );
  const passkeys = getPasskeys()
    .filter((passkey) => matchesSearch([passkey.rpId, passkey.user?.name, passkey.user?.displayName]))
    .sort((a, b) => a.rpId.toLowerCase().localeCompare(b.rpId.toLowerCase()));
  return `
    <section class="grid">
      <div>
        <h2>2FA codes</h2>
        <div class="stack">
          ${
            totp.length
              ? totp.map(renderTotpItem).join('')
              : `<div class="panel muted">${searching ? 'No matching 2FA codes.' : 'No 2FA codes yet.'}</div>`
          }
        </div>
      </div>
      <div>
        <h2>Passkeys</h2>
        <div class="stack">
          ${
            passkeys.length
              ? passkeys.map(renderPasskeyItem).join('')
              : `<div class="panel muted">${searching ? 'No matching passkeys.' : 'No passkeys yet.'}</div>`
          }
        </div>
      </div>
    </section>
  `;
}

function renderTotpItem(entry: StoredTotpEntry): string {
  const { code, remaining } = codeFor(entry);
  const width = Math.max(2, (remaining / (entry.period || 30)) * 100);
  const expanded = state.expanded.has(entry.id);
  return `
    <article class="item totp-card" data-item-kind="totp" data-item-id="${escapeHtml(entry.id)}" data-expand="${escapeHtml(entry.id)}">
      <div class="item-head">
        <div class="totp-text">
          <h3>${escapeHtml(entry.issuer || 'Unknown issuer')}</h3>
          <p class="muted">${escapeHtml(entry.account || '')}</p>
        </div>
        <button class="code code-compact" data-copy="${escapeHtml(code)}">${code}</button>
      </div>
      <div class="progress"><div style="width:${width}%"></div></div>
      ${
        expanded
          ? `<div class="totp-details">
        <p class="muted">${entry.type.toUpperCase()} &middot; ${entry.algorithm} &middot; ${entry.digits} digits &middot; ${entry.period}s period &middot; ${remaining}s left</p>
        <p class="muted">Added ${new Date(entry.createdAt).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}</p>
        <button data-copy="${escapeHtml(code)}">Copy code</button>
      </div>`
          : ''
      }
    </article>
  `;
}

function renderPasskeyItem(passkey: StoredPasskey): string {
  const account = passkey.user?.name || passkey.user?.displayName || 'Unknown account';
  const created = passkey.createdAt
    ? new Date(passkey.createdAt).toLocaleDateString(undefined, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      })
    : null;
  const uses =
    passkey.counter === 0 ? 'not used yet' : passkey.counter === 1 ? 'used once' : `used ${passkey.counter} times`;
  return `
    <article class="item passkey-card" data-item-kind="passkey" data-item-id="${escapeHtml(passkey.id)}">
      <div class="item-head">
        <div class="passkey-glyph" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="7.5" cy="15.5" r="5.5"></circle>
            <path d="m21 2-9.6 9.6"></path>
            <path d="m15.5 7.5 3 3L22 7l-3-3"></path>
          </svg>
        </div>
        <div class="passkey-text">
          <h3>${escapeHtml(passkey.rpId)}</h3>
          <p class="muted">${escapeHtml(account)}</p>
        </div>
      </div>
      <p class="muted passkey-meta">${created ? `Created ${escapeHtml(created)} &middot; ` : ''}${uses}</p>
    </article>
  `;
}

function renderAdd(): string {
  return `
    <section class="grid">
      <form id="totp-uri-form" class="panel stack">
        <h2>Add 2FA by URI</h2>
        <textarea name="uri" placeholder="otpauth://totp/..."></textarea>
        <div class="row">
          <button class="primary" type="submit">Add URI</button>
          <button type="button" id="scan-qr">Scan QR</button>
        </div>
        <div id="qr-scanner" class="scanner hidden">
          <video id="qr-video" playsinline muted></video>
          <canvas id="qr-canvas" class="hidden"></canvas>
          <button type="button" id="stop-qr">Stop camera</button>
        </div>
      </form>
      <form id="totp-manual-form" class="panel stack">
        <h2>Add 2FA manually</h2>
        <input name="issuer" placeholder="Issuer" />
        <input name="account" placeholder="Account" />
        <input name="secret" placeholder="Base32 secret" />
        <div class="row">
          <select name="algorithm">
            <option>SHA1</option>
            <option>SHA256</option>
            <option>SHA512</option>
          </select>
          <input name="digits" type="number" value="6" min="6" max="10" />
        </div>
        <div class="row">
          <select name="type">
            <option value="totp">TOTP</option>
            <option value="hotp">HOTP</option>
          </select>
          <input name="period" type="number" value="30" min="1" />
          <input name="counter" type="number" value="0" min="0" />
        </div>
        <button class="primary" type="submit">Add code</button>
      </form>
    </section>
  `;
}

function renderSync(): string {
  const config = getSyncConfig();
  const chain = loadJson<SyncChain | null>(SYNC_DEVICES_KEY, null);
  const connected = state.sync?.connected;
  const relays = getRelays();
  return `
    <section class="grid">
      <div class="panel stack">
        <h2>Current sync</h2>
        <p class="muted">${config.enabled ? 'Enabled' : 'Off'} ${connected ? 'and connected' : ''}</p>
        <p class="small-code">${escapeHtml(config.chainId || 'No chain')}</p>
        <div class="row">
          <button id="sync-now" ${config.enabled ? '' : 'disabled'}>Sync now</button>
          <button class="danger" id="leave-sync" ${config.enabled ? '' : 'disabled'}>Leave</button>
        </div>
        <div class="stack">
          ${
            chain?.devices?.length
              ? chain.devices
                  .map(
                    (device) => `
                      <div class="item">
                        <h3>${escapeHtml(device.name)}</h3>
                        <p class="muted">${escapeHtml(device.deviceType)} ${device.isThisDevice ? '(this device)' : ''}</p>
                      </div>
                    `
                  )
                  .join('')
              : '<p class="muted">No devices listed.</p>'
          }
        </div>
      </div>
      <form id="create-sync-form" class="panel stack">
        <h2>Create chain</h2>
        <input name="deviceName" value="Android phone" />
        <button class="primary" type="submit">Create and copy phrase</button>
      </form>
      <form id="join-sync-form" class="panel stack">
        <h2>Join chain</h2>
        <input name="deviceName" value="Android phone" />
        <textarea name="mnemonic" placeholder="12-word recovery phrase"></textarea>
        <button class="primary" type="submit">Join</button>
      </form>
      <div class="panel stack">
        <h2>Compatibility</h2>
        <p class="muted">Default mode matches the extension's current salt field. Deterministic mode is useful for Android-to-Android tests.</p>
        <label class="row">
          <input id="deterministic-salt" type="checkbox" ${localStorage.getItem('android_sync_deterministic_salt') === '1' ? 'checked' : ''} />
          <span>Use deterministic sync salt</span>
        </label>
      </div>
      <div class="panel stack">
        <h2>Relays</h2>
        <textarea id="relay-list" spellcheck="false">${escapeHtml(relays.join('\n'))}</textarea>
        <button id="save-relays">Save relays</button>
      </div>
    </section>
  `;
}

function renderTools(): string {
  return `
    <section class="grid">
      <div class="panel stack">
        <h2>Auto-lock</h2>
        <p class="muted">Locks the vault after inactivity. Unlocking uses your device's face, fingerprint, or screen lock.</p>
        <select id="autolock-minutes">
          ${[
            [0, 'Never'],
            [1, 'After 1 minute'],
            [5, 'After 5 minutes'],
            [15, 'After 15 minutes'],
            [30, 'After 30 minutes'],
          ]
            .map(
              ([value, label]) =>
                `<option value="${value}" ${autoLockMinutes() === value ? 'selected' : ''}>${label}</option>`
            )
            .join('')}
        </select>
      </div>
      <div class="panel stack">
        <h2>Backup</h2>
        <button id="export-encrypted-vault">Copy encrypted backup</button>
        <button id="export-vault">Copy backup JSON</button>
        <textarea id="import-json" placeholder="Paste backup JSON"></textarea>
        <button class="primary" id="import-vault">Import backup</button>
      </div>
      <div class="panel stack">
        <h2>Recycle bin</h2>
        <p class="muted">Deleted items are kept for 7 days, then removed for good. Long-press a vault item to delete it.</p>
        <div class="stack">
          ${
            getRecycleBin().length
              ? getRecycleBin()
                  .map((entry, index) => {
                    const daysLeft = Math.max(
                      1,
                      Math.ceil((entry.deletedAt + RECYCLE_TTL_MS - Date.now()) / (24 * 60 * 60 * 1000))
                    );
                    return `
                      <div class="item">
                        <h3>${escapeHtml(recycleLabel(entry))}</h3>
                        <p class="muted">${entry.kind === 'passkey' ? 'Passkey' : '2FA code'} &middot; gone in ${daysLeft}d</p>
                        <div class="row">
                          <button data-restore-bin="${index}">Restore</button>
                          <button class="danger" data-purge-bin="${index}">Delete now</button>
                        </div>
                      </div>
                    `;
                  })
                  .join('')
              : '<div class="item muted">Empty.</div>'
          }
        </div>
      </div>
      <div class="panel stack">
        <h2>Danger</h2>
        <button class="danger" id="wipe-vault">Wipe local vault</button>
      </div>
      <div class="panel stack about">
        <div class="brand">
          <img class="brand-mark" src="icon.png" alt="" aria-hidden="true" />
          <div>
            <h2 class="about-title">Fenko Vault</h2>
            <p class="muted">Version ${escapeHtml(__APP_VERSION__)} &middot; Fenko Limited, New Zealand</p>
          </div>
        </div>
        <p class="muted">
          Fenko Vault is a free, open-source project, offered by Fenko Limited to help the community
          manage passkeys and 2FA codes. The source code is MIT licensed &mdash; you can read it, audit it,
          and build it yourself.
        </p>
        <p class="muted">
          Your vault lives on this device. Optional sync sends only end-to-end encrypted bundles
          through the relays you choose &mdash; Fenko runs no server that can read your secrets.
          No analytics, no tracking.
        </p>
        <h3>No warranty</h3>
        <p class="muted">
          This software is provided &ldquo;as is&rdquo;, without warranty of any kind, express or implied,
          including merchantability, fitness for a particular purpose, and non-infringement. It is not a
          commercial service and comes with no support obligation, no uptime promise, and no guarantee
          against data loss. You use it at your own risk. To the maximum extent permitted by New Zealand
          law, Fenko Limited is not liable for any loss or damage arising from its use.
        </p>
        <nav class="link-list">
          <a href="https://fenko.nz/about">About Fenko</a>
          <a href="https://fenko.nz/contact">Contact</a>
          <a href="mailto:security@fenko.nz">security@fenko.nz</a>
          <a href="https://fenko.nz/terms-conditions">Terms of Service</a>
          <a href="https://fenko.nz/privacy-policy">Privacy Policy</a>
        </nav>
        <p class="muted">
          Built with open source: Saira (SIL OFL 1.1), jsQR, and noble cryptography (MIT).
          Fenko Vault source is MIT licensed.
        </p>
      </div>
    </section>
  `;
}

function renderLock(): string {
  return `
    <section class="lock">
      <img class="mark" src="icon.png" alt="" />
      <h1>Vault locked</h1>
      ${state.status ? `<div class="panel ${state.statusKind}">${escapeHtml(state.status)}</div>` : ''}
      <button class="primary" id="biometric-unlock-btn">Unlock</button>
    </section>
  `;
}

function bindCommon(): void {
  document.querySelectorAll<HTMLElement>('[data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      stopScanner();
      state.tab = button.dataset.tab as Tab;
      render();
    });
  });
  document.getElementById('lock-btn')?.addEventListener('click', lockVault);

  const searchInput = document.getElementById('search-input') as HTMLInputElement | null;
  searchInput?.addEventListener('input', () => {
    state.search = searchInput.value;
    document.getElementById('search-clear')?.toggleAttribute('hidden', !searchInput.value.trim());
    updateTabContent();
  });
  document.getElementById('search-clear')?.addEventListener('click', () => {
    state.search = '';
    if (searchInput) searchInput.value = '';
    document.getElementById('search-clear')?.setAttribute('hidden', '');
    updateTabContent();
    searchInput?.focus();
  });
}

let longPressFired = false;

function bindLongPress(el: HTMLElement, onLongPress: () => void): void {
  let timer = 0;
  let startX = 0;
  let startY = 0;
  el.addEventListener('pointerdown', (event) => {
    if ((event.target as HTMLElement).closest('button')) return;
    startX = event.clientX;
    startY = event.clientY;
    longPressFired = false;
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      longPressFired = true;
      navigator.vibrate?.(40);
      onLongPress();
    }, 600);
  });
  const cancel = () => window.clearTimeout(timer);
  el.addEventListener('pointerup', cancel);
  el.addEventListener('pointercancel', cancel);
  el.addEventListener('pointerleave', cancel);
  el.addEventListener('pointermove', (event) => {
    if (Math.abs(event.clientX - startX) > 12 || Math.abs(event.clientY - startY) > 12) cancel();
  });
}

function bindVault(): void {
  document.querySelectorAll<HTMLElement>('[data-copy]').forEach((button) => {
    button.addEventListener('click', () => copyText(button.dataset.copy || ''));
  });
  document.querySelectorAll<HTMLElement>('[data-item-kind]').forEach((item) => {
    bindLongPress(item, () => {
      void requestDelete(item.dataset.itemKind as 'passkey' | 'totp', item.dataset.itemId || '');
    });
  });
  document.querySelectorAll<HTMLElement>('[data-expand]').forEach((card) => {
    card.addEventListener('click', (event) => {
      if (longPressFired || (event.target as HTMLElement).closest('button')) return;
      const id = card.dataset.expand || '';
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      updateTabContent();
    });
  });
}

function bindAdd(): void {
  document.getElementById('totp-uri-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const uri = String(new FormData(form).get('uri') || '');
    void addTotpFromUri(uri).catch((error) => setStatus(String(error), 'bad'));
  });
  document.getElementById('totp-manual-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    void addTotpManual(event.currentTarget as HTMLFormElement).catch((error) => setStatus(String(error), 'bad'));
  });
  document.getElementById('scan-qr')?.addEventListener('click', () => void startScanner());
  document.getElementById('stop-qr')?.addEventListener('click', stopScanner);
}

function bindSync(): void {
  document.getElementById('create-sync-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    void createSyncChain(event.currentTarget as HTMLFormElement).catch((error) => setStatus(String(error), 'bad'));
  });
  document.getElementById('join-sync-form')?.addEventListener('submit', (event) => {
    event.preventDefault();
    void joinSyncChain(event.currentTarget as HTMLFormElement).catch((error) => setStatus(String(error), 'bad'));
  });
  document.getElementById('sync-now')?.addEventListener('click', () =>
    void state.sync?.requestSync().then(() => setStatus('Sync requested.'))
  );
  document.getElementById('leave-sync')?.addEventListener('click', leaveSync);
  document.getElementById('deterministic-salt')?.addEventListener('change', (event) => {
    const checked = (event.currentTarget as HTMLInputElement).checked;
    if (checked) localStorage.setItem('android_sync_deterministic_salt', '1');
    else localStorage.removeItem('android_sync_deterministic_salt');
  });
  document.getElementById('save-relays')?.addEventListener('click', () => {
    const raw = (document.getElementById('relay-list') as HTMLTextAreaElement).value;
    setRelays(raw);
  });
}

function bindTools(): void {
  document.querySelectorAll<HTMLElement>('[data-restore-bin]').forEach((button) => {
    button.addEventListener('click', () => {
      restoreFromBin(Number(button.dataset.restoreBin));
      render();
    });
  });
  document.querySelectorAll<HTMLElement>('[data-purge-bin]').forEach((button) => {
    button.addEventListener('click', () => void purgeFromBin(Number(button.dataset.purgeBin)));
  });
  document.getElementById('autolock-minutes')?.addEventListener('change', (event) => {
    const minutes = (event.currentTarget as HTMLSelectElement).value;
    localStorage.setItem(AUTOLOCK_KEY, minutes);
    setStatus(minutes === '0' ? 'Auto-lock off.' : `Auto-lock after ${minutes} min.`);
  });
  document
    .getElementById('export-encrypted-vault')
    ?.addEventListener('click', () => void exportEncryptedVault().catch((error) => setStatus(String(error), 'bad')));
  document.getElementById('export-vault')?.addEventListener('click', exportVault);
  document.getElementById('import-vault')?.addEventListener('click', () => {
    const raw = (document.getElementById('import-json') as HTMLTextAreaElement).value;
    void importVault(raw).catch((error) => setStatus(String(error), 'bad'));
  });
  document.getElementById('wipe-vault')?.addEventListener('click', () => {
    if (!confirm('Wipe all local vault data?')) return;
    localStorage.clear();
    mirrorVaultToAndroid();
    state.sync?.stop();
    state.sync = null;
    setStatus('Vault wiped.', 'warn');
  });
}

function bindLock(): void {
  document.getElementById('biometric-unlock-btn')?.addEventListener('click', startBiometricUnlock);
}

function setupPullToRefresh(): void {
  const indicator = document.createElement('div');
  indicator.className = 'ptr hidden';
  document.body.appendChild(indicator);
  const THRESHOLD = 80;
  let startY = 0;
  let active = false;
  let armed = false;

  document.addEventListener(
    'touchstart',
    (event) => {
      active = state.unlocked && window.scrollY <= 0;
      armed = false;
      if (active) startY = event.touches[0].clientY;
    },
    { passive: true }
  );
  document.addEventListener(
    'touchmove',
    (event) => {
      if (!active) return;
      const delta = event.touches[0].clientY - startY;
      if (delta > 24 && window.scrollY <= 0) {
        armed = delta > THRESHOLD;
        indicator.textContent = armed ? 'Release to sync' : 'Pull to sync';
        indicator.classList.remove('hidden');
      } else {
        armed = false;
        indicator.classList.add('hidden');
      }
    },
    { passive: true }
  );
  document.addEventListener(
    'touchend',
    () => {
      if (!active) return;
      active = false;
      if (!armed) {
        indicator.classList.add('hidden');
        return;
      }
      indicator.textContent = 'Syncing…';
      void (async () => {
        try {
          if (state.sync) {
            await state.sync.requestSync();
            setStatus('Sync requested.');
          } else {
            setStatus('Refreshed.');
          }
        } catch (error) {
          setStatus(String(error), 'bad');
        } finally {
          indicator.classList.add('hidden');
          render();
        }
      })();
    },
    { passive: true }
  );
}

let pointerDown = false;

async function boot(): Promise<void> {
  localStorage.removeItem(LEGACY_LOCK_KEY);
  purgeRecycleBin();
  mergeNativeSnapshot();
  state.unlocked = !localStorage.getItem(LOCKED_FLAG_KEY);
  if (state.unlocked) await bootSync();
  render();
  mirrorVaultToAndroid();
  setupPullToRefresh();
  document.addEventListener(
    'pointerdown',
    () => {
      pointerDown = true;
      touchActivity();
    },
    { passive: true }
  );
  document.addEventListener('pointerup', () => (pointerDown = false), { passive: true });
  document.addEventListener('pointercancel', () => (pointerDown = false), { passive: true });
  document.addEventListener('keydown', touchActivity, { passive: true });
  window.setInterval(() => {
    maybeAutoLock();
    // Re-rendering mid-press would destroy the card under a long-press.
    if (state.unlocked && state.tab === 'vault' && !pointerDown) updateTabContent();
  }, 1000);
}

void boot().catch((error) => {
  app.innerHTML = `<section class="lock"><h1>Boot failed</h1><pre>${escapeHtml(String(error))}</pre></section>`;
});
