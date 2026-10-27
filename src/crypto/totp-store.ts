/**
 * TOTP entry storage.
 *
 * Mirrors the passkey storage pattern: writes to raw `chrome.storage.local`
 * for UI display, and to `secureStorage` (encrypted) when the vault is
 * unlocked. Falls back to raw storage when secure storage is not in use.
 */

import { secureStorage } from './secure-storage';
import { generateHotp } from './totp';
import { arrayBufferToBase64, base64ToUint8Array } from '../utils/base64';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface StoredTotpEntry {
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

export const TOTP_STORAGE_KEY = 'totp_entries';

function isUnlocked(): boolean {
  return secureStorage.isStorageUnlocked();
}

export async function loadTotpEntries(): Promise<StoredTotpEntry[]> {
  if (isUnlocked()) {
    const entries = (await secureStorage.getTotpEntries()) as unknown as StoredTotpEntry[];
    return entries;
  }
  if (await secureStorage.isSetup()) {
    throw new Error('Secure storage is locked. Please unlock with master password.');
  }
  const result = await chrome.storage.local.get(TOTP_STORAGE_KEY);
  return (result[TOTP_STORAGE_KEY] || []) as StoredTotpEntry[];
}

export async function saveTotpEntries(entries: StoredTotpEntry[]): Promise<void> {
  if (isUnlocked()) {
    await secureStorage.storeTotpEntries(entries as unknown as Record<string, unknown>[]);
    return;
  }
  if (await secureStorage.isSetup()) {
    throw new Error('Secure storage is locked. Please unlock with master password.');
  }
  await chrome.storage.local.set({ [TOTP_STORAGE_KEY]: entries });
}

export async function addTotpEntry(entry: StoredTotpEntry): Promise<void> {
  const entries = await loadTotpEntries();
  const existingIndex = entries.findIndex((e) => e.id === entry.id);
  if (existingIndex >= 0) {
    entries[existingIndex] = entry;
  } else {
    entries.push(entry);
  }
  await saveTotpEntries(entries);
}

export async function deleteTotpEntry(id: string): Promise<boolean> {
  const entries = await loadTotpEntries();
  const filtered = entries.filter((e) => e.id !== id);
  if (filtered.length < entries.length) {
    await saveTotpEntries(filtered);
    return true;
  }
  return false;
}

/**
 * Issue the next code for an HOTP entry (RFC 4226 section 7.2): generate the
 * code for the stored counter, then persist counter + 1 so the next request
 * yields a fresh code. The stored counter is the next unused value, which is
 * what an otpauth `counter` parameter means. Only call this on an explicit
 * user request: every call consumes a counter value. Callers must serialize
 * it with other vault writes. Returns null when no entry has that id.
 */
export async function issueHotpCode(
  id: string,
  now: number = Date.now()
): Promise<{ code: string; counter: number; entry: StoredTotpEntry } | null> {
  const entries = await loadTotpEntries();
  const index = entries.findIndex((e) => e.id === id);
  if (index < 0) return null;
  const current = entries[index];
  if (current.type !== 'hotp') {
    throw new Error('Not an HOTP entry');
  }
  const counter = current.counter || 0;
  const code = generateHotp({
    secret: entryToSecretBytes(current),
    algorithm: current.algorithm,
    digits: current.digits,
    counter,
  });
  // The counter is merged by max during sync, independent of record
  // revisions, so it is not an edit: updatedAt stays put and a deletion made
  // on another device still wins.
  const entry: StoredTotpEntry = { ...current, counter: counter + 1, lastUsed: now };
  entries[index] = entry;
  await saveTotpEntries(entries);
  return { code, counter, entry };
}

export function entryToSecretBytes(entry: StoredTotpEntry): Uint8Array {
  return base64ToUint8Array(entry.secretB64);
}

export function secretBytesToEntry(
  secret: Uint8Array,
  fields: Omit<StoredTotpEntry, 'secretB64'>
): StoredTotpEntry {
  return { ...fields, secretB64: arrayBufferToBase64(secret.buffer as ArrayBuffer) };
}

export function generateTotpId(): string {
  return crypto.randomUUID();
}
