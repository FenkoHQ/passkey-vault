/**
 * TOTP entry storage.
 *
 * Mirrors the passkey storage pattern: writes to raw `chrome.storage.local`
 * for UI display, and to `secureStorage` (encrypted) when the vault is
 * unlocked. Falls back to raw storage when secure storage is not in use.
 */

import { secureStorage } from './secure-storage';
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
  const result = await chrome.storage.local.get(TOTP_STORAGE_KEY);
  return (result[TOTP_STORAGE_KEY] || []) as StoredTotpEntry[];
}

export async function saveTotpEntries(entries: StoredTotpEntry[]): Promise<void> {
  await chrome.storage.local.set({ [TOTP_STORAGE_KEY]: entries });
  if (isUnlocked()) {
    await secureStorage.storeTotpEntries(entries as unknown as Record<string, unknown>[]);
  }
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
