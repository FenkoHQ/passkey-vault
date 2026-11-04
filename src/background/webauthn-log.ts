// The WebAuthn event log on the Developer page: a diagnostic record of
// passkey operations, kept only while the user has debug logging on.
//
// Which sites the user signs in to, and with which credential, is vault
// data: with a PIN set it otherwise exists only inside the encrypted vault.
// So the log never touches disk. It lives in chrome.storage.session, which
// is memory-only, cleared when the browser quits and unreadable by content
// scripts at its default access level, and it survives the service worker
// stopping in between. Firefox before 115 has no session storage; there the
// log is held by the worker itself and lasts only as long as the worker.
// The background also clears it when the vault locks or debug logging is
// turned off, and refuses to read it out while the vault is locked.

import { logger } from '../utils/logger';

/** Also the key older builds wrote to chrome.storage.local. */
export const WEBAUTHN_LOG_KEY = 'webauthn_log';
const MAX_ENTRIES = 200;

export interface WebAuthnLogEntry {
  timestamp: number;
  level: 'info' | 'warn' | 'error';
  category: string;
  message: string;
  /** The RP ID and credential ID, never the account name. */
  data?: { rpId?: string; credentialId?: string; [key: string]: unknown };
}

let memoryLog: WebAuthnLogEntry[] = [];
// Appends are read/modify/write; serialize them so two ceremonies finishing
// together cannot drop each other's entry.
let queue: Promise<unknown> = Promise.resolve();

function sessionArea(): chrome.storage.StorageArea | null {
  return typeof chrome !== 'undefined' && chrome.storage?.session ? chrome.storage.session : null;
}

function serialize<T>(job: () => Promise<T>): Promise<T> {
  const result = queue.then(job);
  queue = result.catch(() => undefined);
  return result;
}

async function readEntries(): Promise<WebAuthnLogEntry[]> {
  const area = sessionArea();
  if (!area) return [...memoryLog];
  const stored = (await area.get(WEBAUTHN_LOG_KEY))[WEBAUTHN_LOG_KEY];
  return Array.isArray(stored) ? stored : [];
}

/**
 * Record a passkey operation, if the user has turned debug logging on.
 * Never throws: a failed log write must not fail the ceremony.
 */
export async function appendWebAuthnLog(entry: Omit<WebAuthnLogEntry, 'timestamp'>): Promise<void> {
  try {
    await logger.init();
    if (!logger.isDebugEnabled()) return;
    await serialize(async () => {
      const entries = await readEntries();
      entries.push({ timestamp: Date.now(), ...entry });
      const kept = entries.slice(-MAX_ENTRIES);
      const area = sessionArea();
      if (area) {
        await area.set({ [WEBAUTHN_LOG_KEY]: kept });
      } else {
        memoryLog = kept;
      }
    });
  } catch {
    // Diagnostics only.
  }
}

export function readWebAuthnLog(): Promise<WebAuthnLogEntry[]> {
  return serialize(readEntries);
}

export function clearWebAuthnLog(): Promise<void> {
  return serialize(async () => {
    memoryLog = [];
    await sessionArea()?.remove(WEBAUTHN_LOG_KEY);
  });
}

/**
 * Remove the log that builds before this one kept in chrome.storage.local,
 * whatever the debug setting: it was written for every user, unencrypted.
 */
export async function removeStoredWebAuthnLog(): Promise<void> {
  await chrome.storage.local.remove(WEBAUTHN_LOG_KEY);
}
