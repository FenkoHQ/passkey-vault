/**
 * The real background service and secure storage against an in-memory
 * chrome.storage.local, for the master PIN tests. The test file must stub the
 * relay-facing sync service itself (jest.mock('../src/sync/sync-service')),
 * since jest.mock is hoisted per file.
 */

export type StorageData = Record<string, unknown>;
export type Reply = { success: boolean; [field: string]: unknown };
export type Respond = (message: Record<string, unknown>) => Promise<Reply>;
type SecureStorageModule = typeof import('../../src/crypto/secure-storage');
export type SyncServiceModule = { syncService: Record<string, jest.Mock> };

// jsdom has no structuredClone; stored values are all JSON.
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value));

/** Back chrome.storage.local with a plain object, honouring every key form. */
export function useFakeStorage(): StorageData {
  const data: StorageData = {};
  const keysOf = (keys: unknown): string[] =>
    keys == null ? Object.keys(data) : Array.isArray(keys) ? keys : [keys as string];
  const local = chrome.storage.local as unknown as Record<string, jest.Mock>;
  local.get.mockReset().mockImplementation(async (keys: unknown) => {
    const result: StorageData = {};
    for (const key of keysOf(keys)) {
      if (data[key] !== undefined) result[key] = clone(data[key]);
    }
    return result;
  });
  local.set.mockReset().mockImplementation(async (items: StorageData) => {
    for (const [key, value] of Object.entries(items)) data[key] = clone(value);
  });
  local.remove.mockReset().mockImplementation(async (keys: unknown) => {
    for (const key of keysOf(keys)) delete data[key];
  });
  local.clear.mockReset().mockImplementation(async () => {
    for (const key of Object.keys(data)) delete data[key];
  });
  return data;
}

/**
 * Load a fresh background service (and its secure storage singleton) and
 * return a function that sends it a runtime message. Loading again stands in
 * for a restarted service worker.
 */
export async function loadBackground(): Promise<{
  send: Respond;
  secure: SecureStorageModule['secureStorage'];
  sync: SyncServiceModule['syncService'];
}> {
  const runtime = chrome.runtime as unknown as Record<string, unknown>;
  const listeners: Array<(m: unknown, s: unknown, r: (v: unknown) => void) => void> = [];
  runtime.onMessage = { addListener: (fn: (typeof listeners)[number]) => listeners.push(fn) };
  for (const event of ['onInstalled', 'onStartup', 'onSuspend']) {
    runtime[event] = { addListener: jest.fn() };
  }

  let secure!: SecureStorageModule['secureStorage'];
  let sync!: SyncServiceModule['syncService'];
  await jest.isolateModulesAsync(async () => {
    await import('../../src/background/background');
    secure = (await import('../../src/crypto/secure-storage')).secureStorage;
    sync = ((await import('../../src/sync/sync-service')) as unknown as SyncServiceModule)
      .syncService;
  });

  // Chrome's account of a message from the popup, an extension page.
  const popup = { id: chrome.runtime.id, url: chrome.runtime.getURL('popup.html') };
  const send: Respond = (message) =>
    new Promise((resolve) => listeners[0](message, popup, (v) => resolve(v as Reply)));
  return { send, secure, sync };
}

/** Lock, then report whether the given PIN unlocks the vault. */
export async function unlocksWith(send: Respond, pin: string): Promise<boolean> {
  await send({ type: 'LOCK_SECURE_STORAGE' });
  return (await send({ type: 'UNLOCK_SECURE_STORAGE', payload: { password: pin } })).success;
}
