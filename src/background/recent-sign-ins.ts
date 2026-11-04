/**
 * The passkeys the vault signed with in the last few minutes, by site.
 *
 * The vault never learns whether a site accepted a sign-in. A second sign-in
 * with the same passkey on the same site soon after the first is the best
 * sign that the site refused it, so the picker uses this list to offer the
 * likeliest fix (see VaultDialogPasskey.retry).
 *
 * Kept in chrome.storage.session: it outlives a service worker restart
 * between the two attempts, content scripts cannot read it, and it is gone
 * when the browser closes.
 */

const STORAGE_KEY = 'recent_sign_ins';

/** How long after a sign-in another one with the same passkey counts as a retry. */
export const RETRY_WINDOW_MS = 3 * 60 * 1000;

type SignIns = Record<string, { rpId: string; at: number }>;

let memory: SignIns = {};

function area(): chrome.storage.StorageArea | null {
  return (chrome.storage as { session?: chrome.storage.StorageArea }).session ?? null;
}

async function load(now: number): Promise<SignIns> {
  const storage = area();
  const stored = storage
    ? ((await storage.get(STORAGE_KEY))[STORAGE_KEY] as SignIns | undefined)
    : memory;
  const fresh: SignIns = {};
  for (const [id, entry] of Object.entries(stored ?? {})) {
    if (entry && typeof entry.at === 'number' && now - entry.at < RETRY_WINDOW_MS) {
      fresh[id] = entry;
    }
  }
  return fresh;
}

/** Record that the vault signed with `passkeyId` for `rpId`. */
export async function noteSignIn(passkeyId: string, rpId: string, now = Date.now()): Promise<void> {
  const signIns = await load(now);
  signIns[passkeyId] = { rpId, at: now };
  const storage = area();
  if (storage) await storage.set({ [STORAGE_KEY]: signIns });
  else memory = signIns;
}

/** The passkeys signed with for `rpId` within RETRY_WINDOW_MS. */
export async function recentSignIns(rpId: string, now = Date.now()): Promise<Set<string>> {
  const signIns = await load(now);
  return new Set(
    Object.entries(signIns)
      .filter(([, entry]) => entry.rpId === rpId)
      .map(([id]) => id)
  );
}
