/**
 * One-time cleanup after a device moves from sync protocol v4 to v5, shared
 * by the extension and the mobile apps.
 *
 * Every v4 event carried the v4 chain ID, a prefix of SHA-256 of the phrase,
 * in its tags: a one-hash check for a guessed phrase. Once a device has moved
 * to its v5 chain ID it asks each relay to delete its own v4 events (NIP-09),
 * signed with the v4 key that published them. Relays may ignore the request
 * or keep copies elsewhere, so this narrows the exposure; it cannot undo it.
 */

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  LEGACY_CLEANUP_KEY,
  LEGACY_SYNC_EVENT_PREFIX,
  LEGACY_SYNC_KEY_PREFIX,
  NOSTR_EVENT_KIND,
} from './protocol';
import { legacyChainId } from './chain-keys';

export { LEGACY_CLEANUP_KEY };
export const NOSTR_DELETION_KIND = 5;
export const MAX_CLEANUP_ATTEMPTS = 3;
const RELAY_TIMEOUT_MS = 15000;
const QUERY_TIMEOUT_MS = 5000;
const MAX_QUERY_EVENTS = 500;
// About 170 bytes per tag keeps a deletion well inside a 16 KiB relay message.
const TARGETS_PER_DELETION = 60;

/**
 * A device's cleanup, written before its stored chain ID changes. It names the
 * v5 chain, never the v4 ID: that would leave the cheap check in storage.
 */
export interface LegacyCleanup {
  chainId: string;
  deviceId: string;
  attempts: number;
  done: boolean;
}

export interface SignedEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export function pendingLegacyCleanup(chainId: string, deviceId: string): LegacyCleanup {
  return { chainId, deviceId, attempts: 0, done: false };
}

/**
 * The record to store before the next attempt, counting it, or null when this
 * device on this chain has nothing left to clean up.
 */
export function nextLegacyCleanup(
  stored: unknown,
  chainId: string | null,
  deviceId: string | null
): LegacyCleanup | null {
  const record = stored as Partial<LegacyCleanup> | null | undefined;
  if (
    !record ||
    record.done !== false ||
    record.chainId !== chainId ||
    record.deviceId !== deviceId ||
    !Number.isInteger(record.attempts) ||
    record.attempts >= MAX_CLEANUP_ATTEMPTS
  ) {
    return null;
  }
  return { ...(record as LegacyCleanup), attempts: record.attempts + 1 };
}

/** The v4 signing key, exactly as v4 derived it. */
async function deriveLegacyNostrKey(seedHash: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const material = await crypto.subtle.importKey('raw', encoder.encode(seedHash), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(`${LEGACY_SYNC_KEY_PREFIX}-${legacyChainId(seedHash)}-nostr`),
      iterations: 100000,
      hash: 'SHA-256',
    },
    material,
    256
  );
  return new Uint8Array(bits);
}

/**
 * What one deletion request names: this device's v4 snapshot addresses and
 * the chain's shared presence address, whether or not the relay listed them,
 * plus the ID of every such event it did list. Other devices' snapshots stay;
 * a device still on v4 needs them.
 */
export function legacyDeletionTargets(
  seedHash: string,
  deviceId: string,
  pubkey: string,
  listed: SignedEvent[]
): string[][] {
  const shared = `${LEGACY_SYNC_EVENT_PREFIX}-${legacyChainId(seedHash)}`;
  const own = `${shared}-${deviceId}-`;
  const addresses = new Set([shared, `${own}update-0`, `${own}response-0`]);
  const ids = new Set<string>();
  for (const event of listed) {
    const address = event?.tags?.find((tag) => tag[0] === 'd')?.[1];
    if (
      event.pubkey !== pubkey ||
      event.kind !== NOSTR_EVENT_KIND ||
      typeof address !== 'string' ||
      (address !== shared && !address.startsWith(own))
    ) {
      continue;
    }
    addresses.add(address);
    if (typeof event.id === 'string' && /^[0-9a-f]{64}$/.test(event.id)) ids.add(event.id);
  }
  return [
    ...[...addresses].map((address) => ['a', `${NOSTR_EVENT_KIND}:${pubkey}:${address}`]),
    ...[...ids].map((id) => ['e', id]),
  ];
}

export async function signLegacyDeletions(
  privateKey: Uint8Array,
  pubkey: string,
  targets: string[][],
  createdAt = Math.floor(Date.now() / 1000)
): Promise<SignedEvent[]> {
  const events: SignedEvent[] = [];
  for (let i = 0; i < targets.length; i += TARGETS_PER_DELETION) {
    const tags = [...targets.slice(i, i + TARGETS_PER_DELETION), ['k', String(NOSTR_EVENT_KIND)]];
    const content = 'Fenko Vault sync moved to a new chain identity';
    const data = [0, pubkey, createdAt, NOSTR_DELETION_KIND, tags, content];
    const hash = sha256(new TextEncoder().encode(JSON.stringify(data)));
    const sig = await secp256k1.schnorr.signAsync(hash, privateKey);
    events.push({
      id: bytesToHex(hash),
      pubkey,
      created_at: createdAt,
      kind: NOSTR_DELETION_KIND,
      tags,
      content,
      sig: bytesToHex(sig),
    });
  }
  return events;
}

export interface LegacyCleanupOptions {
  seedHash: string;
  deviceId: string;
  relays: string[];
  timeoutMs?: number;
  log?: (message: string, data?: Record<string, unknown>) => void;
}

/**
 * Ask every relay, each on a short-lived socket of its own so sync traffic is
 * untouched, to delete this device's v4 events. Bounded by the timeout; never
 * rejects. Resolves with how many relays accepted a deletion.
 */
export async function deleteLegacyEvents(options: LegacyCleanupOptions): Promise<number> {
  const log = options.log ?? (() => {});
  let privateKey: Uint8Array | null = null;
  try {
    privateKey = await deriveLegacyNostrKey(options.seedHash);
    const pubkey = bytesToHex(secp256k1.schnorr.getPublicKey(privateKey));
    const key = privateKey;
    const accepted = await Promise.all(
      options.relays.map((url) => deleteOnRelay(url, key, pubkey, options, log))
    );
    return accepted.filter(Boolean).length;
  } catch (error) {
    log('Legacy cleanup failed', { error: error instanceof Error ? error.message : String(error) });
    return 0;
  } finally {
    privateKey?.fill(0);
  }
}

function deleteOnRelay(
  url: string,
  privateKey: Uint8Array,
  pubkey: string,
  options: LegacyCleanupOptions,
  log: NonNullable<LegacyCleanupOptions['log']>
): Promise<boolean> {
  return new Promise((resolve) => {
    const subId = `cleanup_${Date.now()}`;
    const listed: SignedEvent[] = [];
    const waiting = new Set<string>();
    let ws: WebSocket | null = null;
    let requested = false;
    let accepted = false;
    let settled = false;
    let queryTimer: ReturnType<typeof setTimeout> | null = null;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (queryTimer) clearTimeout(queryTimer);
      try {
        ws?.close();
      } catch {
        // Already closing
      }
      resolve(accepted);
    };
    const timer = setTimeout(() => {
      log('Legacy cleanup timed out', { relay: url, accepted });
      finish();
    }, options.timeoutMs ?? RELAY_TIMEOUT_MS);

    // Sent once, when the relay has listed our v4 events or stopped answering.
    const requestDeletion = async () => {
      if (requested || settled) return;
      requested = true;
      const targets = legacyDeletionTargets(options.seedHash, options.deviceId, pubkey, listed);
      const events = await signLegacyDeletions(privateKey, pubkey, targets);
      if (settled) return;
      for (const event of events) {
        waiting.add(event.id);
        ws?.send(JSON.stringify(['EVENT', event]));
      }
    };

    const handle = async (raw: string) => {
      if (settled) return;
      const message = JSON.parse(raw);
      if (message[0] === 'EVENT' && message[1] === subId && message[2]) {
        if (listed.length < MAX_QUERY_EVENTS) listed.push(message[2]);
      } else if ((message[0] === 'EOSE' || message[0] === 'CLOSED') && message[1] === subId) {
        if (message[0] === 'EOSE') ws?.send(JSON.stringify(['CLOSE', subId]));
        await requestDeletion();
      } else if (message[0] === 'OK' && waiting.delete(message[1])) {
        if (message[2] === true) accepted = true;
        else log('Relay refused legacy deletion', { relay: url, message: message[3] });
        if (waiting.size === 0) finish();
      }
    };

    try {
      ws = new WebSocket(url);
    } catch {
      finish();
      return;
    }
    ws.onopen = () => {
      ws?.send(
        JSON.stringify([
          'REQ',
          subId,
          { kinds: [NOSTR_EVENT_KIND], authors: [pubkey], limit: MAX_QUERY_EVENTS },
        ])
      );
      queryTimer = setTimeout(() => void requestDeletion().catch(finish), QUERY_TIMEOUT_MS);
    };
    ws.onmessage = (event) => {
      void handle(String(event.data)).catch(finish);
    };
    ws.onerror = () => {
      // onclose follows
    };
    ws.onclose = finish;
  });
}
