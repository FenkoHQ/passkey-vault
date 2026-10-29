/**
 * Keys for a sync chain, shared by the extension (sync-service.ts) and the
 * mobile apps (android/web/src/app.ts).
 *
 * Every device on a chain stores the same `seedHash`, hex(SHA-256(phrase
 * bytes)), and derives from it:
 *
 *   root          = scrypt(utf8(seedHash), utf8(SYNC_KEY_PREFIX + '/root'),
 *                          N=2^17, r=8, p=1, dkLen=32)
 *   chainId       = hex(HKDF-SHA256(root, no salt, '<prefix>/chain-id', 16))
 *   encryptionKey = HKDF-SHA256(root, no salt, '<prefix>/aes-256-gcm', 32)
 *   nostrKey      = HKDF-SHA256(root, no salt, '<prefix>/nostr-secp256k1', 32)
 *
 * The chain ID is public: it is in the tags of every event on the relays. The
 * memory-hard step sits in front of it so that testing a guessed phrase
 * against it costs a full scrypt: 128 MiB and a few hundred ms. Protocol v4
 * published hex(seedHash).slice(0, 32), which a guess could be checked
 * against with one SHA-256 (see legacyChainId).
 *
 * The parameters are part of the protocol. Changing any of them moves every
 * chain to a new identity, so they are pinned by tests/sync/chain-keys.test.ts.
 */

import { scryptAsync } from '@noble/hashes/scrypt';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { SYNC_KEY_PREFIX } from './protocol';

/** OWASP's scrypt recommendation for password storage. */
export const CHAIN_SCRYPT = { N: 2 ** 17, r: 8, p: 1 } as const;

const ROOT_SALT = `${SYNC_KEY_PREFIX}/root`;
const CHAIN_ID_INFO = `${SYNC_KEY_PREFIX}/chain-id`;
const ENCRYPTION_INFO = `${SYNC_KEY_PREFIX}/aes-256-gcm`;
const NOSTR_INFO = `${SYNC_KEY_PREFIX}/nostr-secp256k1`;

/** Hex characters in a chain ID; the same length v4 used. */
export const CHAIN_ID_LENGTH = 32;

export interface ChainKeys {
  /** Public: published in relay tags. */
  chainId: string;
  /** AES-256-GCM key for sync payloads; not extractable. */
  encryptionKey: CryptoKey;
  /**
   * secp256k1 secret for signing Nostr events; wipe with wipeChainKeys().
   * Used as is, like v4's PBKDF2 output: schnorr.getPublicKey() rejects the
   * 1 in 2^128 value outside the curve order.
   */
  nostrPrivateKey: Uint8Array;
}

export async function deriveChainKeys(seedHash: string): Promise<ChainKeys> {
  const encoder = new TextEncoder();
  const root = await scryptAsync(encoder.encode(seedHash), encoder.encode(ROOT_SALT), {
    ...CHAIN_SCRYPT,
    dkLen: 32,
  });
  const idBytes = hkdf(sha256, root, undefined, CHAIN_ID_INFO, CHAIN_ID_LENGTH / 2);
  const encryptionBytes = hkdf(sha256, root, undefined, ENCRYPTION_INFO, 32);
  const nostrPrivateKey = hkdf(sha256, root, undefined, NOSTR_INFO, 32);
  root.fill(0);
  try {
    const encryptionKey = await crypto.subtle.importKey(
      'raw',
      encryptionBytes as Uint8Array<ArrayBuffer>,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return { chainId: bytesToHex(idBytes), encryptionKey, nostrPrivateKey };
  } catch (error) {
    nostrPrivateKey.fill(0);
    throw error;
  } finally {
    encryptionBytes.fill(0);
  }
}

export function wipeChainKeys(keys: ChainKeys | null | undefined): void {
  keys?.nostrPrivateKey.fill(0);
}

/** The chain ID protocol v4 published for this seed. */
export function legacyChainId(seedHash: string): string {
  return seedHash.slice(0, CHAIN_ID_LENGTH);
}

/**
 * Whether `chainId` is the chain this seed derives, under v4 or v5. The v5
 * check runs scrypt, so call it only off the hot path.
 */
export async function isChainIdOfSeed(chainId: string, seedHash: string): Promise<boolean> {
  if (chainId === legacyChainId(seedHash)) return true;
  const keys = await deriveChainKeys(seedHash);
  wipeChainKeys(keys);
  return keys.chainId === chainId;
}
