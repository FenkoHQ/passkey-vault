/**
 * Password-based key derivation for the vault key and for encrypted backups,
 * shared by the extension and the mobile apps (android/web/src/app.ts).
 *
 * Every derived key comes with a KdfSpec, `{ kdf, params, salt }`, that is
 * stored next to what the key encrypts, so the cost can be raised later and a
 * reader can tell a newer format from a wrong password. Data from before
 * specs existed was always PBKDF2-SHA256 with 100,000 iterations
 * (legacyKdfSpec).
 *
 * No KDF makes a 6-digit PIN safe against someone holding a copy of the
 * encrypted data: there are only a million PINs. The KDF multiplies the cost
 * of each guess; only a longer secret multiplies the number of guesses.
 */

import { scryptAsync } from '@noble/hashes/scrypt';
import { randomBytes } from '@noble/hashes/utils';
import { base64ToUint8Array, uint8ArrayToBase64 } from '../utils/base64';
import { DEFAULT_KDF } from './kdf-profile';

/** Bytes of key material: AES-256-GCM. */
export const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const MIN_SALT_LENGTH = 16;
const MAX_SALT_LENGTH = 64;

/** What vaults and backups used before KDF specs were stored. */
export const LEGACY_PBKDF2_ITERATIONS = 100000;

// Upper bounds for parameters read from storage or from a backup file. They
// keep a hostile or corrupt file from asking for gigabytes of memory or
// minutes of work, while leaving room to raise the default about 8x.
const MAX_PBKDF2_ITERATIONS = 10_000_000;
const MAX_SCRYPT_MEMORY = 256 * 1024 * 1024; // 128 * N * r bytes
const MAX_SCRYPT_WORK = 2 ** 23; // N * r * p

export interface Pbkdf2Spec {
  kdf: 'pbkdf2-sha256';
  params: { iterations: number };
  /** Base64. */
  salt: string;
}

export interface ScryptSpec {
  kdf: 'scrypt';
  params: { N: number; r: number; p: number };
  /** Base64. */
  salt: string;
}

export type KdfSpec = Pbkdf2Spec | ScryptSpec;

/**
 * The stored KDF is one this build cannot use: written by a newer version, or
 * with parameters outside the bounds above. Distinct from a wrong password,
 * so the UI can say "update Fenko Vault" instead of "wrong password".
 */
export class UnsupportedKdfError extends Error {
  readonly code = 'UNSUPPORTED_KDF';

  constructor(detail: string) {
    super(`Unsupported key derivation: ${detail}`);
    this.name = 'UnsupportedKdfError';
  }
}

function isInteger(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

function parseSalt(value: unknown): string {
  if (typeof value !== 'string') throw new UnsupportedKdfError('missing salt');
  let length: number;
  try {
    length = base64ToUint8Array(value).length;
  } catch {
    throw new UnsupportedKdfError('salt is not base64');
  }
  if (length < MIN_SALT_LENGTH || length > MAX_SALT_LENGTH) {
    throw new UnsupportedKdfError(`salt of ${length} bytes`);
  }
  return value;
}

/**
 * Validate a KDF spec read from storage or a file, returning a clean copy.
 * Throws UnsupportedKdfError for an unknown KDF or out-of-range parameters.
 */
export function parseKdfSpec(value: unknown): KdfSpec {
  if (!value || typeof value !== 'object') throw new UnsupportedKdfError('no KDF record');
  const { kdf, params, salt } = value as { kdf?: unknown; params?: unknown; salt?: unknown };
  const p = (params && typeof params === 'object' ? params : {}) as Record<string, unknown>;

  if (kdf === 'pbkdf2-sha256') {
    if (!isInteger(p.iterations, 1000, MAX_PBKDF2_ITERATIONS)) {
      throw new UnsupportedKdfError(`PBKDF2 iterations ${String(p.iterations)}`);
    }
    return { kdf, params: { iterations: p.iterations }, salt: parseSalt(salt) };
  }

  if (kdf === 'scrypt') {
    const { N, r, p: parallel } = p;
    if (
      !isInteger(N, 2, 2 ** 30) ||
      (N & (N - 1)) !== 0 ||
      !isInteger(r, 1, 64) ||
      !isInteger(parallel, 1, 64) ||
      128 * N * r > MAX_SCRYPT_MEMORY ||
      N * r * parallel > MAX_SCRYPT_WORK
    ) {
      throw new UnsupportedKdfError(`scrypt N=${String(N)} r=${String(r)} p=${String(parallel)}`);
    }
    return { kdf, params: { N, r, p: parallel }, salt: parseSalt(salt) };
  }

  throw new UnsupportedKdfError(typeof kdf === 'string' ? `"${kdf.slice(0, 40)}"` : 'no KDF name');
}

/** A spec with the current default parameters and a fresh random salt. */
export function newKdfSpec(): KdfSpec {
  return parseKdfSpec({
    kdf: DEFAULT_KDF.kdf,
    params: { ...DEFAULT_KDF.params },
    salt: uint8ArrayToBase64(randomBytes(SALT_LENGTH)),
  });
}

/** The spec implied by data from before specs were stored. */
export function legacyKdfSpec(salt: string): KdfSpec {
  return parseKdfSpec({
    kdf: 'pbkdf2-sha256',
    params: { iterations: LEGACY_PBKDF2_ITERATIONS },
    salt,
  });
}

/**
 * Whether a key under this spec should be re-derived with the default: any
 * PBKDF2 spec once the default is memory-hard, or scrypt with less memory or
 * less work than the default. A stronger spec (a newer build raised it) is
 * left alone, never lowered.
 */
export function isWeakerThanDefault(spec: KdfSpec): boolean {
  const target = DEFAULT_KDF as { kdf: string; params: Record<string, number> };
  if (spec.kdf !== target.kdf) return spec.kdf === 'pbkdf2-sha256';
  if (spec.kdf === 'scrypt') {
    const { N, r, p } = spec.params;
    const memory = N * r;
    const targetMemory = target.params.N * target.params.r;
    return memory < targetMemory || memory * p < targetMemory * target.params.p;
  }
  return spec.params.iterations < target.params.iterations;
}

/** Whether two specs are the same record (same KDF, parameters and salt). */
export function sameKdfSpec(a: KdfSpec, b: KdfSpec): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Derive a 32-byte key. PBKDF2 hashes the password's UTF-8 bytes as given,
 * as every earlier build did. scrypt first normalises the password to NFC, so
 * the same passphrase typed on different systems derives the same key.
 */
export async function deriveKey(password: string, spec: KdfSpec): Promise<Uint8Array> {
  const checked = parseKdfSpec(spec);
  const salt = base64ToUint8Array(checked.salt);

  if (checked.kdf === 'pbkdf2-sha256') {
    const material = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: new Uint8Array(salt),
        iterations: checked.params.iterations,
      },
      material,
      KEY_LENGTH * 8
    );
    return new Uint8Array(bits);
  }

  const { N, r, p } = checked.params;
  return scryptAsync(new TextEncoder().encode(password.normalize('NFC')), salt, {
    N,
    r,
    p,
    dkLen: KEY_LENGTH,
    maxmem: MAX_SCRYPT_MEMORY + 1024 * 1024,
  });
}
