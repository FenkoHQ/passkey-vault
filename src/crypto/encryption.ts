import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Encryption utilities for PassKey Vault
 * Implements AES-256-GCM encryption with PBKDF2 key derivation
 */

export interface EncryptionResult {
  data: string; // Base64 encoded encrypted data
  iv: string; // Base64 encoded initialization vector
  salt: string; // Base64 encoded salt
  algorithm: string;
}

export interface EncryptionKey {
  key: Uint8Array;
  salt: Uint8Array;
}

const ENCRYPTION_CONFIG = {
  algorithm: 'AES-256-GCM',
  keyLength: 32, // 256 bits
  ivLength: 12, // 96 bits for GCM
  saltLength: 32, // 256 bits
  iterations: 100000, // PBKDF2 iterations
  tagLength: 16, // 128 bits authentication tag
} as const;

/**
 * Derives encryption key from password using PBKDF2
 */
export async function deriveKey(password: string, salt?: Uint8Array): Promise<EncryptionKey> {
  const keySalt = salt || randomBytes(ENCRYPTION_CONFIG.saltLength);

  const key = pbkdf2(sha256, new TextEncoder().encode(password), keySalt, {
    c: ENCRYPTION_CONFIG.iterations,
    dkLen: ENCRYPTION_CONFIG.keyLength,
  });

  return {
    key: new Uint8Array(key),
    salt: keySalt,
  };
}

/**
 * Encrypts data using AES-256-GCM
 */
export async function encrypt(
  data: string,
  key: Uint8Array,
  iv?: Uint8Array
): Promise<EncryptionResult> {
  const initVector = iv || randomBytes(ENCRYPTION_CONFIG.ivLength);

  const cipher = gcm(key, initVector);
  const encrypted = cipher.encrypt(new TextEncoder().encode(data));

  return {
    data: btoa(String.fromCharCode(...encrypted)),
    iv: btoa(String.fromCharCode(...initVector)),
    salt: '', // Salt is handled at key derivation level
    algorithm: ENCRYPTION_CONFIG.algorithm,
  };
}

/**
 * Decrypts data using AES-256-GCM
 */
export async function decrypt(
  encryptedData: string,
  key: Uint8Array,
  iv: Uint8Array
): Promise<string> {
  try {
    const encrypted = new Uint8Array(
      atob(encryptedData)
        .split('')
        .map((char) => char.charCodeAt(0))
    );

    const cipher = gcm(key, iv);
    const decrypted = cipher.decrypt(encrypted);

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new Error('Decryption failed: Invalid data or key');
  }
}

/**
 * High-level encryption function that handles key derivation
 */
export async function encryptWithPassword(
  data: string,
  password: string
): Promise<EncryptionResult> {
  const { key, salt } = await deriveKey(password);
  const iv = randomBytes(ENCRYPTION_CONFIG.ivLength);

  const result = await encrypt(data, key, iv);
  result.salt = btoa(String.fromCharCode(...salt));

  // Securely clear the key from memory
  key.fill(0);

  return result;
}

/**
 * High-level decryption function that handles key derivation
 */
export async function decryptWithPassword(
  encryptedData: string,
  iv: string,
  salt: string,
  password: string
): Promise<string> {
  try {
    const { key } = await deriveKey(
      password,
      new Uint8Array(
        atob(salt)
          .split('')
          .map((char) => char.charCodeAt(0))
      )
    );

    const initVector = new Uint8Array(
      atob(iv)
        .split('')
        .map((char) => char.charCodeAt(0))
    );

    const result = await decrypt(encryptedData, key, initVector);

    // Securely clear the key from memory
    key.fill(0);

    return result;
  } catch (error) {
    throw new Error(`Failed to decrypt data: ${error.message}`);
  }
}

/**
 * Generates a secure random string
 */
export function generateSecureRandom(length: number = 32): string {
  const bytes = randomBytes(length);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
    .substring(0, length);
}

/**
 * Creates a checksum for data integrity verification
 */
export async function createChecksum(data: string): Promise<string> {
  const hash = sha256(new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...hash))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Verifies data integrity using checksum
 */
export async function verifyChecksum(data: string, expectedChecksum: string): Promise<boolean> {
  const actualChecksum = await createChecksum(data);
  return actualChecksum === expectedChecksum;
}

/**
 * Securely wipes sensitive data from memory
 */
export function secureWipe(data: Uint8Array | string): void {
  if (typeof data === 'string') {
    // Strings are immutable in JavaScript, but we can wipe if it's in a mutable container
    return;
  }

  // Overwrite the array with random data, then zeros
  for (let i = 0; i < data.length; i++) {
    data[i] = Math.floor(Math.random() * 256);
  }
  for (let i = 0; i < data.length; i++) {
    data[i] = 0;
  }
}

/**
 * Session key manager for temporary encryption keys
 */
export class SessionKeyManager {
  private keys = new Map<string, { key: Uint8Array; expires: number }>();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Clean up expired keys every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredKeys();
    }, 60000);
  }

  /**
   * Creates and stores a session key
   */
  async createSessionKey(
    sessionId: string,
    password: string,
    ttlMs: number = 3600000 // 1 hour default
  ): Promise<void> {
    const { key } = await deriveKey(password);

    this.keys.set(sessionId, {
      key,
      expires: Date.now() + ttlMs,
    });
  }

  /**
   * Retrieves a session key
   */
  getSessionKey(sessionId: string): Uint8Array | null {
    const entry = this.keys.get(sessionId);

    if (!entry || Date.now() > entry.expires) {
      if (entry) {
        secureWipe(entry.key);
        this.keys.delete(sessionId);
      }
      return null;
    }

    return entry.key;
  }

  /**
   * Removes a session key
   */
  removeSessionKey(sessionId: string): void {
    const entry = this.keys.get(sessionId);
    if (entry) {
      secureWipe(entry.key);
      this.keys.delete(sessionId);
    }
  }

  /**
   * Clean up expired keys
   */
  private cleanupExpiredKeys(): void {
    const now = Date.now();

    for (const [sessionId, entry] of this.keys.entries()) {
      if (now > entry.expires) {
        secureWipe(entry.key);
        this.keys.delete(sessionId);
      }
    }
  }

  /**
   * Destroy all keys and cleanup
   */
  destroy(): void {
    for (const entry of this.keys.values()) {
      secureWipe(entry.key);
    }
    this.keys.clear();

    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

// Global session key manager instance
export const sessionKeyManager = new SessionKeyManager();
