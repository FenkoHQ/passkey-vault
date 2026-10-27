/**
 * Storage as builds before KDF records left it: a PIN-protected vault whose
 * key is PBKDF2-SHA256 (100,000 iterations) over the PIN and a salt in
 * `passext_encryption_salt`. Written with Node's own crypto rather than the
 * extension's code, so the fixture pins the old format instead of agreeing
 * with whatever the code under test does.
 */

import { createCipheriv, pbkdf2Sync, randomBytes } from 'crypto';

export interface LegacyVaultContents {
  passkeys?: unknown[];
  totpEntries?: unknown[];
  syncConfig?: Record<string, unknown>;
}

function seal(plaintext: string, key: Buffer) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    data: Buffer.concat([body, cipher.getAuthTag()]).toString('base64'),
    iv: iv.toString('base64'),
    salt: '',
    version: '2.0',
  };
}

export function legacyVault(pin: string, contents: LegacyVaultContents = {}) {
  const salt = randomBytes(32);
  const key = pbkdf2Sync(pin, salt, 100000, 32, 'sha256');
  const storage: Record<string, unknown> = {
    passext_encryption_salt: salt.toString('base64'),
    passext_master_key_check: seal('passkey-vault-check', key),
  };
  if (contents.passkeys) {
    storage.passext_encrypted_passkeys = seal(JSON.stringify(contents.passkeys), key);
  }
  if (contents.totpEntries) {
    storage.passext_encrypted_totp_entries = seal(JSON.stringify(contents.totpEntries), key);
  }
  if (contents.syncConfig) {
    storage.passext_encrypted_sync_config = seal(JSON.stringify(contents.syncConfig), key);
  }
  return storage;
}

/** The vault's encrypted values: what a re-key must rewrite, all at once. */
export const ENCRYPTED_VAULT_VALUES = [
  'passext_master_key_check',
  'passext_encrypted_passkeys',
  'passext_encrypted_totp_entries',
  'passext_encrypted_sync_config',
];
