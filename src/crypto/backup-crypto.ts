/**
 * Password encryption for exported backups (format: backup-format.ts),
 * shared by the extension and the mobile apps.
 */

import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/hashes/utils';
import { base64ToUint8Array, uint8ArrayToBase64 } from '../utils/base64';
import {
  deriveKey,
  legacyKdfSpec,
  newKdfSpec,
  parseKdfSpec,
  UnsupportedKdfError,
  type KdfSpec,
} from './kdf';
import { BACKUP_ALGORITHM, type EncryptedBackupFields } from './backup-format';

export * from './backup-format';

const IV_LENGTH = 12;

/**
 * The backup needs a newer build: its KDF or cipher is unknown here, or its
 * parameters are out of bounds. Not a wrong password.
 */
export class UnsupportedBackupError extends Error {
  readonly code = 'UNSUPPORTED_BACKUP';

  constructor(detail: string) {
    super(`This backup was made by a newer version of Fenko Vault (${detail}).`);
    this.name = 'UnsupportedBackupError';
  }
}

/** The password is wrong, or the file was changed or damaged: GCM cannot tell which. */
export class BackupDecryptError extends Error {
  readonly code = 'BACKUP_DECRYPT_FAILED';

  constructor() {
    super('Wrong password or damaged backup.');
    this.name = 'BackupDecryptError';
  }
}

/** The KDF a backup's key was derived with, from its header. */
export function backupKdfSpec(backup: Partial<EncryptedBackupFields>): KdfSpec {
  if (backup.kdf === undefined) {
    // Every build before KDF records wrote a 32-byte salt; anything else is damage.
    try {
      return legacyKdfSpec(backup.salt as string);
    } catch {
      throw new BackupDecryptError();
    }
  }
  try {
    return parseKdfSpec({ kdf: backup.kdf, params: backup.kdfParams, salt: backup.salt });
  } catch (error) {
    if (error instanceof UnsupportedKdfError) {
      throw new UnsupportedBackupError(error.message.replace(/^Unsupported key derivation: /, ''));
    }
    throw error;
  }
}

/** Encrypt a backup's JSON under a fresh key from the default KDF. */
export async function encryptBackup(
  plaintext: string,
  password: string
): Promise<EncryptedBackupFields> {
  const spec = newKdfSpec();
  const key = await deriveKey(password, spec);
  try {
    const iv = randomBytes(IV_LENGTH);
    const sealed = gcm(key, iv).encrypt(new TextEncoder().encode(plaintext));
    return {
      algorithm: BACKUP_ALGORITHM,
      kdf: spec.kdf,
      kdfParams: { ...spec.params },
      salt: spec.salt,
      iv: uint8ArrayToBase64(iv),
      data: uint8ArrayToBase64(sealed),
    };
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypt any encrypted backup this or an earlier build wrote, on the
 * extension or on mobile. Throws UnsupportedBackupError for a newer format
 * and BackupDecryptError for a wrong password or a damaged file.
 */
export async function decryptBackup(
  backup: Partial<EncryptedBackupFields>,
  password: string
): Promise<string> {
  if (backup.algorithm !== undefined && backup.algorithm !== BACKUP_ALGORITHM) {
    throw new UnsupportedBackupError(`cipher "${String(backup.algorithm).slice(0, 40)}"`);
  }
  const spec = backupKdfSpec(backup);
  let iv: Uint8Array;
  let sealed: Uint8Array;
  try {
    iv = base64ToUint8Array(backup.iv as string);
    sealed = base64ToUint8Array(backup.data as string);
  } catch {
    throw new BackupDecryptError();
  }
  if (iv.length !== IV_LENGTH) throw new BackupDecryptError();

  const key = await deriveKey(password, spec);
  try {
    return new TextDecoder().decode(gcm(key, iv).decrypt(sealed));
  } catch {
    throw new BackupDecryptError();
  } finally {
    key.fill(0);
  }
}
