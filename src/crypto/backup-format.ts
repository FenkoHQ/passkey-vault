/**
 * The encrypted backup format, shared by the extension and the mobile apps
 * (android/web/src/app.ts), so a backup made on one opens on the other. The
 * crypto is in backup-crypto.ts; this module has no dependencies, so pages
 * that only check a password or recognise a file stay small.
 *
 * An encrypted backup is a JSON object:
 *
 *   {
 *     "encrypted": true,
 *     "algorithm": "AES-256-GCM",
 *     "kdf": "scrypt",
 *     "kdfParams": { "N": 131072, "r": 8, "p": 1 },
 *     "salt": "<base64, 32 bytes>",
 *     "iv": "<base64, 12 bytes>",
 *     "data": "<base64 ciphertext and 16-byte tag>",
 *     ...unencrypted metadata (version, exportedAt, counts)
 *   }
 *
 * `kdf`, `kdfParams` and `salt` make the KdfSpec of src/crypto/kdf.ts. A
 * backup without `kdf` was made before they were recorded and is
 * PBKDF2-SHA256 at 100,000 iterations over the raw password. The salt keeps
 * its top-level place so older builds still recognise the file as an
 * encrypted backup; they report a wrong password for it, which is the most
 * they can do.
 */

export const BACKUP_ALGORITHM = 'AES-256-GCM';

/**
 * The shortest password a new encrypted backup takes. A backup file is
 * attacked offline with no rate limit, and length is the only property of a
 * password that can be checked without guessing at how it was chosen; the
 * export prompt recommends four or more random words as well.
 */
export const MIN_BACKUP_PASSWORD_LENGTH = 12;

/** The fields of an encrypted backup that carry the ciphertext and its key derivation. */
export interface EncryptedBackupFields {
  data: string;
  iv: string;
  salt: string;
  algorithm: string;
  kdf?: string;
  kdfParams?: Record<string, number>;
}

/** Whether parsed JSON is one of our encrypted backups, in any format version. */
export function isEncryptedBackup(value: unknown): value is EncryptedBackupFields {
  const backup = value as Partial<EncryptedBackupFields> & { encrypted?: unknown };
  return (
    !!backup &&
    backup.encrypted === true &&
    typeof backup.data === 'string' &&
    typeof backup.iv === 'string' &&
    typeof backup.salt === 'string'
  );
}

/** Why a password cannot encrypt a new backup, or null. */
export function checkBackupPassword(password: unknown): 'too-short' | null {
  return typeof password === 'string' && [...password].length >= MIN_BACKUP_PASSWORD_LENGTH
    ? null
    : 'too-short';
}
