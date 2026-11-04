/**
 * What the vault accepts as its master secret: a PIN of 4 or more digits,
 * or a passphrase of 8 or more characters. Shared by the background, which
 * enforces it, and the popup and options pages, which explain it.
 *
 * A PIN is kept for convenience and for vaults that already have one. It
 * mainly stops someone at the unlocked computer: with a copy of the browser
 * profile, every 6-digit PIN can be tried in hours whatever the KDF. Length
 * is what protects against that, so long PINs are accepted too.
 */

export const MIN_PIN_DIGITS = 4;
export const MIN_PASSPHRASE_LENGTH = 8;
/** Generous for a passphrase; bounds the work a hostile message can ask for. */
export const MAX_SECRET_LENGTH = 256;

export type VaultSecretProblem = 'too-short' | 'too-long';

/** Length in characters as a person counts them (code points, not UTF-16 units). */
function length(secret: string): number {
  return [...secret].length;
}

/** Whether the secret is all ASCII digits, so a PIN. */
export function isPin(secret: string): boolean {
  return /^[0-9]+$/.test(secret);
}

/** Why the secret cannot be used, or null when it can. */
export function checkVaultSecret(secret: unknown): VaultSecretProblem | null {
  if (typeof secret !== 'string' || secret.trim() === '') return 'too-short';
  const chars = length(secret);
  if (chars > MAX_SECRET_LENGTH) return 'too-long';
  const minimum = isPin(secret) ? MIN_PIN_DIGITS : MIN_PASSPHRASE_LENGTH;
  return chars < minimum ? 'too-short' : null;
}
