/**
 * Advanced WebAuthn ceremony settings.
 *
 * Everything here was previously a constant baked into the ceremony code:
 * flag bits, the AAGUID, the reported attachment, and how the signature
 * counter moves. Relying parties differ on what they want from each, and
 * some of the values are claims the extension cannot back up (see the UV
 * discussion in issue #5), so they are settings rather than assumptions.
 *
 * Defaults reproduce the shipped 0.9.6 behaviour, except for the backup
 * flags. Those are now stamped onto each passkey when it is created or
 * imported (see sync/backup-flags.ts), so the toggles here only decide what a
 * passkey created from now on asserts. Sign-in uses the passkey's own flags.
 */

import { BackupFlags, PRE_UPGRADE_BACKUP_FLAGS, normalizeBackupFlags } from '../sync/backup-flags';

export const WEBAUTHN_FLAGS_KEY = 'webauthn_flags';

/** Report user verification on every ceremony, or never claim it. */
export type UserVerificationMode = 'always' | 'never';

/** Advance the per-credential counter, or always send zero. */
export type SignCounterMode = 'increment' | 'zero';

/** What `authenticatorAttachment` says on the returned credential. */
export type AttachmentMode = 'cross-platform' | 'platform';

/**
 * Only claim the local platform transport. Cross-platform attachment alone
 * does not establish support for any particular transport.
 */
export function transportsFor(attachment: AttachmentMode): AuthenticatorTransport[] {
  return attachment === 'platform' ? ['internal'] : [];
}

/** Identify the authenticator model, or stay anonymous with an all-zero AAGUID. */
export type AaguidMode = 'vault' | 'zero';

export interface WebAuthnFlagSettings {
  userVerification: UserVerificationMode;
  /** BE (0x08) for passkeys created from now on — the credential can be synced. */
  backupEligible: boolean;
  /**
   * BS (0x10) for passkeys created from now on, even before sync is set up.
   * A new passkey is reported as backed up anyway once sync is on. Requires BE.
   */
  backupState: boolean;
  signCounter: SignCounterMode;
  attachment: AttachmentMode;
  aaguid: AaguidMode;
}

export const DEFAULT_WEBAUTHN_FLAGS: WebAuthnFlagSettings = {
  userVerification: 'always',
  // The vault syncs its passkeys between devices, which is exactly what BE
  // describes. Existing passkeys keep whatever they were created with.
  backupEligible: true,
  backupState: false,
  signCounter: 'increment',
  attachment: 'cross-platform',
  aaguid: 'vault',
};

function pick<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback;
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

/**
 * Coerce stored (or messaged) settings into a valid set. Anything unknown
 * falls back to the default rather than reaching the ceremony code.
 */
export function normalizeWebAuthnFlags(raw: unknown): WebAuthnFlagSettings {
  const input = (raw && typeof raw === 'object' ? raw : {}) as Partial<WebAuthnFlagSettings>;

  const backupEligible = bool(input.backupEligible, DEFAULT_WEBAUTHN_FLAGS.backupEligible);

  return {
    userVerification: pick(
      input.userVerification,
      ['always', 'never'] as const,
      DEFAULT_WEBAUTHN_FLAGS.userVerification
    ),
    backupEligible,
    // WebAuthn L3 §6.1: BS is only meaningful when BE is set. A credential
    // cannot be backed up if it was never eligible for backup, and RPs are
    // required to treat that combination as invalid.
    backupState: backupEligible && bool(input.backupState, DEFAULT_WEBAUTHN_FLAGS.backupState),
    signCounter: pick(
      input.signCounter,
      ['increment', 'zero'] as const,
      DEFAULT_WEBAUTHN_FLAGS.signCounter
    ),
    attachment: pick(
      input.attachment,
      ['cross-platform', 'platform'] as const,
      DEFAULT_WEBAUTHN_FLAGS.attachment
    ),
    aaguid: pick(input.aaguid, ['vault', 'zero'] as const, DEFAULT_WEBAUTHN_FLAGS.aaguid),
  };
}

/** Read the settings from extension storage, falling back to the defaults. */
export async function loadWebAuthnFlags(): Promise<WebAuthnFlagSettings> {
  try {
    const stored = await chrome.storage.local.get([WEBAUTHN_FLAGS_KEY]);
    return normalizeWebAuthnFlags(stored?.[WEBAUTHN_FLAGS_KEY]);
  } catch {
    return { ...DEFAULT_WEBAUTHN_FLAGS };
  }
}

/** Persist the settings, normalized. Returns what was actually written. */
export async function saveWebAuthnFlags(raw: unknown): Promise<WebAuthnFlagSettings> {
  const flags = normalizeWebAuthnFlags(raw);
  await chrome.storage.local.set({ [WEBAUTHN_FLAGS_KEY]: flags });
  return flags;
}

/**
 * Set once, by the upgrade that introduced per-credential backup flags: the
 * flags every passkey was being signed with at that moment. Passkeys that
 * still have no flags of their own (an old backup, a record from a device
 * that has not updated) keep signing with these.
 */
export const BACKUP_FLAGS_SNAPSHOT_KEY = 'webauthn_backup_snapshot';

/**
 * The backup flags this vault signed every passkey with before the upgrade:
 * the user's stored toggles, or the old all-off defaults if they never
 * touched them. Deliberately not normalizeWebAuthnFlags(), whose defaults
 * now describe new passkeys.
 */
export function preUpgradeBackupFlags(storedFlags: unknown): BackupFlags {
  const input = (storedFlags && typeof storedFlags === 'object' ? storedFlags : {}) as Partial<
    Record<'backupEligible' | 'backupState', unknown>
  >;
  return normalizeBackupFlags(
    bool(input.backupEligible, PRE_UPGRADE_BACKUP_FLAGS.backupEligible),
    bool(input.backupState, PRE_UPGRADE_BACKUP_FLAGS.backupState)
  );
}

/** The pre-upgrade snapshot, if the upgrade has already taken it. */
export async function loadBackupFlagsSnapshot(): Promise<BackupFlags | null> {
  try {
    const stored = await chrome.storage.local.get([BACKUP_FLAGS_SNAPSHOT_KEY]);
    const snapshot = stored?.[BACKUP_FLAGS_SNAPSHOT_KEY];
    if (!snapshot || typeof snapshot !== 'object') return null;
    return preUpgradeBackupFlags(snapshot);
  } catch {
    return null;
  }
}

/**
 * Take the snapshot unless it already exists, reading the user's toggles
 * before anything could change their meaning. Returns the snapshot.
 */
export async function ensureBackupFlagsSnapshot(): Promise<BackupFlags> {
  const existing = await loadBackupFlagsSnapshot();
  if (existing) return existing;
  const stored = await chrome.storage.local.get([WEBAUTHN_FLAGS_KEY]);
  const snapshot = preUpgradeBackupFlags(stored?.[WEBAUTHN_FLAGS_KEY]);
  await chrome.storage.local.set({ [BACKUP_FLAGS_SNAPSHOT_KEY]: snapshot });
  return snapshot;
}
