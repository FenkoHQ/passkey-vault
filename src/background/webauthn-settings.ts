/**
 * Advanced WebAuthn ceremony settings.
 *
 * Everything here was previously a constant baked into the ceremony code:
 * flag bits, the AAGUID, the reported attachment, and how the signature
 * counter moves. Relying parties differ on what they want from each, and
 * some of the values are claims the extension cannot back up (see the UV
 * discussion in issue #5), so they are settings rather than assumptions.
 *
 * Defaults reproduce the shipped 0.9.6 behaviour exactly. A vault that has
 * never opened this page signs identically to one running the old constants.
 */

export const WEBAUTHN_FLAGS_KEY = 'webauthn_flags';

/** Report user verification on every ceremony, or never claim it. */
export type UserVerificationMode = 'always' | 'never';

/** Advance the per-credential counter, or always send zero. */
export type SignCounterMode = 'increment' | 'zero';

/** What `authenticatorAttachment` says on the returned credential. */
export type AttachmentMode = 'cross-platform' | 'platform';

/**
 * Transport hints for AuthenticatorAttestationResponse.getTransports(),
 * derived from the attachment claim so the two never contradict each other.
 */
export function transportsFor(attachment: AttachmentMode): AuthenticatorTransport[] {
  return attachment === 'platform' ? ['internal'] : ['hybrid', 'internal'];
}

/** Identify the authenticator model, or stay anonymous with an all-zero AAGUID. */
export type AaguidMode = 'vault' | 'zero';

export interface WebAuthnFlagSettings {
  userVerification: UserVerificationMode;
  /** BE (0x08) — the credential can be backed up / synced. */
  backupEligible: boolean;
  /** BS (0x10) — the credential currently is backed up. Requires BE. */
  backupState: boolean;
  signCounter: SignCounterMode;
  attachment: AttachmentMode;
  aaguid: AaguidMode;
}

export const DEFAULT_WEBAUTHN_FLAGS: WebAuthnFlagSettings = {
  userVerification: 'always',
  backupEligible: false,
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
