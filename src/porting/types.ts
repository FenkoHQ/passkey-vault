/**
 * Canonical shapes used while moving credentials between Fenko Vault and
 * third-party apps. Parsers translate a vendor file into these; the importer
 * then materialises them into vault records.
 */

import type { BackupFlags, BackupSource } from '../sync/backup-flags';

export type OtpType = 'totp' | 'hotp';
export type OtpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

/** One MFA seed, vendor-neutral. Mirrors the otpauth:// parameter set. */
export interface PortableOtp {
  type: OtpType;
  issuer: string;
  account: string;
  secret: Uint8Array;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter: number;
}

/**
 * One passkey, vendor-neutral.
 *
 * `privateKey` holds the key exactly as the vendor wrote it — base64 or
 * base64url PKCS#8, PEM, or a JWK object. It is normalised to base64 PKCS#8
 * when the entry is materialised into a vault record (see keys.ts), because
 * that conversion needs WebCrypto and parsers stay synchronous.
 */
export interface PortablePasskey {
  credentialId: string;
  rpId: string;
  userName: string;
  userDisplayName: string;
  userHandle: string | null;
  privateKey: unknown;
  counter: number;
  createdAt: number;
  /**
   * Backup flags the file recorded for this passkey. Absent when the format
   * does not record them: the passkey came from a manager that syncs it, so
   * it is imported as a synced passkey. 'unknown' marks a Fenko backup made
   * before passkeys carried their own flags; those keep signing as before.
   */
  backup?: { flags: BackupFlags; source: BackupSource } | 'unknown';
}

/** What a parser hands back: everything it understood plus what it skipped. */
export interface ParsedImport {
  format: string;
  formatLabel: string;
  otp: PortableOtp[];
  passkeys: PortablePasskey[];
  warnings: string[];
}

/** A file offered for import, pre-parsed as JSON when it looked like JSON. */
export interface ImportInput {
  fileName: string;
  text: string;
  json?: unknown;
}

export interface FormatParser {
  id: string;
  label: string;
  /** Extensions the vendor emits, used for the file picker and for hints. */
  extensions: string[];
  detect(input: ImportInput): boolean;
  parse(input: ImportInput): ParsedImport;
}

export const DEFAULT_DIGITS = 6;
export const DEFAULT_PERIOD = 30;

export function emptyImport(format: string, formatLabel: string): ParsedImport {
  return { format, formatLabel, otp: [], passkeys: [], warnings: [] };
}
