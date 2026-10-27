/**
 * Import pipeline: sniff the file, parse it, then materialise vault records.
 *
 *   file ──detect──> FormatParser ──parse──> ParsedImport ──materialise──>
 *   { passkeys, totpEntries } ready for the IMPORT_VAULT message.
 *
 * Parsing is synchronous and pure; only materialisation touches WebCrypto
 * (normalising private keys and deriving public keys).
 */

import { arrayBufferToBase64, arrayBufferToBase64URL } from '../utils/base64';
import { StoredTotpEntry } from '../crypto/totp-store';
import { derivePublicKeyBase64, toPkcs8Base64 } from './keys';
import {
  IMPORTED_BACKUP_FLAGS,
  canRepairBackupFlags,
  hasBackupFlags,
  normalizeBackupFlags,
  withBackupFlags,
  type BackupFields,
  type BackupRepair,
} from '../sync/backup-flags';
import { FormatParser, ImportInput, ParsedImport, PortableOtp, PortablePasskey } from './types';
import { AUTHENTICATOR_PARSERS } from './formats/authenticators';
import { MANAGER_PARSERS } from './formats/managers';
import { FENKO_PARSERS } from './formats/fenko';
import { cxf } from './formats/cxf';

const CREDENTIAL_ID_BYTES = 16;
const PASSKEY_TYPE = 'public-key';

/**
 * Detection order matters: the specific vendor shapes are tried before the
 * catch-all JSON/CSV readers, which would otherwise swallow them.
 */
export const IMPORT_PARSERS: FormatParser[] = [
  ...FENKO_PARSERS,
  cxf,
  ...MANAGER_PARSERS,
  ...AUTHENTICATOR_PARSERS,
];

export interface StoredPasskeyRecord extends BackupFields {
  id: string;
  credentialId: string;
  type: string;
  rpId: string;
  origin: string;
  user: { id: string | null; name: string; displayName: string };
  privateKey: string;
  publicKey: string;
  createdAt: number;
  counter: number;
  prfKey?: string;
}

export interface ExistingVault {
  passkeys: Array<
    { id?: string; credentialId?: string; rpId?: string; publicKey?: string } & BackupFields
  >;
  totpEntries: Array<Partial<StoredTotpEntry>>;
}

export interface MaterializedImport {
  format: string;
  formatLabel: string;
  passkeys: StoredPasskeyRecord[];
  totpEntries: StoredTotpEntry[];
  duplicatePasskeys: number;
  duplicateTotp: number;
  /**
   * Passkeys already in the vault whose backup flags this file corrects,
   * typically ones imported before passkeys carried their own flags.
   */
  backupRepairs: BackupRepair[];
  warnings: string[];
}

/** Accepted file extensions, for the file picker. */
export function acceptedExtensions(): string[] {
  const seen = new Set<string>();
  for (const parser of IMPORT_PARSERS) {
    parser.extensions.forEach((extension) => seen.add(extension));
  }
  return [...seen].sort();
}

export function buildInput(fileName: string, text: string): ImportInput {
  const trimmed = text.trim();
  let json: unknown;

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      json = JSON.parse(trimmed);
    } catch {
      /* not JSON after all — leave undefined so CSV/text parsers get a turn */
    }
  }

  return { fileName, text, json };
}

export function detectFormat(input: ImportInput): FormatParser | null {
  for (const parser of IMPORT_PARSERS) {
    try {
      if (parser.detect(input)) return parser;
    } catch {
      /* a parser that throws while sniffing simply does not match */
    }
  }
  return null;
}

/** Parse a file into the vendor-neutral shape. Throws when nothing matches. */
export function parseImport(fileName: string, text: string): ParsedImport {
  const input = buildInput(fileName, text);
  const parser = detectFormat(input);

  if (!parser) {
    throw new Error(
      'Unrecognised file. Export from your provider as JSON, CXF or CSV, or use the Fenko CSV template.'
    );
  }

  return parser.parse(input);
}

function otpFingerprint(entry: {
  type?: string;
  issuer?: string;
  account?: string;
  secretB64?: string;
}): string {
  return [
    (entry.type || 'totp').toLowerCase(),
    (entry.issuer || '').trim().toLowerCase(),
    (entry.account || '').trim().toLowerCase(),
    entry.secretB64 || '',
  ].join('|');
}

function toStoredTotp(entry: PortableOtp): StoredTotpEntry {
  const secret = new Uint8Array(entry.secret.length);
  secret.set(entry.secret);

  return {
    id: entry.id || crypto.randomUUID(),
    type: entry.type,
    issuer: entry.issuer,
    account: entry.account,
    secretB64: arrayBufferToBase64(secret.buffer),
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
    createdAt: entry.createdAt || Date.now(),
    ...(entry.lastUsed && { lastUsed: entry.lastUsed }),
  };
}

function mintCredentialId(): string {
  const bytes = new Uint8Array(CREDENTIAL_ID_BYTES);
  crypto.getRandomValues(bytes);
  return arrayBufferToBase64URL(bytes.buffer);
}

function normalizeCredentialId(value: string): string {
  const trimmed = (value || '').trim();
  if (!trimmed) return mintCredentialId();
  return trimmed.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function toStoredPasskey(passkey: PortablePasskey): Promise<StoredPasskeyRecord> {
  const privateKey = await toPkcs8Base64(passkey.privateKey);
  const publicKey = await derivePublicKeyBase64(privateKey);
  const credentialId = normalizeCredentialId(passkey.credentialId);

  const record: StoredPasskeyRecord = {
    id: passkey.id || credentialId,
    credentialId,
    type: PASSKEY_TYPE,
    rpId: passkey.rpId,
    origin: passkey.rpId ? `https://${passkey.rpId}` : '',
    user: {
      id: passkey.userHandle,
      name: passkey.userName,
      displayName: passkey.userDisplayName || passkey.userName,
    },
    privateKey,
    publicKey,
    createdAt: passkey.createdAt || Date.now(),
    counter: passkey.counter || 0,
    ...(passkey.prfKey && { prfKey: passkey.prfKey }),
  };

  if (passkey.backup === 'unknown') return record;
  const backup = passkey.backup ?? { flags: IMPORTED_BACKUP_FLAGS, source: 'imported' as const };
  return withBackupFlags(record, backup.flags, backup.source);
}

/**
 * A re-imported passkey the vault already holds: correct its backup flags if
 * they are only an assumption (an earlier import, or the upgrade snapshot)
 * and the file says otherwise. Nothing else about the stored record changes.
 */
function backupRepairFor(
  record: StoredPasskeyRecord,
  existing: ExistingVault['passkeys'][number]
): BackupRepair | null {
  if (!hasBackupFlags(record) || !canRepairBackupFlags(existing)) return null;
  if (existing.rpId !== record.rpId || existing.publicKey !== record.publicKey) return null;
  const flags = normalizeBackupFlags(record.backupEligible === true, record.backupState === true);
  if (
    hasBackupFlags(existing) &&
    existing.backupEligible === flags.backupEligible &&
    (existing.backupState === true) === flags.backupState
  ) {
    return null;
  }
  return { id: existing.id || record.id, rpId: record.rpId, publicKey: record.publicKey, ...flags };
}

/**
 * Turn parsed entries into vault records, dropping anything the vault already
 * holds. TOTP seeds have no stable id across apps, so they are matched on
 * issuer + account + secret; a Fenko backup does carry the ids, so those are
 * matched too.
 */
export async function materialize(
  parsed: ParsedImport,
  existing: ExistingVault
): Promise<MaterializedImport> {
  const warnings = [...parsed.warnings];

  const knownPasskeys = new Map<string, ExistingVault['passkeys'][number]>();
  for (const entry of existing.passkeys) {
    for (const key of [entry.id, entry.credentialId]) {
      if (key) knownPasskeys.set(key, entry);
    }
  }
  const backupRepairs: BackupRepair[] = [];
  const knownOtp = new Set(existing.totpEntries.map(otpFingerprint));
  const knownOtpIds = new Set(existing.totpEntries.map((entry) => entry.id).filter(Boolean));

  const passkeys: StoredPasskeyRecord[] = [];
  let duplicatePasskeys = 0;

  for (const candidate of parsed.passkeys) {
    try {
      const record = await toStoredPasskey(candidate);
      const known = knownPasskeys.get(record.id) ?? knownPasskeys.get(record.credentialId);
      if (known) {
        duplicatePasskeys += 1;
        const repair = backupRepairFor(record, known);
        if (repair && !backupRepairs.some((entry) => entry.id === repair.id)) {
          backupRepairs.push(repair);
        }
        continue;
      }
      knownPasskeys.set(record.id, record);
      knownPasskeys.set(record.credentialId, record);
      passkeys.push(record);
    } catch (error) {
      warnings.push(`${candidate.rpId || 'passkey'}: ${(error as Error).message}`);
    }
  }

  const totpEntries: StoredTotpEntry[] = [];
  let duplicateTotp = 0;

  for (const candidate of parsed.otp) {
    const record = toStoredTotp(candidate);
    const fingerprint = otpFingerprint(record);
    if (knownOtp.has(fingerprint) || knownOtpIds.has(record.id)) {
      duplicateTotp += 1;
      continue;
    }
    knownOtp.add(fingerprint);
    knownOtpIds.add(record.id);
    totpEntries.push(record);
  }

  return {
    format: parsed.format,
    formatLabel: parsed.formatLabel,
    passkeys,
    totpEntries,
    duplicatePasskeys,
    duplicateTotp,
    backupRepairs,
    warnings,
  };
}

/** Human-readable label for a parsed MFA entry, used in the import preview. */
export function describeOtp(entry: StoredTotpEntry): string {
  return [entry.issuer, entry.account].filter(Boolean).join(' — ') || 'MFA entry';
}
