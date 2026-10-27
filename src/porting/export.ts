/**
 * Export pipeline: vault records out to the formats other providers read.
 *
 * Every payload here is plaintext by design — it is what the receiving app
 * expects. The encrypted backup in the popup stays the safe default; these
 * are for moving to another provider and should be deleted afterwards.
 */

import { base32Encode } from '../crypto/totp';
import { StoredTotpEntry } from '../crypto/totp-store';
import { base64ToUint8Array } from '../utils/base64';
import { backupSourceOf, hasBackupFlags, normalizeBackupFlags } from '../sync/backup-flags';
import { buildOtpauthUri } from './otpauth';
import { buildCxf } from './formats/cxf';
import { passkeysToCsv, totpToCsv } from './formats/fenko';
import { PortableOtp, PortablePasskey } from './types';
import { StoredPasskeyRecord } from './import';

const JSON_MIME = 'application/json';
const CSV_MIME = 'text/csv';
const TEXT_MIME = 'text/plain';
const EXPORTER_RP_ID = 'fenko.nz';
const EXPORTER_NAME = 'Fenko Vault';

export type ExportFormat = 'fenko-json' | 'cxf' | 'otpauth-txt' | 'totp-csv' | 'passkey-csv';

export interface VaultSnapshot {
  passkeys: StoredPasskeyRecord[];
  totpEntries: StoredTotpEntry[];
}

export interface ExportFile {
  fileName: string;
  mimeType: string;
  content: string;
}

export interface ExportFormatInfo {
  id: ExportFormat;
  label: string;
  hint: string;
  includes: 'both' | 'passkeys' | 'totp';
}

export const EXPORT_FORMATS: ExportFormatInfo[] = [
  {
    id: 'fenko-json',
    label: 'Fenko Vault backup (JSON)',
    hint: 'Everything, ready to restore into another Fenko Vault.',
    includes: 'both',
  },
  {
    id: 'cxf',
    label: 'Credential Exchange Format (CXF)',
    hint: 'Passkeys and MFA for Apple, Google, 1Password, Bitwarden, Dashlane.',
    includes: 'both',
  },
  {
    id: 'otpauth-txt',
    label: 'otpauth:// URI list (TXT)',
    hint: 'MFA only. Reads into Aegis, Ente Auth, 2FAS and most authenticators.',
    includes: 'totp',
  },
  {
    id: 'totp-csv',
    label: 'MFA spreadsheet (CSV)',
    hint: 'MFA only, in the same columns as the import template.',
    includes: 'totp',
  },
  {
    id: 'passkey-csv',
    label: 'Passkey spreadsheet (CSV)',
    hint: 'Passkeys only, private keys in base64 PKCS#8.',
    includes: 'passkeys',
  },
];

export function toPortableOtp(entry: StoredTotpEntry): PortableOtp {
  return {
    type: entry.type,
    issuer: entry.issuer,
    account: entry.account,
    secret: base64ToUint8Array(entry.secretB64),
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
  };
}

export function toPortablePasskey(record: StoredPasskeyRecord): PortablePasskey {
  return {
    credentialId: record.credentialId || record.id,
    rpId: record.rpId,
    userName: record.user?.name || '',
    userDisplayName: record.user?.displayName || '',
    userHandle: record.user?.id ?? null,
    privateKey: record.privateKey,
    counter: record.counter || 0,
    createdAt: record.createdAt || Date.now(),
    backup: hasBackupFlags(record)
      ? {
          flags: normalizeBackupFlags(record.backupEligible === true, record.backupState === true),
          source: backupSourceOf(record) ?? 'imported',
        }
      : 'unknown',
  };
}

function dateStamp(): string {
  return new Date().toISOString().slice(0, 10);
}

export function buildExport(format: ExportFormat, vault: VaultSnapshot): ExportFile {
  const otp = (vault.totpEntries || []).map(toPortableOtp);
  const passkeys = (vault.passkeys || []).map(toPortablePasskey);
  const stamp = dateStamp();

  switch (format) {
    case 'cxf':
      return {
        fileName: `fenko-vault-cxf-${stamp}.json`,
        mimeType: JSON_MIME,
        content: JSON.stringify(
          buildCxf({
            passkeys,
            otp,
            exporterRpId: EXPORTER_RP_ID,
            exporterDisplayName: EXPORTER_NAME,
          }),
          null,
          2
        ),
      };

    case 'otpauth-txt':
      return {
        fileName: `fenko-vault-mfa-${stamp}.txt`,
        mimeType: TEXT_MIME,
        content: otp.map(buildOtpauthUri).join('\n') + '\n',
      };

    case 'totp-csv':
      return {
        fileName: `fenko-vault-mfa-${stamp}.csv`,
        mimeType: CSV_MIME,
        content: totpToCsv(otp),
      };

    case 'passkey-csv':
      return {
        fileName: `fenko-vault-passkeys-${stamp}.csv`,
        mimeType: CSV_MIME,
        content: passkeysToCsv(passkeys),
      };

    case 'fenko-json':
    default:
      return {
        fileName: `fenko-vault-export-${stamp}.json`,
        mimeType: JSON_MIME,
        content: JSON.stringify(
          {
            version: '1.0',
            exportType: 'full',
            exportedAt: new Date().toISOString(),
            passkeys: vault.passkeys,
            totpEntries: vault.totpEntries,
          },
          null,
          2
        ),
      };
  }
}

/** QR-friendly single-entry URI, used by the "show as QR" action. */
export function otpauthFor(entry: StoredTotpEntry): string {
  return buildOtpauthUri(toPortableOtp(entry));
}

export function base32For(entry: StoredTotpEntry): string {
  return base32Encode(base64ToUint8Array(entry.secretB64));
}
