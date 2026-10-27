/**
 * Fenko Vault's own formats: the native JSON backup, and the two fillable
 * CSV templates for people typing secrets in by hand or coming from an app
 * nobody wrote a parser for.
 *
 * Template rows starting with `#` are treated as comments so the file can
 * carry its own instructions.
 */

import { FormatParser, ParsedImport, PortableOtp, PortablePasskey, emptyImport } from '../types';
import { CsvRow, csvHeaders, parseCsv, parseCsvGrid, toCsv } from '../csv';
import { makeOtp } from '../otp';
import { base32Encode } from '../../crypto/totp';

type Json = Record<string, unknown>;

export const TOTP_TEMPLATE_HEADERS = [
  'type',
  'issuer',
  'account',
  'secret',
  'algorithm',
  'digits',
  'period',
  'counter',
];

export const PASSKEY_TEMPLATE_HEADERS = [
  'rpId',
  'userName',
  'userDisplayName',
  'userHandle',
  'credentialId',
  'privateKey',
  'counter',
];

function asObject(value: unknown): Json | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : null;
}

function str(value: unknown): string {
  return value == null ? '' : String(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function positiveNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0;
}

/** Drop `#` comment rows before the header-keyed parse. */
function withoutComments(text: string): string {
  const grid = parseCsvGrid(text).filter((cells) => !cells[0]?.trim().startsWith('#'));
  return grid.map((cells) => cells.map(quote).join(',')).join('\n');
}

function quote(cell: string): string {
  return /[",\r\n]/.test(cell) ? `"${cell.replace(/"/g, '""')}"` : cell;
}

function headersOf(text: string): string[] {
  return csvHeaders(withoutComments(text));
}

/** The native `{passkeys, totpEntries}` backup this extension writes. */
export const fenkoJson: FormatParser = {
  id: 'fenko-json',
  label: 'Fenko Vault backup (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    return Boolean(json && (Array.isArray(json.passkeys) || Array.isArray(json.totpEntries)));
  },

  parse(input) {
    const result = emptyImport(fenkoJson.id, fenkoJson.label);
    const json = asObject(input.json) as Json;

    for (const raw of (json.passkeys as unknown[]) || []) {
      const passkey = asObject(raw);
      if (!passkey?.privateKey || !passkey.rpId) continue;
      const user = asObject(passkey.user) || {};
      result.passkeys.push({
        credentialId: str(passkey.credentialId || passkey.id),
        rpId: str(passkey.rpId),
        userName: str(user.name),
        userDisplayName: str(user.displayName),
        userHandle: user.id == null ? null : str(user.id),
        privateKey: passkey.privateKey,
        counter: Number(passkey.counter) || 0,
        createdAt: Number(passkey.createdAt) || Date.now(),
        ...(nonEmptyString(passkey.id) && { id: passkey.id }),
        ...(nonEmptyString(passkey.prfKey) && { prfKey: passkey.prfKey }),
      });
    }

    for (const raw of (json.totpEntries as unknown[]) || []) {
      const entry = asObject(raw);
      if (!entry?.secretB64) continue;
      try {
        result.otp.push({
          ...makeOtp({
            type: entry.type,
            issuer: entry.issuer,
            account: entry.account,
            secret: entry.secretB64,
            secretEncoding: 'base64',
            algorithm: entry.algorithm,
            digits: entry.digits,
            period: entry.period,
            counter: entry.counter,
          }),
          ...(nonEmptyString(entry.id) && { id: entry.id }),
          ...(positiveNumber(entry.createdAt) && { createdAt: entry.createdAt }),
          ...(positiveNumber(entry.lastUsed) && { lastUsed: entry.lastUsed }),
        });
      } catch (error) {
        result.warnings.push(`TOTP ${str(entry.issuer)}: ${(error as Error).message}`);
      }
    }

    return result;
  },
};

/** The fillable MFA template: one seed per row. */
export const fenkoTotpCsv: FormatParser = {
  id: 'fenko-totp-csv',
  label: 'Fenko MFA template (CSV)',
  extensions: ['.csv'],

  detect(input) {
    if (input.json !== undefined) return false;
    const headers = headersOf(input.text);
    return headers.includes('secret') && (headers.includes('issuer') || headers.includes('account'));
  },

  parse(input) {
    const result = emptyImport(fenkoTotpCsv.id, fenkoTotpCsv.label);
    parseCsv(withoutComments(input.text)).forEach((row: CsvRow, index) => {
      if (!row.secret) return;
      try {
        result.otp.push(
          makeOtp({
            type: row.type,
            issuer: row.issuer,
            account: row.account,
            secret: row.secret,
            algorithm: row.algorithm,
            digits: row.digits,
            period: row.period,
            counter: row.counter,
          })
        );
      } catch (error) {
        result.warnings.push(`Row ${index + 1}: ${(error as Error).message}`);
      }
    });
    return result;
  },
};

/** The fillable passkey template: one credential per row. */
export const fenkoPasskeyCsv: FormatParser = {
  id: 'fenko-passkey-csv',
  label: 'Fenko passkey template (CSV)',
  extensions: ['.csv'],

  detect(input) {
    if (input.json !== undefined) return false;
    const headers = headersOf(input.text);
    return headers.includes('rpid') && headers.includes('privatekey');
  },

  parse(input) {
    const result = emptyImport(fenkoPasskeyCsv.id, fenkoPasskeyCsv.label);
    parseCsv(withoutComments(input.text)).forEach((row: CsvRow) => {
      if (!row.privatekey || !row.rpid) return;
      result.passkeys.push({
        credentialId: row.credentialid || '',
        rpId: row.rpid,
        userName: row.username || '',
        userDisplayName: row.userdisplayname || row.username || '',
        userHandle: row.userhandle || null,
        privateKey: row.privatekey,
        counter: Number(row.counter) || 0,
        createdAt: Date.now(),
      });
    });
    return result;
  },
};

const TEMPLATE_TOTP_NOTES = [
  '# Fenko Vault MFA import template.',
  '# secret: the base32 key the site shows next to its QR code (spaces are fine).',
  '# type: totp (default) or hotp. algorithm: SHA1 (default), SHA256 or SHA512.',
  '# digits: 6 or 8. period: seconds, 30 unless the site says otherwise.',
  '# counter: HOTP only. Delete the example rows before importing.',
];

const TEMPLATE_PASSKEY_NOTES = [
  '# Fenko Vault passkey import template.',
  '# privateKey: base64 PKCS#8 for an ES256 (P-256) key. PEM and JWK also work.',
  '# credentialId / userHandle: base64url. Leave credentialId blank to mint one.',
  '# Delete the example row before importing.',
];

export function totpCsvTemplate(): string {
  const body = toCsv(TOTP_TEMPLATE_HEADERS, [
    ['totp', 'GitHub', 'you@example.com', 'JBSWY3DPEHPK3PXP', 'SHA1', 6, 30, 0],
    ['totp', 'AWS', 'root@example.com', 'KRSXG5CTMVRXEZLU', 'SHA1', 6, 30, 0],
  ]);
  return `${TEMPLATE_TOTP_NOTES.join('\n')}\n${body}`;
}

export function passkeyCsvTemplate(): string {
  const body = toCsv(PASSKEY_TEMPLATE_HEADERS, [
    ['example.com', 'you@example.com', 'Your Name', '', '', 'MIGHAgEAMBMGByqGSM49AgEG...', 0],
  ]);
  return `${TEMPLATE_PASSKEY_NOTES.join('\n')}\n${body}`;
}

/** Write MFA entries back out in the same template shape. */
export function totpToCsv(entries: PortableOtp[]): string {
  return toCsv(
    TOTP_TEMPLATE_HEADERS,
    entries.map((entry) => [
      entry.type,
      entry.issuer,
      entry.account,
      base32Encode(entry.secret),
      entry.algorithm,
      entry.digits,
      entry.period,
      entry.counter,
    ])
  );
}

/** Write passkeys back out in the same template shape. */
export function passkeysToCsv(passkeys: PortablePasskey[]): string {
  return toCsv(
    PASSKEY_TEMPLATE_HEADERS,
    passkeys.map((passkey) => [
      passkey.rpId,
      passkey.userName,
      passkey.userDisplayName,
      passkey.userHandle || '',
      passkey.credentialId,
      str(passkey.privateKey),
      passkey.counter,
    ])
  );
}

export const FENKO_PARSERS: FormatParser[] = [fenkoJson, fenkoPasskeyCsv, fenkoTotpCsv];

export type { ParsedImport };
