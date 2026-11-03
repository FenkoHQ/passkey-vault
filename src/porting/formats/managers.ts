/**
 * Importers for the password managers.
 *
 * These files mix logins, MFA seeds and (for a few vendors) passkeys. We take
 * the two kinds of secret the vault stores and ignore the passwords: Fenko
 * Vault is not a password manager.
 */

import { FormatParser, ImportInput, ParsedImport, PortablePasskey, emptyImport } from '../types';
import { otpFromManagerField, otpFromUri } from '../otp';
import { parseCsv, parseCsvGrid, csvHeaders, CsvRow } from '../csv';
import { decodeBitwardenCredentialId } from '../../sync/credential-ids';

type Json = Record<string, unknown>;

function asObject(value: unknown): Json | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string {
  return value == null ? '' : String(value);
}

function hasHeaders(input: ImportInput, required: string[]): boolean {
  if (input.json !== undefined) return false;
  const headers = csvHeaders(input.text);
  return required.every((name) => headers.includes(name));
}

/** Pull the TOTP cell out of a manager CSV row, whatever the column is named. */
function otpFromRow(result: ParsedImport, row: CsvRow, columns: string[], index: number): void {
  const issuer = row.name || row.title || row.grouping || hostOf(row.url || row.loginuri || '');
  const account = row.username || row.loginusername || row.login || row.email || '';

  for (const column of columns) {
    const value = row[column];
    if (!value) continue;
    try {
      const otp = otpFromManagerField(value, issuer, account);
      if (otp) result.otp.push(otp);
    } catch (error) {
      result.warnings.push(`Row ${index + 1}: ${(error as Error).message}`);
    }
    return;
  }
}

function hostOf(url: string): string {
  if (!url) return '';
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

function passkeyFrom(fields: Partial<PortablePasskey> & { privateKey: unknown }): PortablePasskey {
  return {
    credentialId: str(fields.credentialId),
    rpId: str(fields.rpId),
    userName: str(fields.userName),
    userDisplayName: str(fields.userDisplayName) || str(fields.userName),
    userHandle: fields.userHandle == null ? null : str(fields.userHandle),
    privateKey: fields.privateKey,
    counter: Number(fields.counter) || 0,
    createdAt: Number(fields.createdAt) || Date.now(),
  };
}

// ==================== Bitwarden ====================

/** Bitwarden JSON — TOTP in `login.totp`, passkeys in `login.fido2Credentials`. */
export const bitwardenJson: FormatParser = {
  id: 'bitwarden-json',
  label: 'Bitwarden (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    if (!json || !Array.isArray(json.items)) return false;
    return 'encrypted' in json || 'folders' in json || asArray(json.items).some(isBitwardenItem);
  },

  parse(input) {
    const result = emptyImport(bitwardenJson.id, bitwardenJson.label);
    const json = asObject(input.json) as Json;

    if (json.encrypted === true) {
      throw new Error('This Bitwarden export is encrypted. Re-export with "Password protected" off.');
    }

    asArray(json.items).forEach((raw, index) => {
      const item = asObject(raw);
      const login = item && asObject(item.login);
      if (!login) return;

      const name = str(item.name);
      const username = str(login.username);

      try {
        const otp = otpFromManagerField(str(login.totp), name, username);
        if (otp) result.otp.push(otp);
      } catch (error) {
        result.warnings.push(`${name || `Item ${index + 1}`}: ${(error as Error).message}`);
      }

      asArray(login.fido2Credentials).forEach((rawCredential) => {
        const credential = asObject(rawCredential);
        if (!credential?.keyValue) return;
        // Bitwarden writes credential IDs as GUIDs or "b64."-prefixed, not base64url.
        const credentialId = str(credential.credentialId);
        result.passkeys.push(
          passkeyFrom({
            credentialId: decodeBitwardenCredentialId(credentialId) ?? credentialId,
            rpId: str(credential.rpId),
            userName: str(credential.userName) || username,
            userDisplayName: str(credential.userDisplayName),
            userHandle: credential.userHandle == null ? null : str(credential.userHandle),
            privateKey: credential.keyValue,
            counter: Number(credential.counter) || 0,
            createdAt: Date.parse(str(credential.creationDate)) || Date.now(),
          })
        );
      });
    });

    return result;
  },
};

function isBitwardenItem(raw: unknown): boolean {
  const item = asObject(raw);
  return Boolean(item && 'type' in item && ('login' in item || 'secureNote' in item));
}

export const bitwardenCsv: FormatParser = {
  id: 'bitwarden-csv',
  label: 'Bitwarden (CSV)',
  extensions: ['.csv'],

  detect(input) {
    return hasHeaders(input, ['loginusername', 'logintotp']);
  },

  parse(input) {
    const result = emptyImport(bitwardenCsv.id, bitwardenCsv.label);
    parseCsv(input.text).forEach((row, index) => otpFromRow(result, row, ['logintotp'], index));
    result.warnings.push('Bitwarden CSV exports cannot contain passkeys — use its JSON export.');
    return result;
  },
};

// ==================== 1Password ====================

/** 1Password 1PUX (`export.data` inside the .1pux archive). */
export const onepasswordPux: FormatParser = {
  id: '1password-1pux',
  label: '1Password (1PUX export.data)',
  extensions: ['.json', '.1pux'],

  detect(input) {
    const json = asObject(input.json);
    return Boolean(json && json.accounts && Array.isArray(json.accounts) && findPuxVaults(json));
  },

  parse(input) {
    const result = emptyImport(onepasswordPux.id, onepasswordPux.label);
    const json = asObject(input.json) as Json;

    for (const vault of findPuxVaults(json) || []) {
      asArray(asObject(vault)?.items).forEach((rawItem, index) => {
        const item = asObject(rawItem);
        const details = item && asObject(item.item);
        const overview = details && asObject(details.overview);
        const title = str(overview?.title);

        collectPuxFields(details, title, result, index);
      });
    }

    return result;
  },
};

function findPuxVaults(json: Json): unknown[] | null {
  const vaults: unknown[] = [];
  for (const account of asArray(json.accounts)) {
    vaults.push(...asArray(asObject(account)?.vaults));
  }
  return vaults.length > 0 ? vaults : null;
}

function collectPuxFields(
  details: Json | null,
  title: string,
  result: ParsedImport,
  index: number
): void {
  if (!details) return;

  const sections = asArray(details.details && asObject(details.details)?.sections);
  const loginFields = asArray(details.details && asObject(details.details)?.loginFields);
  const username = str(loginFields.map(asObject).find((f) => f?.designation === 'username')?.value);

  for (const rawSection of sections) {
    for (const rawField of asArray(asObject(rawSection)?.fields)) {
      const value = asObject(asObject(rawField)?.value);
      const totp = str(value?.totp);
      if (!totp) continue;
      try {
        const otp = otpFromManagerField(totp, title, username);
        if (otp) result.otp.push(otp);
      } catch (error) {
        result.warnings.push(`${title || `Item ${index + 1}`}: ${(error as Error).message}`);
      }
    }
  }
}

// Apple's Passwords app writes the same OTPAuth column, so this reader covers
// both. The id stays 1password-csv for continuity.
export const onepasswordCsv: FormatParser = {
  id: '1password-csv',
  label: '1Password / Apple Passwords (CSV)',
  extensions: ['.csv'],

  detect(input) {
    return hasHeaders(input, ['otpauth']) || hasHeaders(input, ['title', 'otpauth']);
  },

  parse(input) {
    const result = emptyImport(onepasswordCsv.id, onepasswordCsv.label);
    parseCsv(input.text).forEach((row, index) => otpFromRow(result, row, ['otpauth'], index));
    result.warnings.push('These CSV exports cannot contain passkeys — use a CXF export instead.');
    return result;
  },
};

// ==================== Proton Pass ====================

/** Proton Pass JSON — TOTP in `content.totpUri`, passkeys in `content.passkeys`. */
export const protonPass: FormatParser = {
  id: 'proton-pass',
  label: 'Proton Pass (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    return Boolean(json && asObject(json.vaults) && 'version' in json);
  },

  parse(input) {
    const result = emptyImport(protonPass.id, protonPass.label);
    const vaults = asObject((asObject(input.json) as Json).vaults) || {};

    for (const rawVault of Object.values(vaults)) {
      asArray(asObject(rawVault)?.items).forEach((rawItem, index) => {
        const data = asObject(asObject(rawItem)?.data);
        const content = data && asObject(data.content);
        if (!content) return;

        const title = str(asObject(data.metadata)?.name);
        const username = str(content.itemUsername || content.itemEmail || content.username);

        try {
          const otp = otpFromManagerField(str(content.totpUri), title, username);
          if (otp) result.otp.push(otp);
        } catch (error) {
          result.warnings.push(`${title || `Item ${index + 1}`}: ${(error as Error).message}`);
        }

        asArray(content.passkeys).forEach((rawPasskey) => {
          const passkey = asObject(rawPasskey);
          if (!passkey?.content) return;
          result.passkeys.push(
            passkeyFrom({
              credentialId: str(passkey.credentialId),
              rpId: str(passkey.rpId || passkey.domain),
              userName: str(passkey.userName),
              userDisplayName: str(passkey.userDisplayName),
              userHandle: passkey.userHandle == null ? null : str(passkey.userHandle),
              privateKey: passkey.content,
              createdAt: Number(passkey.createTime) * 1000 || Date.now(),
            })
          );
        });
      });
    }

    return result;
  },
};

// ==================== Dashlane ====================

/** Dashlane personal-data JSON (`AUTHENTIFIANT`, plus `PASSKEY` when present). */
export const dashlaneJson: FormatParser = {
  id: 'dashlane-json',
  label: 'Dashlane (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    return Boolean(json && (Array.isArray(json.AUTHENTIFIANT) || Array.isArray(json.PASSKEY)));
  },

  parse(input) {
    const result = emptyImport(dashlaneJson.id, dashlaneJson.label);
    const json = asObject(input.json) as Json;

    asArray(json.AUTHENTIFIANT).forEach((rawItem, index) => {
      const item = asObject(rawItem);
      if (!item) return;
      const field = str(item.otpUrl || item.otpSecret);
      if (!field) return;
      try {
        const otp = otpFromManagerField(field, str(item.title || item.domain), str(item.login));
        if (otp) result.otp.push(otp);
      } catch (error) {
        result.warnings.push(`${str(item.title) || `Item ${index + 1}`}: ${(error as Error).message}`);
      }
    });

    asArray(json.PASSKEY).forEach((rawPasskey) => {
      const passkey = asObject(rawPasskey);
      if (!passkey?.privateKey) return;
      result.passkeys.push(
        passkeyFrom({
          credentialId: str(passkey.credentialId),
          rpId: str(passkey.rpId),
          userName: str(passkey.userDisplayName || passkey.itemName),
          userDisplayName: str(passkey.userDisplayName),
          userHandle: passkey.userHandle == null ? null : str(passkey.userHandle),
          privateKey: passkey.privateKey,
          counter: Number(passkey.counter) || 0,
        })
      );
    });

    return result;
  },
};

export const dashlaneCsv: FormatParser = {
  id: 'dashlane-csv',
  label: 'Dashlane (CSV)',
  extensions: ['.csv'],

  detect(input) {
    return hasHeaders(input, ['otpsecret']) || hasHeaders(input, ['otpurl']);
  },

  parse(input) {
    const result = emptyImport(dashlaneCsv.id, dashlaneCsv.label);
    parseCsv(input.text).forEach((row, index) =>
      otpFromRow(result, row, ['otpurl', 'otpsecret'], index)
    );
    return result;
  },
};

// ==================== KeePassXC / LastPass / Keeper ====================

export const keepassCsv: FormatParser = {
  id: 'keepass-csv',
  label: 'KeePassXC (CSV)',
  extensions: ['.csv'],

  detect(input) {
    return hasHeaders(input, ['group', 'title', 'totp']);
  },

  parse(input) {
    const result = emptyImport(keepassCsv.id, keepassCsv.label);
    parseCsv(input.text).forEach((row, index) => otpFromRow(result, row, ['totp'], index));
    result.warnings.push(
      'KeePassXC stores passkeys inside the .kdbx database; its CSV export leaves them out.'
    );
    return result;
  },
};

export const lastpassCsv: FormatParser = {
  id: 'lastpass-csv',
  label: 'LastPass (CSV)',
  extensions: ['.csv'],

  detect(input) {
    return hasHeaders(input, ['url', 'username', 'totp']);
  },

  parse(input) {
    const result = emptyImport(lastpassCsv.id, lastpassCsv.label);
    parseCsv(input.text).forEach((row, index) => otpFromRow(result, row, ['totp'], index));
    return result;
  },
};

export const keeperCsv: FormatParser = {
  id: 'keeper-csv',
  label: 'Keeper (CSV)',
  extensions: ['.csv'],

  detect(input) {
    if (input.json !== undefined) return false;
    return /TFC:Keeper/i.test(input.text) && csvHeaders(input.text).length >= 5;
  },

  parse(input) {
    const result = emptyImport(keeperCsv.id, keeperCsv.label);

    // Keeper's CSV is headerless: folder,title,login,password,url,notes, then
    // custom fields as `name:value` pairs, with TOTP as `TFC:Keeper:<uri>`.
    // Read the raw grid — there is no header row to key off.
    parseCsvGrid(input.text).forEach((cells) => {
      for (const cell of cells) {
        const match = /otpauth:\/\/\S+/i.exec(cell);
        if (!match) continue;
        try {
          result.otp.push(otpFromUri(match[0]));
        } catch (error) {
          result.warnings.push((error as Error).message);
        }
      }
    });

    return result;
  },
};

/**
 * Browser password CSVs (Chrome, Edge, Safari, Firefox). They hold no MFA
 * seeds and no passkeys — say so instead of importing an empty file.
 */
export const browserCsv: FormatParser = {
  id: 'browser-csv',
  label: 'Browser password export (CSV)',
  extensions: ['.csv'],

  detect(input) {
    return hasHeaders(input, ['name', 'url', 'username', 'password']) && !hasHeaders(input, ['totp']);
  },

  parse() {
    throw new Error(
      'Browser password exports contain no MFA seeds or passkeys. Chrome, Edge and Safari cannot ' +
        'export passkeys yet — import from your password manager instead.'
    );
  },
};

export const MANAGER_PARSERS: FormatParser[] = [
  bitwardenJson,
  protonPass,
  dashlaneJson,
  onepasswordPux,
  bitwardenCsv,
  keepassCsv,
  lastpassCsv,
  dashlaneCsv,
  onepasswordCsv,
  keeperCsv,
  browserCsv,
];
