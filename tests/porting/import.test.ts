import { materialize, parseImport } from '../../src/porting/import';
import { passkeyCsvTemplate, totpCsvTemplate } from '../../src/porting/formats/fenko';
import { buildExport } from '../../src/porting/export';
import { arrayBufferToBase64 } from '../../src/utils/base64';
import { base32Encode } from '../../src/crypto/totp';

const SECRET_B32 = 'JBSWY3DPEHPK3PXP';
const EMPTY_VAULT = { passkeys: [], totpEntries: [] };

let pkcs8 = '';
let rawPublicKey = '';

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  pkcs8 = arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  rawPublicKey = arrayBufferToBase64(await crypto.subtle.exportKey('raw', pair.publicKey));
});

describe('the fillable CSV templates', () => {
  it('imports the MFA template it ships, comments and all', () => {
    const parsed = parseImport('fenko-mfa-template.csv', totpCsvTemplate());

    expect(parsed.format).toBe('fenko-totp-csv');
    expect(parsed.otp).toHaveLength(2);
    expect(parsed.otp[0]).toMatchObject({
      type: 'totp',
      issuer: 'GitHub',
      account: 'you@example.com',
      digits: 6,
      period: 30,
    });
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
  });

  it('tolerates a half-filled MFA row', () => {
    const csv = ['type,issuer,account,secret', `,Fastmail,ali,${SECRET_B32}`].join('\n');
    const parsed = parseImport('filled.csv', csv);

    expect(parsed.otp[0]).toMatchObject({ type: 'totp', digits: 6, period: 30, counter: 0 });
  });

  it('reads the passkey template once a real key is pasted in', async () => {
    const csv = passkeyCsvTemplate().replace('MIGHAgEAMBMGByqGSM49AgEG...', pkcs8);
    const parsed = parseImport('fenko-passkey-template.csv', csv);

    expect(parsed.format).toBe('fenko-passkey-csv');
    const ready = await materialize(parsed, EMPTY_VAULT);
    expect(ready.passkeys[0]).toMatchObject({
      rpId: 'example.com',
      origin: 'https://example.com',
      publicKey: rawPublicKey,
      counter: 0,
    });
    expect(ready.passkeys[0].id).toHaveLength(22); // minted 16-byte credential id
  });
});

describe('materialising an import', () => {
  it('derives the public key and normalises the private key encoding', async () => {
    const csv = ['rpId,userName,privateKey', `github.com,ali,${pkcs8}`].join('\n');
    const ready = await materialize(parseImport('p.csv', csv), EMPTY_VAULT);

    expect(ready.passkeys[0].privateKey).toBe(pkcs8);
    expect(ready.passkeys[0].publicKey).toBe(rawPublicKey);
    expect(ready.passkeys[0].user).toEqual({ id: null, name: 'ali', displayName: 'ali' });
  });

  it('skips passkeys already in the vault and reports how many', async () => {
    const csv = [
      'rpId,userName,credentialId,privateKey',
      `github.com,ali,Y3JlZC1pZA,${pkcs8}`,
    ].join('\n');
    const ready = await materialize(parseImport('p.csv', csv), {
      passkeys: [{ id: 'Y3JlZC1pZA' }],
      totpEntries: [],
    });

    expect(ready.passkeys).toHaveLength(0);
    expect(ready.duplicatePasskeys).toBe(1);
  });

  it('matches existing MFA entries on issuer, account and secret, not on id', async () => {
    const uri = `otpauth://totp/GitHub:ali?secret=${SECRET_B32}&issuer=GitHub`;
    const existing = await materialize(parseImport('a.txt', uri), EMPTY_VAULT);

    const again = await materialize(parseImport('a.txt', uri), {
      passkeys: [],
      totpEntries: existing.totpEntries,
    });

    expect(again.totpEntries).toHaveLength(0);
    expect(again.duplicateTotp).toBe(1);
    expect(existing.totpEntries[0].id).not.toBe('');
  });

  it('collapses duplicates inside a single file', async () => {
    const uri = `otpauth://totp/GitHub:ali?secret=${SECRET_B32}&issuer=GitHub`;
    const ready = await materialize(parseImport('a.txt', [uri, uri].join('\n')), EMPTY_VAULT);

    expect(ready.totpEntries).toHaveLength(1);
    expect(ready.duplicateTotp).toBe(1);
  });

  it('turns an unusable key into a warning rather than losing the whole file', async () => {
    const csv = [
      'rpId,userName,privateKey',
      'broken.example,ali,AAAA',
      `github.com,ali,${pkcs8}`,
    ].join('\n');

    const ready = await materialize(parseImport('p.csv', csv), EMPTY_VAULT);
    expect(ready.passkeys).toHaveLength(1);
    expect(ready.warnings[0]).toMatch(/broken.example/);
  });
});

describe('the native backup format', () => {
  it('round-trips a Fenko export back into vault records', async () => {
    const file = buildExport('fenko-json', {
      passkeys: [
        {
          id: 'Y3JlZC1pZA',
          credentialId: 'Y3JlZC1pZA',
          type: 'public-key',
          rpId: 'github.com',
          origin: 'https://github.com',
          user: { id: 'dXNlcg', name: 'ali', displayName: 'Ali' },
          privateKey: pkcs8,
          publicKey: rawPublicKey,
          createdAt: 1750000000000,
          counter: 3,
        },
      ],
      totpEntries: [
        {
          id: 'totp-1',
          type: 'totp',
          issuer: 'GitHub',
          account: 'ali',
          secretB64: arrayBufferToBase64(new Uint8Array([72, 105]).buffer),
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
          counter: 0,
          createdAt: 1750000000000,
        },
      ],
    });

    const ready = await materialize(parseImport(file.fileName, file.content), EMPTY_VAULT);

    expect(ready.format).toBe('fenko-json');
    expect(ready.passkeys[0]).toMatchObject({
      id: 'Y3JlZC1pZA',
      rpId: 'github.com',
      privateKey: pkcs8,
      publicKey: rawPublicKey,
      counter: 3,
      user: { id: 'dXNlcg', name: 'ali', displayName: 'Ali' },
    });
    expect(ready.totpEntries[0]).toMatchObject({ issuer: 'GitHub', account: 'ali', digits: 6 });
  });

  it('exports MFA to the same CSV columns it imports', async () => {
    const source = await materialize(
      parseImport('a.txt', `otpauth://totp/GitHub:ali?secret=${SECRET_B32}&issuer=GitHub`),
      EMPTY_VAULT
    );

    const file = buildExport('totp-csv', { passkeys: [], totpEntries: source.totpEntries });
    const parsed = parseImport(file.fileName, file.content);

    expect(parsed.format).toBe('fenko-totp-csv');
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
  });

  it('refuses a file no parser recognises', () => {
    expect(() => parseImport('notes.txt', 'just some text')).toThrow(/Unrecognised file/);
  });
});

describe('backup flags on imported passkeys', () => {
  const ON = { backupEligible: true, backupState: true };
  const OFF = { backupEligible: false, backupState: false };

  function bitwardenFile(): string {
    const pkcs8Base64Url = pkcs8.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return JSON.stringify({
      encrypted: false,
      folders: [],
      items: [
        {
          type: 1,
          name: 'Teleport',
          login: {
            username: 'colin',
            fido2Credentials: [
              {
                credentialId: 'Y3JlZC1pZA',
                keyType: 'public-key',
                keyAlgorithm: 'ECDSA',
                keyCurve: 'P-256',
                keyValue: pkcs8Base64Url,
                rpId: 'tele.example.com',
                userHandle: 'dXNlcg',
                userName: 'colin',
                counter: '0',
                discoverable: 'true',
                creationDate: '2026-01-02T03:04:05.000Z',
              },
            ],
          },
        },
      ],
    });
  }

  function stored(extra: Record<string, unknown>) {
    return { id: 'Y3JlZC1pZA', rpId: 'tele.example.com', publicKey: rawPublicKey, ...extra };
  }

  it('imports a passkey from another manager as a synced passkey', async () => {
    const ready = await materialize(parseImport('bitwarden.json', bitwardenFile()), EMPTY_VAULT);
    expect(ready.passkeys[0]).toMatchObject({ ...ON, backupSource: 'imported' });
    expect(ready.backupRepairs).toEqual([]);
  });

  it('fixes a passkey imported before flags existed when the file is imported again', async () => {
    const ready = await materialize(parseImport('bitwarden.json', bitwardenFile()), {
      passkeys: [stored({ ...OFF, backupSource: 'legacy' })],
      totpEntries: [],
    });

    expect(ready.passkeys).toHaveLength(0);
    expect(ready.duplicatePasskeys).toBe(1);
    expect(ready.backupRepairs).toEqual([
      { id: 'Y3JlZC1pZA', rpId: 'tele.example.com', publicKey: rawPublicKey, ...ON },
    ]);
  });

  it('leaves a passkey the user set by hand, or one whose key does not match', async () => {
    for (const existing of [
      stored({ ...OFF, backupSource: 'manual' }),
      stored({ ...OFF, backupSource: 'created' }),
      stored({ ...OFF, backupSource: 'legacy', publicKey: 'someone-else' }),
      stored({ ...ON, backupSource: 'legacy' }),
    ]) {
      const ready = await materialize(parseImport('bitwarden.json', bitwardenFile()), {
        passkeys: [existing],
        totpEntries: [],
      });
      expect(ready.backupRepairs).toEqual([]);
    }
  });

  function nativeExport(extra: Record<string, unknown>): string {
    return buildExport('fenko-json', {
      passkeys: [
        {
          id: 'Y3JlZC1pZA',
          credentialId: 'Y3JlZC1pZA',
          type: 'public-key',
          rpId: 'tele.example.com',
          origin: 'https://tele.example.com',
          user: { id: 'dXNlcg', name: 'colin', displayName: 'colin' },
          privateKey: pkcs8,
          publicKey: rawPublicKey,
          createdAt: 1750000000000,
          counter: 3,
          ...extra,
        },
      ],
      totpEntries: [],
    }).content;
  }

  it('keeps the flags a Fenko backup recorded, including device-bound ones', async () => {
    const ready = await materialize(
      parseImport('fenko.json', nativeExport({ ...OFF, backupSource: 'created' })),
      EMPTY_VAULT
    );
    expect(ready.passkeys[0]).toMatchObject({ ...OFF, backupSource: 'created' });
  });

  it('does not assume a pre-flags Fenko backup holds synced passkeys', async () => {
    const ready = await materialize(parseImport('fenko.json', nativeExport({})), {
      passkeys: [stored({ ...OFF, backupSource: 'legacy' })],
      totpEntries: [],
    });
    expect(ready.backupRepairs).toEqual([]);

    const fresh = await materialize(parseImport('fenko.json', nativeExport({})), EMPTY_VAULT);
    expect(fresh.passkeys[0].backupEligible).toBeUndefined();
  });

  it('round-trips the flags through the passkey CSV', async () => {
    const source = await materialize(
      parseImport('fenko.json', nativeExport({ ...OFF, backupSource: 'created' })),
      EMPTY_VAULT
    );
    const csv = buildExport('passkey-csv', { passkeys: source.passkeys, totpEntries: [] });
    const ready = await materialize(parseImport(csv.fileName, csv.content), EMPTY_VAULT);

    expect(ready.passkeys[0]).toMatchObject({ ...OFF, backupSource: 'imported' });
  });

  it('treats blank CSV flag cells as a passkey from another manager', async () => {
    const csv = passkeyCsvTemplate().replace('MIGHAgEAMBMGByqGSM49AgEG...', pkcs8);
    const ready = await materialize(parseImport('template.csv', csv), EMPTY_VAULT);
    expect(ready.passkeys[0]).toMatchObject({ ...ON, backupSource: 'imported' });
  });
});
