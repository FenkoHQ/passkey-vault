import { parseImport } from '../../src/porting/import';
import { base32Encode } from '../../src/crypto/totp';
import { arrayBufferToBase64URL } from '../../src/utils/base64';

const SECRET_B32 = 'JBSWY3DPEHPK3PXP';
const URI = `otpauth://totp/GitHub:ali%40example.com?secret=${SECRET_B32}&issuer=GitHub`;

let pkcs8Base64Url = '';

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  pkcs8Base64Url = arrayBufferToBase64URL(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
});

describe('password manager imports', () => {
  it('reads Bitwarden JSON including its passkeys', () => {
    const text = JSON.stringify({
      encrypted: false,
      folders: [],
      items: [
        {
          type: 1,
          name: 'GitHub',
          login: {
            username: 'ali',
            password: 'hunter2',
            totp: URI,
            fido2Credentials: [
              {
                // Bitwarden writes 16-byte credential IDs as GUIDs.
                credentialId: '674880d4-06ed-1af1-e8dd-2d901d9dbd3d',
                keyType: 'public-key',
                keyAlgorithm: 'ECDSA',
                keyCurve: 'P-256',
                keyValue: pkcs8Base64Url,
                rpId: 'github.com',
                userHandle: 'dXNlci1oYW5kbGU',
                userName: 'ali@example.com',
                userDisplayName: 'Ali',
                counter: '0',
                discoverable: 'true',
                creationDate: '2026-01-02T03:04:05.000Z',
              },
            ],
          },
        },
      ],
    });

    const parsed = parseImport('bitwarden.json', text);
    expect(parsed.format).toBe('bitwarden-json');
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
    expect(parsed.passkeys[0]).toMatchObject({
      rpId: 'github.com',
      userName: 'ali@example.com',
      userDisplayName: 'Ali',
      credentialId: 'Z0iA1AbtGvHo3S2QHZ29PQ',
    });
    expect(parsed.passkeys[0].createdAt).toBe(Date.parse('2026-01-02T03:04:05.000Z'));
  });

  it('decodes Bitwarden "b64."-prefixed credential IDs', () => {
    const rawId = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64url');
    const text = JSON.stringify({
      encrypted: false,
      items: [
        {
          type: 1,
          name: 'Example',
          login: {
            username: 'ali',
            fido2Credentials: [
              { credentialId: `b64.${rawId}`, keyValue: pkcs8Base64Url, rpId: 'example.com' },
            ],
          },
        },
      ],
    });

    expect(parseImport('bitwarden.json', text).passkeys[0].credentialId).toBe(rawId);
  });

  it('refuses an encrypted Bitwarden export', () => {
    const text = JSON.stringify({ encrypted: true, items: [], folders: [] });
    expect(() => parseImport('bitwarden.json', text)).toThrow(/encrypted/i);
  });

  it('reads a Bitwarden CSV and flags the missing passkeys', () => {
    const csv = [
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
      `,,login,GitHub,,,0,https://github.com,ali,hunter2,${SECRET_B32}`,
    ].join('\n');

    const parsed = parseImport('bitwarden.csv', csv);
    expect(parsed.format).toBe('bitwarden-csv');
    expect(parsed.otp[0]).toMatchObject({ issuer: 'GitHub', account: 'ali' });
    expect(parsed.warnings.join(' ')).toMatch(/JSON export/);
  });

  it('reads a 1Password CSV', () => {
    const csv = ['Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes', `GitHub,https://github.com,ali,hunter2,${URI},,,,`].join('\n');
    const parsed = parseImport('1password.csv', csv);
    expect(parsed.format).toBe('1password-csv');
    expect(parsed.otp[0].issuer).toBe('GitHub');
  });

  it('reads an Apple Passwords CSV through the same OTPAuth column', () => {
    const csv = ['Title,URL,Username,Password,Notes,OTPAuth', `GitHub,https://github.com,ali,hunter2,,${URI}`].join('\n');
    const parsed = parseImport('Passwords.csv', csv);
    expect(parsed.format).toBe('1password-csv');
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
  });

  it('reads a 1PUX export.data payload', () => {
    const text = JSON.stringify({
      accounts: [
        {
          attrs: { name: 'Personal' },
          vaults: [
            {
              attrs: { name: 'Private' },
              items: [
                {
                  item: {
                    overview: { title: 'GitHub' },
                    details: {
                      loginFields: [{ designation: 'username', value: 'ali' }],
                      sections: [{ fields: [{ value: { totp: URI } }] }],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const parsed = parseImport('export.data', text);
    expect(parsed.format).toBe('1password-1pux');
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
  });

  it('reads Proton Pass including its passkeys', () => {
    const text = JSON.stringify({
      version: '1.31.5',
      vaults: {
        vaultA: {
          name: 'Personal',
          items: [
            {
              data: {
                metadata: { name: 'GitHub', note: '' },
                content: {
                  itemUsername: 'ali',
                  totpUri: URI,
                  passkeys: [
                    {
                      keyId: 'k1',
                      content: pkcs8Base64Url,
                      domain: 'github.com',
                      rpId: 'github.com',
                      userName: 'ali@example.com',
                      userDisplayName: 'Ali',
                      userHandle: 'dXNlci1oYW5kbGU',
                      credentialId: 'Y3JlZC1pZA',
                      createTime: 1750000000,
                    },
                  ],
                },
              },
            },
          ],
        },
      },
    });

    const parsed = parseImport('proton-pass.json', text);
    expect(parsed.format).toBe('proton-pass');
    expect(parsed.otp).toHaveLength(1);
    expect(parsed.passkeys[0]).toMatchObject({ rpId: 'github.com', credentialId: 'Y3JlZC1pZA' });
    expect(parsed.passkeys[0].createdAt).toBe(1750000000 * 1000);
  });

  it('reads Dashlane JSON, both logins and passkeys', () => {
    const text = JSON.stringify({
      AUTHENTIFIANT: [{ title: 'GitHub', login: 'ali', domain: 'github.com', otpUrl: URI }],
      PASSKEY: [
        {
          credentialId: 'Y3JlZC1pZA',
          rpId: 'github.com',
          userDisplayName: 'ali@example.com',
          userHandle: 'dXNlci1oYW5kbGU',
          privateKey: pkcs8Base64Url,
          counter: 0,
        },
      ],
    });

    const parsed = parseImport('dashlane.json', text);
    expect(parsed.format).toBe('dashlane-json');
    expect(parsed.otp).toHaveLength(1);
    expect(parsed.passkeys).toHaveLength(1);
  });

  it('reads a Dashlane CSV secret column', () => {
    const csv = ['username,title,password,url,otpSecret', `ali,GitHub,hunter2,https://github.com,${SECRET_B32}`].join('\n');
    const parsed = parseImport('dashlane.csv', csv);
    expect(parsed.format).toBe('dashlane-csv');
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
  });

  it('reads a KeePassXC CSV and warns about the kdbx-only passkeys', () => {
    const csv = ['Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created', `Root,GitHub,ali,hunter2,https://github.com,,${URI},0,,`].join('\n');
    const parsed = parseImport('keepassxc.csv', csv);
    expect(parsed.format).toBe('keepass-csv');
    expect(parsed.otp).toHaveLength(1);
    expect(parsed.warnings.join(' ')).toMatch(/kdbx/);
  });

  it('reads a LastPass vault CSV', () => {
    const csv = ['url,username,password,totp,extra,name,grouping,fav', `https://github.com,ali,hunter2,${SECRET_B32},,GitHub,,0`].join('\n');
    const parsed = parseImport('lastpass.csv', csv);
    expect(parsed.format).toBe('lastpass-csv');
    expect(parsed.otp[0]).toMatchObject({ issuer: 'GitHub', account: 'ali' });
  });

  it('digs otpauth URIs out of a Keeper CSV custom field', () => {
    const csv = `Personal,GitHub,ali,hunter2,https://github.com,note,"TFC:Keeper:${URI}"`;
    const parsed = parseImport('keeper.csv', csv);
    expect(parsed.format).toBe('keeper-csv');
    expect(base32Encode(parsed.otp[0].secret)).toBe(SECRET_B32);
  });

  it('explains that browser password CSVs carry nothing importable', () => {
    const csv = ['name,url,username,password', 'github.com,https://github.com,ali,hunter2'].join('\n');
    expect(() => parseImport('chrome-passwords.csv', csv)).toThrow(/cannot export passkeys/i);
  });
});
