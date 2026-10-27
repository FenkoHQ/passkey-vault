/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: a damaged passkey record.
 *
 * Records reach the vault from imports, from backups made by older builds,
 * and from sync peers on other platforms. One bad record must cost that one
 * passkey at most: the rest of the vault keeps working on every site, and
 * using the bad one fails with an error instead of a hang.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { authenticate, outcome, register } from '../helpers/ceremony';
import { authenticationJSON, requestOptionsFromJSON } from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const damage: Array<[string, (passkeys: any[]) => void]> = [
  ['a null entry', (p) => p.push(null)],
  ['a bare string entry', (p) => p.push('garbage')],
  ['a record with no rpId', (p) => p.push({ id: 'x', credentialId: 'x', privateKey: 'AAAA' })],
  [
    'a record with no user',
    (p) => p.push({ ...p[0], id: 'y', credentialId: 'y', user: undefined }),
  ],
  [
    'a record with a numeric rpId',
    (p) => p.push({ ...p[0], id: 'z', credentialId: 'z', rpId: 42 }),
  ],
];

describe.each(damage)('a vault holding %s', (_label, corrupt) => {
  it('still signs in with its good passkey', async () => {
    const registration = await register();
    corrupt(vault.storage.passkeys as any[]);

    await authenticate(registration, {
      allowCredentials: [{ type: 'public-key', id: registration.record.id }],
    });
  });

  it('still registers new passkeys', async () => {
    await register();
    corrupt(vault.storage.passkeys as any[]);

    await register();
  });

  it('still lists its passkeys for the popup', async () => {
    await register();
    corrupt(vault.storage.passkeys as any[]);

    const response = await vault.send({ type: 'LIST_PASSKEYS' });
    expect(response.success).toBe(true);
  });
});

describe('a damaged key', () => {
  it.each([
    ['missing', undefined],
    ['empty', ''],
    ['not base64', '%%%%'],
    ['not a PKCS#8 key', btoa('definitely not a key')],
  ])('fails sign-in with an error when the private key is %s', async (_label, privateKey) => {
    await register();
    (vault.storage.passkeys as any[])[0].privateKey = privateKey;

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect(vault.user.errorToast).toHaveBeenCalled();
  });

  it('leaves the other passkeys for the site usable', async () => {
    await register({ user: { id: 'AQ', name: 'broken', displayName: 'Broken' } });
    const good = await register({ user: { id: 'Ag', name: 'good', displayName: 'Good' } });
    (vault.storage.passkeys as any[])[0].privateKey = '%%%%';
    vault.user.choosePasskey.mockImplementation((options: any[]) => ({
      action: 'use',
      id: options.find((o) => o.userName === 'good').id,
    }));

    await authenticate(good);
  });
});

describe('a damaged TOTP list', () => {
  it('still lists and generates codes for its good entries', async () => {
    const added: any = await vault.send({
      type: 'ADD_TOTP_ENTRY',
      payload: {
        otpauthUri: 'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example',
      },
    });
    (vault.storage.totp_entries as any[]).push(null, 'garbage');

    const list: any = await vault.send({ type: 'LIST_TOTP_ENTRIES' });
    const code: any = await vault.send({
      type: 'GENERATE_TOTP_CODE',
      payload: { id: added.entry.id },
    });

    expect(list.entries.map((e: any) => e.id)).toEqual([added.entry.id]);
    expect(code.code).toMatch(/^\d{6}$/);
  });
});

describe('a damaged snapshot from a sync peer', () => {
  it('merges the peer’s good records and ignores the damaged ones', async () => {
    const mine = await register();
    expect(
      (await vault.send({ type: 'CREATE_SYNC_CHAIN', deviceName: 'Laptop', wordCount: 12 })).success
    ).toBe(true);
    const adapter = vault.syncService.initialize.mock.calls.at(-1)![4];
    const [stored] = await vault.passkeys();
    const theirs = {
      ...stored,
      id: 'peer-passkey',
      credentialId: 'peer-passkey',
      createdAt: 1,
      updatedAt: 1,
    };

    await adapter.mergeRemote(
      [null, 'garbage', { rpId: 'no-id.example' }, theirs],
      [null, { secretB64: 'x' }],
      'peer',
      []
    );

    const ids = (await vault.passkeys()).map((p) => p.credentialId).sort();
    expect(ids).toEqual([mine.record.id, 'peer-passkey'].sort());
    await authenticate(mine, { allowCredentials: [{ type: 'public-key', id: mine.record.id }] });
  });
});
