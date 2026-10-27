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
