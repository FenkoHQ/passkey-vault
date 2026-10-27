/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: chrome.storage fails.
 *
 * chrome.storage.local rejects writes past its quota and can fail on I/O
 * errors. The vault's bookkeeping (sync status, the WebAuthn log) shares
 * that storage with the passkeys themselves.
 *
 * Steady state: a passkey is returned to the site only if it was saved (or
 * the site would register a credential the vault cannot use), a saved
 * passkey is returned to the site (or the vault holds a credential the site
 * never registered), and a fault does not outlive itself.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { authenticate, outcome, register } from '../helpers/ceremony';
import {
  authenticationJSON,
  creationOptionsFromJSON,
  registrationJSON,
  requestOptionsFromJSON,
} from '../helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
});

const quota = () => new Error('QUOTA_BYTES quota exceeded');
const writes = (key: string) => (keys: string[]) => keys.includes(key);

function createRequest() {
  return navigator.credentials.create({
    publicKey: creationOptionsFromJSON(
      registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
    ),
  });
}

describe('the passkey cannot be saved', () => {
  it('returns no credential and stores nothing', async () => {
    vault.chrome.faults.push({ op: 'set', match: writes('passkeys'), error: quota(), times: 1 });

    const { error } = await outcome(createRequest());

    expect(error?.name).toBe('NotAllowedError');
    expect(await vault.passkeys()).toEqual([]);
    expect(vault.user.errorToast).toHaveBeenCalled();
  });

  it('registers normally once storage recovers', async () => {
    vault.chrome.faults.push({ op: 'set', match: writes('passkeys'), error: quota(), times: 1 });
    await outcome(createRequest());

    const registration = await register();

    expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([registration.record.id]);
  });
});

describe('bookkeeping fails after the passkey is saved', () => {
  it.each([['sync_status'], ['webauthn_log']])(
    'still hands the site the saved passkey when %s cannot be written',
    async (key) => {
      vault.chrome.faults.push({ op: 'set', match: writes(key), error: quota() });

      const registration = await register();

      expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([registration.record.id]);
    }
  );

  it('still signs in when sync status cannot be written', async () => {
    const registration = await register();
    vault.chrome.faults.push({ op: 'set', match: writes('sync_status'), error: quota() });

    await authenticate(registration);
  });
});

describe('the signature counter cannot be saved', () => {
  it('does not hand out an assertion whose counter the vault forgot', async () => {
    const registration = await register();
    vault.chrome.faults.push({ op: 'set', match: writes('passkeys'), error: quota(), times: 1 });

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect((await vault.passkeys())[0].counter).toBe(0);
    // The next sign-in reuses no counter value the RP already saw.
    const { result } = await authenticate(registration);
    expect(result.signCount).toBe(1);
  });
});

describe('storage cannot be read', () => {
  it('hands sign-in to the browser when the passkey list cannot be read', async () => {
    await register();
    vault.chrome.faults.push({
      op: 'get',
      match: writes('passkeys'),
      error: new Error('IO error'),
      times: 1,
    });
    vault.native.get.mockResolvedValue({ id: 'native' });

    const result: any = await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });

    expect(result.id).toBe('native');
  });

  it('fails registration cleanly when the existing passkeys cannot be read', async () => {
    vault.chrome.faults.push({
      op: 'get',
      match: writes('passkeys'),
      error: new Error('IO error'),
    });

    const { error } = await outcome(createRequest());
    vault.chrome.faults.length = 0;

    expect(error?.name).toBe('NotAllowedError');
    expect(await vault.passkeys()).toEqual([]);
  });
});
