/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: the MV3 service worker dies.
 *
 * Chrome stops an idle extension worker after about 30 seconds and starts a
 * new one for the next message, and it can kill one mid-message. A ceremony
 * spans several messages with a human in between, so the worker that lists
 * the passkeys is often not the one that signs.
 *
 * Steady state: every page request settles (resolves or rejects, never
 * hangs), a credential the page receives verifies, and the vault never
 * holds half a passkey.
 */

import { setupVault, vaultReady, type PasskeyOption } from '../helpers/harness';
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

const PIN = '123456';

describe('a worker restart between the picker and the signature', () => {
  it('still signs: the picker ran on one worker, the signature on the next', async () => {
    const registration = await register();
    vault.user.choosePasskey.mockImplementation(async (options: PasskeyOption[]) => {
      await vault.restartWorker();
      return { action: 'use', id: options[0].id };
    });

    await authenticate(registration);
  });

  it('keeps a PIN-protected vault unlocked across the restart', async () => {
    const registration = await register();
    expect(
      (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: PIN } })).success
    ).toBe(true);
    vault.user.choosePasskey.mockImplementation(async (options: PasskeyOption[]) => {
      await vault.restartWorker();
      return { action: 'use', id: options[0].id };
    });

    await authenticate(registration);
    expect((await vault.send({ type: 'IS_SECURE_STORAGE_UNLOCKED' })).isUnlocked).toBe(true);
  });

  it('registers on a worker that started after the user confirmed', async () => {
    vault.user.confirmCreate.mockImplementation(async () => {
      await vault.restartWorker();
      return true;
    });

    const registration = await register();
    expect((await vault.passkeys()).map((p) => p.credentialId)).toEqual([registration.record.id]);
  });
});

describe('a worker killed in the middle of a message', () => {
  it('fails the registration cleanly when the worker dies before saving', async () => {
    // The save never completes: the worker is gone before storage answers.
    vault.chrome.faults.push({
      op: 'set',
      match: (keys) => keys.includes('passkeys'),
      hang: true,
      times: 1,
    });
    vault.user.confirmCreate.mockImplementation(() => {
      setTimeout(() => vault.killWorker(), 5);
      return true;
    });

    const { error } = await outcome(
      navigator.credentials.create({
        publicKey: creationOptionsFromJSON(
          registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
        ),
      })
    );
    await vault.restartWorker();

    expect(error?.name).toBe('NotAllowedError');
    expect(await vault.passkeys()).toEqual([]);
  });

  it('answers a sign-in whose worker died, without stranding the page', async () => {
    await register();
    vault.chrome.faults.push({
      op: 'set',
      match: (keys) => keys.includes('passkeys'),
      hang: true,
      times: 1,
    });
    vault.user.choosePasskey.mockImplementation((options: PasskeyOption[]) => {
      setTimeout(() => vault.killWorker(), 5);
      return { action: 'use', id: options[0].id };
    });

    const { error } = await outcome(
      navigator.credentials.get({
        publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect(vault.native.get).not.toHaveBeenCalled();
  });
});

describe('no worker at all', () => {
  it('hands sign-in to the browser when the vault cannot be reached', async () => {
    vault.killWorker();
    vault.native.get.mockResolvedValue({ id: 'native' });

    const result: any = await navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
    });

    expect(result.id).toBe('native');
  });

  it('rejects registration rather than hanging when the vault cannot be reached', async () => {
    vault.killWorker();

    const { error } = await outcome(
      navigator.credentials.create({
        publicKey: creationOptionsFromJSON(
          registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
        ),
      })
    );

    expect(error).toBeDefined();
  });
});

describe('repeated restarts', () => {
  it('survives a restart before every message of twenty ceremonies', async () => {
    const original = vault.chrome.deliver.bind(vault.chrome);
    let restarts = 0;
    jest.spyOn(vault.chrome, 'deliver').mockImplementation(async (message, sender) => {
      if (sender.tab) {
        restarts++;
        vault.chrome.killWorker();
        await vault.restartWorker();
      }
      return original(message, sender);
    });
    try {
      const registration = await register();
      for (let i = 0; i < 19; i++) await authenticate(registration);
    } finally {
      jest.restoreAllMocks();
    }

    expect(restarts).toBeGreaterThanOrEqual(20);
    const [stored] = await vault.passkeys();
    expect(stored.counter).toBe(19);
  });
});
