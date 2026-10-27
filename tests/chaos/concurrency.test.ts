/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Chaos: many ceremonies at once, and pages that change their mind.
 *
 * A double-clicked login button, several tabs signing in to the same site,
 * an SPA that aborts and restarts its request on every route change. The
 * vault serialises its read-modify-write work; these experiments check that
 * it does so without losing a counter step, a passkey, or a request.
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { authenticate, outcome, register } from '../helpers/ceremony';
import { fromB64url, prng, toBytes } from '../helpers/bytes';
import { verifyAuthentication } from '../helpers/rp-verifier';
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

describe('parallel sign-ins with one passkey', () => {
  it('gives every assertion its own counter value, and loses none', async () => {
    const registration = await register();
    const requests = Array.from({ length: 12 }, () => authenticationJSON({ rpId: 'example.com' }));

    const assertions = await Promise.all(
      requests.map((json) => navigator.credentials.get({ publicKey: requestOptionsFromJSON(json) }))
    );

    const counters: number[] = [];
    for (let i = 0; i < assertions.length; i++) {
      const result = await verifyAuthentication(assertions[i], {
        challenge: fromB64url(requests[i].challenge),
        origin: 'https://example.com',
        rpId: 'example.com',
        record: { ...registration.record, signCount: 0 },
      });
      counters.push(result.signCount);
    }
    expect(counters.sort((a, b) => a - b)).toEqual(Array.from({ length: 12 }, (_, i) => i + 1));
    expect((await vault.passkeys())[0].counter).toBe(12);
  });
});

describe('parallel registrations', () => {
  it('keeps every passkey', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        navigator.credentials.create({
          publicKey: creationOptionsFromJSON(
            registrationJSON({
              rp: { name: 'Example', id: 'example.com' },
              user: {
                id: btoa(String(i)).replace(/=/g, ''),
                name: `user${i}`,
                displayName: `User ${i}`,
              },
            })
          ),
        })
      )
    );

    const ids = results.map((credential: any) => credential.id);
    expect(new Set(ids).size).toBe(8);
    expect((await vault.passkeys()).map((p) => p.credentialId).sort()).toEqual([...ids].sort());
  });
});

describe('registrations and sign-ins interleaved', () => {
  it('neither loses a passkey nor a counter step', async () => {
    const first = await register();
    const work: Promise<unknown>[] = [];
    for (let i = 0; i < 5; i++) {
      work.push(
        navigator.credentials.get({
          publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
        })
      );
      work.push(
        navigator.credentials.create({
          publicKey: creationOptionsFromJSON(
            registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
          ),
        })
      );
    }
    vault.user.choosePasskey.mockImplementation((options: any[]) => ({
      action: 'use',
      id: options.find((o) => o.credentialId === first.record.id).id,
    }));

    await Promise.all(work);

    const stored = await vault.passkeys();
    expect(stored).toHaveLength(6);
    expect(stored.find((p) => p.credentialId === first.record.id).counter).toBe(5);
  });
});

describe('abort storm', () => {
  it.each([0xfe17c0de, 0x5eed1, 0xc0ffee, 0xbadc0de, 0x1234567])(
    'settles every request and keeps only what the page received (seed %i)',
    async (seed) => {
      const random = prng(seed);
      const dialogs: AbortSignal[] = [];
      vault.user.confirmCreate.mockImplementation(
        (_rp: string, _user: string, signal: AbortSignal) =>
          new Promise((resolve) => {
            dialogs.push(signal);
            signal.addEventListener('abort', () => resolve(false));
            setTimeout(() => resolve(true), Math.floor(random() * 30));
          })
      );

      const attempts = Array.from({ length: 30 }, () => {
        const controller = new AbortController();
        setTimeout(() => controller.abort(), Math.floor(random() * 30));
        return outcome(
          navigator.credentials.create({
            publicKey: creationOptionsFromJSON(
              registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
            ),
            signal: controller.signal,
          })
        );
      });
      const settled = await Promise.all(attempts);
      await vault.settle();

      const created = settled.filter((s) => s.value).map((s) => (s.value as any).id);
      const aborted = settled.filter((s) => s.error);
      expect(created.length + aborted.length).toBe(30);
      for (const failure of aborted) expect(failure.error.name).toBe('AbortError');
      // Every passkey in the vault went to the page, and every one the page got is in the vault.
      expect((await vault.passkeys()).map((p) => p.credentialId).sort()).toEqual(created.sort());
      void dialogs;
      void toBytes;
    }
  );

  // The page aborts at each step of the protocol in turn: before the
  // content script has the request, while the picker is open, while the
  // background is signing, and after the signature has been posted.
  const steps: Array<[string, (abort: () => void) => void]> = [
    ['before the content script sees it', (abort) => abort()],
    [
      'while the picker is open',
      (abort) =>
        vault.user.choosePasskey.mockImplementationOnce((options: any[]) => {
          abort();
          return { action: 'use', id: options[0].id };
        }),
    ],
    [
      'while the background signs',
      (abort) => {
        const deliver = vault.chrome.deliver.bind(vault.chrome);
        jest.spyOn(vault.chrome, 'deliver').mockImplementation((message: any, sender) => {
          if (message?.type === 'GET_PASSKEY') abort();
          return deliver(message, sender);
        });
      },
    ],
  ];

  it.each(steps)(
    'settles a sign-in aborted %s, without the browser prompt',
    async (_step, arrange) => {
      const registration = await register();
      const controller = new AbortController();
      arrange(() => controller.abort());

      const { error } = await outcome(
        navigator.credentials.get({
          publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
          signal: controller.signal,
        })
      );
      jest.restoreAllMocks();
      await vault.settle();

      expect(error?.name).toBe('AbortError');
      expect(vault.native.get).not.toHaveBeenCalled();
      // The vault is still usable, and its counter never went backwards.
      const { result } = await authenticate(registration, {}, { strictCounter: false });
      expect(result.signCount).toBeGreaterThanOrEqual(1);
    }
  );
});
