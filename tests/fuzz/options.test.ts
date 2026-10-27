/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Fuzzing navigator.credentials.create() and get() with corrupted options.
 *
 * Seeded mutations of valid options: members deleted, replaced with values
 * of the wrong type, oversized, or nested garbage. The properties that must
 * hold for every input:
 *
 *   - the call settles, with a credential or an Error / DOMException
 *   - a credential that comes back passes the strict verifier for the
 *     options as the page passed them
 *   - the vault holds a new passkey exactly when the page received one
 */

import { setupVault, vaultReady } from '../helpers/harness';
import { outcome, register } from '../helpers/ceremony';
import { fromB64url, prng, toBytes } from '../helpers/bytes';
import { verifyAuthentication, verifyRegistration } from '../helpers/rp-verifier';
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

const WEIRD: unknown[] = [
  undefined,
  null,
  0,
  -7,
  NaN,
  '',
  'example.com',
  '-7',
  [],
  [1, 2, 3],
  {},
  { id: 'example.com' },
  new Uint8Array(0),
  new Uint8Array(65),
  new Uint8Array(1024 * 1024),
  new ArrayBuffer(16),
  Symbol('s'),
  () => undefined,
  'x'.repeat(100000),
];

const CREATE_PATHS = [
  'rp',
  'rp.id',
  'rp.name',
  'user',
  'user.id',
  'user.name',
  'user.displayName',
  'challenge',
  'pubKeyCredParams',
  'pubKeyCredParams.0',
  'pubKeyCredParams.0.alg',
  'pubKeyCredParams.0.type',
  'timeout',
  'excludeCredentials',
  'authenticatorSelection',
  'authenticatorSelection.userVerification',
  'attestation',
  'hints',
  'extensions',
  'extensions.prf',
  'extensions.credProps',
];

const GET_PATHS = [
  'challenge',
  'rpId',
  'timeout',
  'allowCredentials',
  'allowCredentials.0',
  'allowCredentials.0.id',
  'allowCredentials.0.transports',
  'userVerification',
  'extensions',
  'extensions.prf',
  'extensions.prf.eval',
  'extensions.prf.eval.first',
];

function mutate(target: any, path: string, value: unknown): void {
  const keys = path.split('.');
  let node = target;
  for (const key of keys.slice(0, -1)) {
    let child = node[key];
    // Replace a primitive or buffer on the path with a fresh object to descend into.
    if (
      child === null ||
      typeof child !== 'object' ||
      ArrayBuffer.isView(child) ||
      child instanceof ArrayBuffer
    ) {
      child = {};
      node[key] = child;
    }
    node = child;
  }
  const last = keys[keys.length - 1];
  if (value === undefined) delete node[last];
  else node[last] = value;
}

async function settles<T>(promise: Promise<T>): Promise<{ value?: T; error?: any }> {
  return Promise.race([
    outcome(promise),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('the call never settled')), 5000)
    ),
  ]);
}

describe.each([1, 2, 3, 4])('create() with corrupted options (seed %i)', (seed) => {
  // Forty ceremonies: seconds locally, longer on a busy CI runner.
  it('settles, and returns only credentials that verify and were stored', async () => {
    const random = prng(seed * 7919);
    for (let i = 0; i < 40; i++) {
      const json = registrationJSON({ rp: { name: 'Example', id: 'example.com' } });
      const options: any = creationOptionsFromJSON(json);
      const mutations = 1 + Math.floor(random() * 2);
      for (let m = 0; m < mutations; m++) {
        mutate(
          options,
          CREATE_PATHS[Math.floor(random() * CREATE_PATHS.length)],
          WEIRD[Math.floor(random() * WEIRD.length)]
        );
      }
      const before = (await vault.passkeys()).length;

      const { value, error } = await settles(navigator.credentials.create({ publicKey: options }));
      await vault.settle();
      const after = (await vault.passkeys()).length;

      if (error) {
        expect(error).toBeInstanceOf(Error);
        expect(after).toBe(before);
        continue;
      }
      const credential: any = value;
      expect(after).toBe(before + 1);
      await verifyRegistration(credential, {
        challenge: toBytes(options.challenge),
        origin: 'https://example.com',
        rpId: typeof options.rp?.id === 'string' && options.rp.id ? options.rp.id : 'example.com',
        userId: toBytes(options.user.id),
        pubKeyCredParams: Array.isArray(options.pubKeyCredParams)
          ? options.pubKeyCredParams
          : undefined,
        extensions:
          options.extensions && typeof options.extensions === 'object'
            ? options.extensions
            : undefined,
      });
    }
  }, 60000);
});

describe.each([1, 2, 3, 4])('get() with corrupted options (seed %i)', (seed) => {
  // Forty ceremonies: seconds locally, longer on a busy CI runner.
  it('settles, and returns only assertions that verify', async () => {
    const registration = await register();
    const random = prng(seed * 104729);
    vault.native.get.mockResolvedValue({ id: 'browser' });
    for (let i = 0; i < 40; i++) {
      const json = authenticationJSON({
        rpId: 'example.com',
        allowCredentials: [{ type: 'public-key', id: registration.record.id }],
        extensions: { prf: { eval: { first: 'AAAA' } } },
      });
      const options: any = requestOptionsFromJSON(json);
      mutate(
        options,
        GET_PATHS[Math.floor(random() * GET_PATHS.length)],
        WEIRD[Math.floor(random() * WEIRD.length)]
      );

      const { value, error } = await settles(navigator.credentials.get({ publicKey: options }));

      if (error) {
        expect(error).toBeInstanceOf(Error);
        continue;
      }
      if ((value as any)?.id === 'browser') continue;
      const result = await verifyAuthentication(value, {
        challenge: toBytes(options.challenge),
        origin: 'https://example.com',
        rpId: 'example.com',
        record: { ...registration.record, signCount: 0 },
        strictCounter: false,
      });
      expect(result.userHandle).toEqual(registration.record.userHandle);
      void fromB64url;
    }
  }, 60000);
});
