/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * Where the browser cannot report whether a frame on the page is really
 * visible (no IntersectionObserver v2: Firefox), the vault's dialog opens
 * in a popup window of its own, which a page cannot fade, cover or
 * shrink. Ceremonies through the whole extension, with the dialog in a
 * window.
 */

import { setupVault, vaultReady } from './helpers/harness';
import { authenticate, outcome, register } from './helpers/ceremony';
import {
  authenticationJSON,
  creationOptionsFromJSON,
  registrationJSON,
  requestOptionsFromJSON,
} from './helpers/options';

const vault = setupVault('https://example.com/login');

beforeAll(() => vaultReady(vault));
beforeEach(async () => {
  await vault.reset();
  vault.goto('https://example.com/login');
  vault.dialogMode = 'window';
});

const signIn = (extra: Record<string, unknown> = {}) =>
  outcome(
    navigator.credentials.get({
      publicKey: requestOptionsFromJSON(authenticationJSON({ rpId: 'example.com' })),
      ...extra,
    })
  );

describe('a dialog in a window', () => {
  it('registers and signs in, mounting nothing in the page', async () => {
    const registration = await register();
    await authenticate(registration);
    await vault.settle();

    expect(vault.dialogs.map((dialog) => [dialog.mode, dialog.kind])).toEqual([
      ['window', 'create'],
      ['window', 'get'],
    ]);
    expect(vault.chrome.windows.every((window) => !window.open)).toBe(true);
    expect(document.documentElement.children).toHaveLength(2);
  });

  it('refuses the sign-in when the user closes the window', async () => {
    await register();
    vault.user.choosePasskey.mockImplementation(() => {
      const [window] = vault.chrome.windows.filter((candidate) => candidate.open);
      vault.chrome.closeWindow(window.id);
      return new Promise(() => undefined);
    });

    const { error } = await signIn();

    expect(error?.name).toBe('NotAllowedError');
    expect(vault.native.get).not.toHaveBeenCalled();
  });

  it('closes the window when the page aborts', async () => {
    await register();
    const controller = new AbortController();
    vault.user.choosePasskey.mockImplementation(() => {
      controller.abort();
      return new Promise(() => undefined);
    });

    const { error } = await signIn({ signal: controller.signal });
    await vault.settle();

    expect(error?.name).toBe('AbortError');
    expect(vault.chrome.windows.every((window) => !window.open)).toBe(true);
  });
});

describe('an autofill sign-in with the dialog in a window', () => {
  it('waits for the user to ask before opening the window', async () => {
    const registration = await register();
    vault.user.launch.mockReturnValue(new Promise(() => undefined));

    void signIn({ mediation: 'conditional' });
    await vault.settle();

    expect(vault.launchers).toEqual(['example.com']);
    expect(vault.dialogs.filter((dialog) => dialog.kind === 'get')).toEqual([]);
    expect(vault.chrome.windows.filter((window) => window.open)).toEqual([]);
    void registration;
  });

  it('signs in through the window once the user asks for it', async () => {
    const registration = await register();

    const { value, error } = await signIn({ mediation: 'conditional' });

    expect(error).toBeUndefined();
    expect((value as any).id).toBe(registration.record.id);
    expect(vault.dialogs.map((dialog) => dialog.mode)).toEqual(['window', 'window']);
  });

  it.each([['cancel'], ['passthrough']])(
    'leaves the request to the browser’s own autofill on %s',
    async (choice) => {
      await register();
      vault.user.launch.mockReturnValue(choice);
      vault.native.get.mockResolvedValue({ id: 'browser-autofill' });

      const { value } = await signIn({ mediation: 'conditional' });

      expect((value as any)?.id).toBe('browser-autofill');
      expect(vault.dialogs.filter((dialog) => dialog.kind === 'get')).toEqual([]);
    }
  );
});

describe('registration with the dialog in a window', () => {
  it('creates nothing when the user closes the window', async () => {
    vault.user.confirmCreate.mockImplementation(() => {
      const [window] = vault.chrome.windows.filter((candidate) => candidate.open);
      vault.chrome.closeWindow(window.id);
      return new Promise(() => undefined);
    });

    const { error } = await outcome(
      navigator.credentials.create({
        publicKey: creationOptionsFromJSON(
          registrationJSON({ rp: { name: 'Example', id: 'example.com' } })
        ),
      })
    );

    expect(error?.name).toBe('NotAllowedError');
    expect(await vault.passkeys()).toEqual([]);
  });
});
