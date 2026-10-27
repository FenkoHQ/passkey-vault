/**
 * Only one in-page dialog shows at a time. A dialog that is replaced or
 * cancelled must still answer its caller, or that request hangs until the
 * page gives up on it.
 */

// A module, not a global script: other test files declare the same top-level
// names, and TypeScript would reject the clash when both compile in one worker.
export {};

const chromeMock = (window as unknown as { chrome: Record<string, any> }).chrome;
chromeMock.storage.local.get.mockResolvedValue({});
chromeMock.storage.onChanged = { addListener: jest.fn() };

type VaultWindow = {
  showPasskeyCreateConfirm: (rpId: string, user: string, signal?: AbortSignal) => Promise<boolean>;
};
const vault = window as unknown as VaultWindow;

const cards = () => document.querySelectorAll('.pkv-notification-container').length;

beforeAll(() => {
  require('../src/ui/passkey-ui');
});

afterEach(() => {
  document.body.innerHTML = '';
});

describe('in-page dialogs', () => {
  it('settles a replaced create dialog as declined', async () => {
    const first = vault.showPasskeyCreateConfirm('example.com', 'alice');
    const controller = new AbortController();
    const second = vault.showPasskeyCreateConfirm('example.com', 'bob', controller.signal);

    await expect(first).resolves.toBe(false);
    expect(cards()).toBe(1);

    controller.abort();
    await expect(second).resolves.toBe(false);
  });

  it('closes the dialog when its request is cancelled', async () => {
    const controller = new AbortController();
    const shown = vault.showPasskeyCreateConfirm('example.com', 'alice', controller.signal);
    expect(cards()).toBe(1);

    controller.abort();

    await expect(shown).resolves.toBe(false);
    expect(cards()).toBe(0);
  });

  it('does not open for a request that was already cancelled', async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(
      vault.showPasskeyCreateConfirm('example.com', 'alice', controller.signal)
    ).resolves.toBe(false);
    expect(cards()).toBe(0);
  });
});
