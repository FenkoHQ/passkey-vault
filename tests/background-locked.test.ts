/**
 * A locked vault must be reported with a machine-readable code, so the
 * content script can tell it apart from a vault with no passkey for the site.
 */

import { secureStorage } from '../src/crypto/secure-storage';

jest.mock('../src/sync/sync-service', () => ({
  syncService: { initialize: jest.fn(), disconnect: jest.fn() },
}));

type Listener = (message: unknown, sender: unknown, respond: (r: unknown) => void) => unknown;

const chromeMock = (window as unknown as { chrome: Record<string, any> }).chrome;
const lifecycle = () => ({ addListener: jest.fn() });
chromeMock.runtime.onInstalled = lifecycle();
chromeMock.runtime.onStartup = lifecycle();
chromeMock.runtime.onSuspend = lifecycle();
chromeMock.storage.local.get.mockResolvedValue({});
chromeMock.storage.local.set.mockResolvedValue(undefined);

function send(message: Record<string, unknown>): Promise<any> {
  const listener = chromeMock.runtime.onMessage.addListener.mock.calls[0][0] as Listener;
  // Chrome's account of a message from a content script on example.com.
  const contentScript = {
    id: chromeMock.runtime.id,
    url: 'https://example.com/login',
    origin: 'https://example.com',
    tab: { id: 1, url: 'https://example.com/login' },
    frameId: 0,
  };
  return new Promise((resolve) => listener(message, contentScript, resolve));
}

beforeAll(() => {
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  // A vault with a PIN, currently locked.
  jest.spyOn(secureStorage, 'isSetup').mockResolvedValue(true);
  jest.spyOn(secureStorage, 'isStorageUnlocked').mockReturnValue(false);
  require('../src/background/background');
});

const openSignInDialog = {
  type: 'PASSKEY_DIALOG_OPEN',
  requestId: 'req-1',
  payload: { kind: 'get', publicKey: { rpId: 'example.com', challenge: 'AQID' } },
};

describe('background: locked vault', () => {
  it('tags a sign-in dialog with VAULT_LOCKED', async () => {
    const response = await send(openSignInDialog);

    expect(response).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
  });

  it('does not report the locked vault as an extension error', async () => {
    (console.error as jest.Mock).mockClear();

    await send(openSignInDialog);

    expect(console.error).not.toHaveBeenCalled();
  });

  it('leaves unrelated failures untagged', async () => {
    const response = await send({ type: 'NO_SUCH_MESSAGE' });

    expect(response.code).toBeUndefined();
  });
});
