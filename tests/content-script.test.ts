/**
 * The content script sits between the page shim and the background worker.
 * These tests drive it the way the shim does (window.postMessage) with the
 * background and the in-page dialogs mocked, and read back what it posts to
 * the page.
 */

const PAGE_SOURCE = 'PASSKEY_VAULT_PAGE';
const CONTENT_SOURCE = 'PASSKEY_VAULT_CONTENT';

const ui = {
  showPasskeySelector: jest.fn(),
  showPasskeyCreateConfirm: jest.fn(),
  showPasskeyCreatedNotification: jest.fn(),
  showPasskeyUsedNotification: jest.fn(),
  showErrorNotification: jest.fn(),
};
Object.assign(window, ui);

type BackgroundHandler = (message: { type: string; payload?: unknown }) => unknown;
let background: BackgroundHandler = () => ({ success: true });
let domainRules: Record<string, unknown> = {};

const chromeMock = (window as unknown as { chrome: Record<string, any> }).chrome;
chromeMock.runtime.sendMessage.mockImplementation(async (message: { type: string }) =>
  background(message)
);
chromeMock.storage.local.get.mockImplementation(async (key: string) =>
  key === 'domain_rules' ? { domain_rules: domainRules } : {}
);

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

/** Post a request as the page shim does and wait for the content script's answer. */
function request(type: string, payload: Record<string, unknown>): Promise<any> {
  const requestId = `req_${Math.random().toString(36).slice(2)}`;
  return new Promise((resolve) => {
    const listener = (event: MessageEvent) => {
      if (event.data?.source !== CONTENT_SOURCE || event.data.requestId !== requestId) {
        return;
      }
      window.removeEventListener('message', listener);
      resolve(event.data.result);
    };
    window.addEventListener('message', listener);
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: PAGE_SOURCE, type, payload, requestId },
        source: window,
      })
    );
  });
}

function getRequest() {
  return request('PASSKEY_GET_REQUEST', {
    publicKey: { rpId: 'localhost', challenge: 'AQID' },
    origin: 'http://localhost',
  });
}

beforeAll(async () => {
  require('../src/content/content');
  // initialize() awaits i18n and logger set-up before it listens to the page.
  await flush();
});

beforeEach(() => {
  jest.clearAllMocks();
  domainRules = {};
});

describe('content script: sign-in with a locked vault', () => {
  const lockedList = {
    success: false,
    error: 'Secure storage is locked. Please unlock with master password.',
    code: 'VAULT_LOCKED',
  };

  beforeEach(() => {
    background = (message) => (message.type === 'LIST_PASSKEYS_FOR_RP' ? lockedList : {});
  });

  it('says the vault is locked instead of "no passkey", then falls back to native', async () => {
    const result = await getRequest();

    expect(result.passthrough).toBe(true);
    expect(result.error).toBe('Vault is locked');
    expect(ui.showErrorNotification).toHaveBeenCalledWith(
      'Vault Locked',
      expect.stringContaining('Unlock Fenko Vault')
    );
    expect(ui.showPasskeySelector).not.toHaveBeenCalled();
  });

  it('blocks with the locked message when native fallback is turned off', async () => {
    domainRules = { passthroughOnNoPasskey: false };

    const result = await getRequest();

    expect(result.passthrough).toBeUndefined();
    expect(result.blockNativeFallback).toBe(true);
    expect(result.error).toContain('Unlock Fenko Vault');
    expect(result.error).not.toBe('No passkeys found for this site');
  });

  it('still treats an unlocked, empty vault as having no passkey', async () => {
    background = (message) =>
      message.type === 'LIST_PASSKEYS_FOR_RP' ? { success: true, passkeys: [] } : {};

    const result = await getRequest();

    expect(result.passthrough).toBe(true);
    expect(result.error).toBe('No vault passkey for this site');
    expect(ui.showErrorNotification).not.toHaveBeenCalled();
  });
});
