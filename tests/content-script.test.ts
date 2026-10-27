/**
 * The content script sits between the page shim and the background worker.
 * These tests drive it the way the shim does (window.postMessage) with the
 * background, the vault dialog's frame and the in-page notices mocked, and
 * read back what it posts to the page.
 */

// A module, not a global script: other test files declare the same top-level
// names, and TypeScript would reject the clash when both compile in one worker.
export {};

import { trustedKey } from './helpers/trusted-input';

const PAGE_SOURCE = 'PASSKEY_VAULT_PAGE';
const CONTENT_SOURCE = 'PASSKEY_VAULT_CONTENT';

jest.mock('../src/content/vault-dialog-frame', () => ({
  extensionOrigin: () => 'chrome-extension://test',
  mountDialogFrame: jest.fn(),
}));
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { mountDialogFrame } = require('../src/content/vault-dialog-frame') as {
  mountDialogFrame: jest.Mock;
};

const ui = {
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

/** The content script's chrome.runtime.onMessage listeners. */
let backgroundListeners: Array<(...args: unknown[]) => void> = [];

beforeAll(async () => {
  require('../src/content/content');
  backgroundListeners = chromeMock.runtime.onMessage.addListener.mock.calls.map(
    ([listener]: [(...args: unknown[]) => void]) => listener
  );
  // initialize() awaits i18n and logger set-up before it listens to the page.
  await flush();
});

/** Tell the content script how a dialog ended, as the background does. */
function dialogResult(dialogId: string, outcome: string): void {
  for (const listener of backgroundListeners) {
    listener(
      { type: 'PASSKEY_DIALOG_RESULT', dialogId, outcome },
      { id: chromeMock.runtime.id },
      () => undefined
    );
  }
}

let frame: { gone: Promise<void>; unmount: jest.Mock; remove: () => void };

beforeEach(() => {
  jest.clearAllMocks();
  domainRules = {};
  mountDialogFrame.mockImplementation(() => {
    let remove!: () => void;
    const gone = new Promise<void>((resolve) => (remove = resolve));
    frame = { gone, unmount: jest.fn(), remove };
    return frame;
  });
});

describe('content script: sign-in with a locked vault', () => {
  const locked = {
    success: false,
    error: 'Secure storage is locked. Please unlock with master password.',
    code: 'VAULT_LOCKED',
  };

  beforeEach(() => {
    background = (message) => (message.type === 'PASSKEY_DIALOG_OPEN' ? locked : {});
  });

  it('says the vault is locked instead of "no passkey", then falls back to native', async () => {
    const result = await getRequest();

    expect(result.passthrough).toBe(true);
    expect(result.error).toBe('Vault is locked');
    expect(ui.showErrorNotification).toHaveBeenCalledWith(
      'Vault Locked',
      expect.stringContaining('Unlock Fenko Vault')
    );
    expect(mountDialogFrame).not.toHaveBeenCalled();
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
      message.type === 'PASSKEY_DIALOG_OPEN' ? { success: true, status: 'none' } : {};

    const result = await getRequest();

    expect(result.passthrough).toBe(true);
    expect(result.error).toBe('No vault passkey for this site');
    expect(ui.showErrorNotification).not.toHaveBeenCalled();
  });
});

describe('content script: page cancels an in-flight request', () => {
  /** Post a request and return its id without waiting for an answer. */
  function post(type: string, payload: Record<string, unknown>): string {
    const requestId = `req_${Math.random().toString(36).slice(2)}`;
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: PAGE_SOURCE, type, payload, requestId },
        source: window,
      })
    );
    return requestId;
  }

  function cancel(requestId: string): void {
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { source: PAGE_SOURCE, type: 'PASSKEY_CANCEL_REQUEST', requestId },
        source: window,
      })
    );
  }

  let posted: unknown[];
  const record = (event: MessageEvent) => {
    if (event.data?.source === CONTENT_SOURCE) posted.push(event.data);
  };

  beforeEach(() => {
    posted = [];
    window.addEventListener('message', record);
    background = (message) =>
      message.type === 'PASSKEY_DIALOG_OPEN'
        ? { success: true, status: 'open', dialogId: 'dialog-1', token: 'token-1' }
        : { success: true, credential: { id: 'cred-1', response: {} } };
  });

  afterEach(() => {
    window.removeEventListener('message', record);
  });

  const sentTypes = () =>
    chromeMock.runtime.sendMessage.mock.calls.map(([message]: [{ type: string }]) => message.type);

  it('closes the create dialog, and a confirmation that arrives late never creates', async () => {
    const requestId = post('PASSKEY_CREATE_REQUEST', {
      publicKey: {
        rp: { id: 'localhost' },
        user: { name: 'alice' },
        challenge: 'AQID',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    });
    await flush();
    expect(mountDialogFrame).toHaveBeenCalledWith({
      token: 'token-1',
      kind: 'create',
      focus: true,
    });

    cancel(requestId);
    // The click that raced the cancel still loses.
    dialogResult('dialog-1', 'approved');
    await flush();

    expect(frame.unmount).toHaveBeenCalled();
    expect(sentTypes()).toContain('PASSKEY_DIALOG_CANCEL');
    expect(sentTypes()).not.toContain('CREATE_PASSKEY');
    expect(ui.showPasskeyCreatedNotification).not.toHaveBeenCalled();
    expect(posted).toEqual([]);
  });

  it('closes the picker, and a decision that arrives late never signs', async () => {
    const requestId = post('PASSKEY_GET_REQUEST', {
      publicKey: { rpId: 'localhost', challenge: 'AQID' },
    });
    await flush();
    expect(mountDialogFrame).toHaveBeenCalledWith({ token: 'token-1', kind: 'get', focus: true });

    cancel(requestId);
    // The click that raced the cancel still loses.
    dialogResult('dialog-1', 'approved');
    await flush();

    expect(frame.unmount).toHaveBeenCalled();
    expect(sentTypes()).toContain('PASSKEY_DIALOG_CANCEL');
    expect(sentTypes()).not.toContain('GET_PASSKEY');
    expect(posted).toEqual([]);
  });
});

describe('content script: the vault dialog', () => {
  let posted: any[];
  const record = (event: MessageEvent) => {
    if (event.data?.source === CONTENT_SOURCE) posted.push(event.data);
  };
  const sent = () =>
    chromeMock.runtime.sendMessage.mock.calls.map(([message]: [Record<string, any>]) => message);

  beforeEach(() => {
    posted = [];
    window.addEventListener('message', record);
    background = (message) =>
      message.type === 'PASSKEY_DIALOG_OPEN'
        ? { success: true, status: 'open', dialogId: 'dialog-2', token: 'token-2' }
        : { success: true, credential: { id: 'cred-1', response: {} } };
  });

  afterEach(() => window.removeEventListener('message', record));

  it('signs after the dialog approves, naming no passkey itself', async () => {
    const result = getRequest();
    await flush();

    dialogResult('dialog-2', 'approved');
    const answer = await result;

    expect(answer.success).toBe(true);
    const getPasskey = sent().find((message) => message.type === 'GET_PASSKEY');
    expect(getPasskey.payload).not.toHaveProperty('selectedPasskeyId');
    expect(frame.unmount).toHaveBeenCalled();
  });

  it('ignores an outcome for a dialog it is not showing', async () => {
    const result = getRequest();
    await flush();

    dialogResult('someone-elses-dialog', 'approved');
    await flush();
    expect(sent().map((message) => message.type)).not.toContain('GET_PASSKEY');

    dialogResult('dialog-2', 'cancel');
    expect((await result).name).toBe('NotAllowedError');
  });

  it('treats the page removing the frame as a cancel', async () => {
    const result = getRequest();
    await flush();

    frame.remove();
    const answer = await result;

    expect(answer).toMatchObject({ success: false, name: 'NotAllowedError' });
    expect(sent().map((message) => message.type)).toContain('PASSKEY_DIALOG_CANCEL');
  });

  it('cancels on Escape in the page, but not on an Escape the page made up', async () => {
    const result = getRequest();
    await flush();

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await flush();
    expect(frame.unmount).not.toHaveBeenCalled();

    trustedKey(document, 'Escape');
    expect((await result).name).toBe('NotAllowedError');
  });

  it('hands the request to the browser when the user picks another passkey', async () => {
    const result = getRequest();
    await flush();

    dialogResult('dialog-2', 'passthrough');

    expect(await result).toMatchObject({ passthrough: true, error: 'User chose other passkey' });
  });

  it('replaces its dialog when the page asks again', async () => {
    const first = getRequest();
    await flush();
    const firstFrame = frame;

    void getRequest();
    await flush();

    expect((await first).name).toBe('NotAllowedError');
    expect(firstFrame.unmount).toHaveBeenCalled();
    expect(mountDialogFrame).toHaveBeenCalledTimes(2);
  });

  it('opens a conditional sign-in without taking focus from the page', async () => {
    void request('PASSKEY_GET_REQUEST', {
      publicKey: { rpId: 'localhost', challenge: 'AQID' },
      mediation: 'conditional',
    });
    await flush();

    expect(mountDialogFrame).toHaveBeenCalledWith(expect.objectContaining({ focus: false }));
  });
});
