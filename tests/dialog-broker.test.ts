/**
 * @jest-environment ./tests/helpers/vault-environment.js
 *
 * The background's side of the ceremony dialogs: who may open a dialog,
 * who may see what it shows, and who may answer it.
 *
 * The dialog page is a web-accessible extension page, so a page can try to
 * frame it, and a compromised renderer can send any message its content
 * script could. Neither must get the passkeys a dialog lists, or a decision
 * in.
 */

import { EXTENSION_PAGE, setupVault, vaultReady } from './helpers/harness';
import { EXTENSION_ID, EXTENSION_ORIGIN, type MessageSender } from './helpers/fake-chrome';

const vault = setupVault('https://bank.example/login');

beforeAll(() => vaultReady(vault));

const PASSKEYS = [
  {
    id: 'cred-alice',
    credentialId: 'cred-alice',
    type: 'public-key',
    rpId: 'bank.example',
    origin: 'https://bank.example',
    user: { id: 'dXNlci1h', name: 'alice@bank.example', displayName: 'Alice' },
    privateKey: 'PRIVATE',
    publicKey: 'PUBLIC',
    createdAt: 1,
    counter: 0,
  },
  {
    id: 'cred-bob',
    credentialId: 'cred-bob',
    type: 'public-key',
    rpId: 'bank.example',
    origin: 'https://bank.example',
    user: { id: 'dXNlci1i', name: 'bob@bank.example', displayName: 'Bob' },
    privateKey: 'PRIVATE',
    publicKey: 'PUBLIC',
    createdAt: 2,
    counter: 0,
  },
];

const PAGE: MessageSender = {
  id: EXTENSION_ID,
  url: 'https://bank.example/login',
  origin: 'https://bank.example',
  tab: { id: 7, url: 'https://bank.example/login' },
  frameId: 0,
};

/** The dialog page, framed by the content script in tab 7. */
const DIALOG: MessageSender = {
  id: EXTENSION_ID,
  url: `${EXTENSION_ORIGIN}/vault-dialog.html`,
  origin: EXTENSION_ORIGIN,
  tab: { id: 7, url: 'https://bank.example/login' },
  frameId: 4,
};

const getPayload = (extra: Record<string, unknown> = {}) => ({
  kind: 'get',
  publicKey: { rpId: 'bank.example', challenge: 'AAAA', ...extra },
});

async function open(requestId = 'req-1', payload = getPayload(), sender = PAGE): Promise<any> {
  return vault.send({ type: 'PASSKEY_DIALOG_OPEN', requestId, payload }, sender);
}

const attach = (token: string, sender: MessageSender = DIALOG) =>
  vault.send({ type: 'PASSKEY_DIALOG_ATTACH', token }, sender) as Promise<any>;

const decide = (token: string, decision: Record<string, unknown>, sender = DIALOG) =>
  vault.send({ type: 'PASSKEY_DIALOG_DECIDE', token, decision }, sender) as Promise<any>;

const results = () =>
  vault.chrome.sentToTabs.filter((sent) => sent.message.type === 'PASSKEY_DIALOG_RESULT');

/** A real P-256 key, so a sign-in the vault allows also succeeds. */
async function privateKey(): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return btoa(String.fromCharCode(...pkcs8));
}

beforeAll(async () => {
  for (const passkey of PASSKEYS) passkey.privateKey = await privateKey();
});

beforeEach(async () => {
  await vault.reset({ passkeys: PASSKEYS });
  vault.goto('https://bank.example/login');
});

describe('opening a dialog', () => {
  it('tells the content script there is a dialog, not which passkeys it lists', async () => {
    const response = await open();

    expect(response).toMatchObject({ success: true, status: 'open' });
    expect(typeof response.token).toBe('string');
    expect(response.token.length).toBeGreaterThanOrEqual(43);
    const text = JSON.stringify(response);
    for (const secret of ['alice', 'Alice', 'bob', 'cred-alice', 'cred-bob']) {
      expect(text).not.toContain(secret);
    }
    expect(response).not.toHaveProperty('count');
  });

  it('says there is nothing to offer when allowCredentials matches no vault passkey', async () => {
    const response = await open(
      'req-1',
      getPayload({ allowCredentials: [{ type: 'public-key', id: 'someone-else' }] })
    );

    expect(response).toEqual({ success: true, status: 'none' });
  });

  it('says so when the vault is locked', async () => {
    expect(
      (await vault.send({ type: 'SETUP_MASTER_PASSWORD', payload: { password: '123456' } })).success
    ).toBe(true);
    await vault.send({ type: 'LOCK_SECURE_STORAGE' });

    expect(await open()).toMatchObject({ success: false, code: 'VAULT_LOCKED' });
  });

  it('cannot open a dialog for another site', async () => {
    const response = await open('req-1', getPayload({ rpId: 'other.example' }));

    expect(response.success).toBe(false);
  });
});

describe('a web page', () => {
  it('can no longer list a site’s passkeys', async () => {
    const response: any = await vault.send(
      { type: 'LIST_PASSKEYS_FOR_RP', payload: { rpId: 'bank.example' } },
      PAGE
    );

    expect(response.success).toBe(false);
    expect(JSON.stringify(response)).not.toContain('alice');
  });

  it('cannot sign without the dialog’s approval, even for its own site', async () => {
    const response: any = await vault.send(
      {
        type: 'GET_PASSKEY',
        requestId: 'req-1',
        payload: { selectedPasskeyId: 'cred-alice', publicKey: getPayload().publicKey },
      },
      PAGE
    );

    expect(response.success).toBe(false);
    expect(response.credential).toBeUndefined();
  });

  it('signs once with the passkey the user picked, whatever it asks for', async () => {
    const { token } = await open('req-1');
    await attach(token);
    await decide(token, { action: 'use', id: 'cred-bob' });
    const signIn = {
      type: 'GET_PASSKEY',
      requestId: 'req-1',
      payload: { selectedPasskeyId: 'cred-alice', publicKey: getPayload().publicKey },
    };

    const first: any = await vault.send(signIn, PAGE);
    const second: any = await vault.send(signIn, PAGE);

    expect(first.success).toBe(true);
    expect(first.credential.id).toBe('cred-bob');
    expect(second.success).toBe(false);
  });

  it.each<[string, Record<string, unknown>, MessageSender]>([
    ['another request', { requestId: 'req-2' }, PAGE],
    ['another challenge', { publicKey: { rpId: 'bank.example', challenge: 'BBBB' } }, PAGE],
    ['another frame', {}, { ...PAGE, frameId: 3 }],
    ['another tab', {}, { ...PAGE, tab: { id: 8, url: 'https://bank.example/login' } }],
  ])('cannot use an approval for %s', async (_label, change, sender) => {
    const { token } = await open('req-1');
    await attach(token);
    await decide(token, { action: 'use', id: 'cred-alice' });
    const { publicKey, requestId, ...rest } = {
      publicKey: getPayload().publicKey,
      requestId: 'req-1',
      ...change,
    } as Record<string, unknown>;

    const response: any = await vault.send(
      { type: 'GET_PASSKEY', requestId, payload: { publicKey, ...rest } },
      sender
    );

    expect(response.success).toBe(false);
    expect(response.credential).toBeUndefined();
  });
});

describe('the dialog page', () => {
  it('gets the passkeys with the token, from a frame in the same tab', async () => {
    const { token } = await open();

    const response = await attach(token);

    expect(response.success).toBe(true);
    expect(response.view).toEqual({
      kind: 'get',
      mode: 'frame',
      rpId: 'bank.example',
      passkeys: [
        { id: 'cred-alice', userName: 'alice@bank.example', userDisplayName: 'Alice' },
        { id: 'cred-bob', userName: 'bob@bank.example', userDisplayName: 'Bob' },
      ],
    });
    expect(JSON.stringify(response)).not.toContain(PASSKEYS[0].privateKey);
  });

  it.each<[string, MessageSender]>([
    ['another tab', { ...DIALOG, tab: { id: 8, url: 'https://evil.example/' } }],
    ['the requesting frame itself', { ...DIALOG, frameId: 0 }],
    ['an extension page outside the tab', EXTENSION_PAGE],
    ['another extension page in the tab', { ...DIALOG, url: `${EXTENSION_ORIGIN}/popup.html` }],
    ['a web page claiming the dialog URL', { ...DIALOG, id: 'another-extension' }],
  ])('refuses a claim from %s', async (_label, sender) => {
    const { token } = await open();

    const response = await attach(token, sender);

    expect(response?.success).not.toBe(true);
    expect(JSON.stringify(response ?? null)).not.toContain('alice');
  });

  it('refuses a content script asking as the dialog', async () => {
    const { token } = await open();

    const response = await vault.send({ type: 'PASSKEY_DIALOG_ATTACH', token }, PAGE);

    expect(response?.success).not.toBe(true);
    expect(JSON.stringify(response ?? null)).not.toContain('alice');
  });

  it('refuses a token it did not issue', async () => {
    await open();

    expect((await attach('A'.repeat(43))).success).toBe(false);
    expect((await attach('')).success).toBe(false);
  });

  it('honours only the first claim', async () => {
    const { token } = await open();
    expect((await attach(token)).success).toBe(true);

    const second = await attach(token, { ...DIALOG, frameId: 5 });

    expect(second.success).toBe(false);
  });

  it('can ask for nothing but the dialog messages', async () => {
    const response: any = await vault.send({ type: 'EXPORT_VAULT' }, DIALOG);

    expect(response.success).not.toBe(true);
    expect(JSON.stringify(response)).not.toContain(PASSKEYS[0].privateKey);
  });
});

describe('deciding', () => {
  it('tells the requesting frame the outcome, never which passkey was picked', async () => {
    const { token, dialogId } = await open('req-9');
    await attach(token);

    expect((await decide(token, { action: 'use', id: 'cred-bob' })).success).toBe(true);
    await vault.settle();

    expect(results()).toEqual([
      {
        tabId: 7,
        frameId: 0,
        message: {
          type: 'PASSKEY_DIALOG_RESULT',
          dialogId,
          requestId: 'req-9',
          outcome: 'approved',
        },
      },
    ]);
  });

  it.each([
    ['cancel', { action: 'cancel' }, 'cancel'],
    ['passthrough', { action: 'passthrough' }, 'passthrough'],
  ])('passes on %s', async (_label, decision, outcome) => {
    const { token } = await open();
    await attach(token);

    await decide(token, decision);
    await vault.settle();

    expect(results().map((sent) => sent.message.outcome)).toEqual([outcome]);
  });

  it('accepts a decision only from the frame that claimed the dialog', async () => {
    const { token } = await open();
    await attach(token);

    const response = await decide(
      token,
      { action: 'use', id: 'cred-alice' },
      {
        ...DIALOG,
        frameId: 5,
      }
    );
    await vault.settle();

    expect(response.success).toBe(false);
    expect(results()).toEqual([]);
  });

  it('refuses a decision before any frame claimed the dialog', async () => {
    const { token } = await open();

    expect((await decide(token, { action: 'use', id: 'cred-alice' })).success).toBe(false);
  });

  it('refuses a passkey the dialog did not offer', async () => {
    const { token } = await open(
      'req-1',
      getPayload({ allowCredentials: [{ type: 'public-key', id: 'cred-alice' }] })
    );
    await attach(token);

    expect((await decide(token, { action: 'use', id: 'cred-bob' })).success).toBe(false);
    expect((await decide(token, { action: 'create' })).success).toBe(false);
    await vault.settle();
    expect(results()).toEqual([]);
  });

  it('takes one decision per dialog', async () => {
    const { token } = await open();
    await attach(token);
    await decide(token, { action: 'cancel' });

    expect((await decide(token, { action: 'use', id: 'cred-alice' })).success).toBe(false);
  });

  it('survives a worker restart while the user is choosing', async () => {
    const { token } = await open();
    await attach(token);
    await vault.restartWorker();

    expect((await decide(token, { action: 'use', id: 'cred-alice' })).success).toBe(true);
  });
});

describe('closing a dialog', () => {
  it('closes it when the page gives up', async () => {
    const { token } = await open('req-1');
    await attach(token);

    await vault.send({ type: 'PASSKEY_DIALOG_CANCEL', requestId: 'req-1' }, PAGE);

    expect((await decide(token, { action: 'use', id: 'cred-alice' })).success).toBe(false);
  });

  it('lets only the requesting tab, frame and origin close it', async () => {
    const { token } = await open('req-1');
    await attach(token);

    await vault.send(
      { type: 'PASSKEY_DIALOG_CANCEL', requestId: 'req-1' },
      { ...PAGE, frameId: 2 }
    );

    expect((await decide(token, { action: 'cancel' })).success).toBe(true);
  });

  it('replaces the frame’s earlier dialog, which settles as cancelled', async () => {
    const first = await open('req-1');
    await attach(first.token);

    const second = await open('req-2');
    await vault.settle();

    expect(results().map((sent) => [sent.message.requestId, sent.message.outcome])).toEqual([
      ['req-1', 'cancel'],
    ]);
    expect((await attach(second.token, { ...DIALOG, frameId: 6 })).success).toBe(true);
    expect((await decide(first.token, { action: 'cancel' })).success).toBe(false);
  });
});

describe('a dialog in a window of its own', () => {
  let opened: Array<{ id: number; tabId: number; url: string }>;

  beforeEach(() => {
    opened = [];
    // Nobody answers: these tests speak for the dialog page themselves.
    vault.chrome.onWindowOpened = (window) => opened.push(window);
  });

  const openInWindow = (requestId = 'req-1', extra: Record<string, unknown> = {}) =>
    open(requestId, { ...getPayload(), mode: 'window', ...extra } as any);

  const windowSender = (window: { tabId: number; url: string }): MessageSender => ({
    id: EXTENSION_ID,
    url: window.url,
    origin: EXTENSION_ORIGIN,
    tab: { id: window.tabId, url: window.url },
    frameId: 0,
  });

  const tokenOf = (window: { url: string }) => new URL(window.url).hash.slice(1);

  it('opens the dialog page in a popup window, and gives the page no token', async () => {
    const response = await openInWindow();
    await vault.settle();

    expect(response).toEqual({ success: true, status: 'open', dialogId: expect.any(String) });
    expect(opened).toHaveLength(1);
    expect(opened[0].url).toMatch(/^chrome-extension:\/\/[a-z]+\/vault-dialog\.html#.{43}$/);
  });

  it('lets only that window claim it', async () => {
    await openInWindow();
    await vault.settle();
    const token = tokenOf(opened[0]);

    expect((await attach(token, DIALOG)).success).toBe(false);
    expect((await attach(token, { ...windowSender(opened[0]), frameId: 1 })).success).toBe(false);
    expect((await attach(token, { ...windowSender(opened[0]), tab: { id: 99 } })).success).toBe(
      false
    );
    expect((await attach(token, windowSender(opened[0]))).view).toMatchObject({
      kind: 'get',
      mode: 'window',
    });
  });

  it('closes the window when the user decides', async () => {
    await openInWindow();
    await vault.settle();
    const token = tokenOf(opened[0]);
    await attach(token, windowSender(opened[0]));

    await decide(token, { action: 'use', id: 'cred-alice' }, windowSender(opened[0]));
    await vault.settle();

    expect(vault.chrome.windows.map((window) => window.open)).toEqual([false]);
    expect(results().map((sent) => sent.message.outcome)).toEqual(['approved']);
  });

  it('cancels when the user closes the window', async () => {
    await openInWindow();
    await vault.settle();

    vault.chrome.closeWindow(opened[0].id);
    await vault.settle();

    expect(results().map((sent) => sent.message.outcome)).toEqual(['cancel']);
    expect((await attach(tokenOf(opened[0]), windowSender(opened[0]))).success).toBe(false);
  });

  it('closes the window when the page gives up', async () => {
    await openInWindow('req-1');
    await vault.settle();

    await vault.send({ type: 'PASSKEY_DIALOG_CANCEL', requestId: 'req-1' }, PAGE);
    await vault.settle();

    expect(vault.chrome.windows.map((window) => window.open)).toEqual([false]);
  });

  it('closes the window when the page’s tab closes', async () => {
    await openInWindow('req-1');
    await vault.settle();

    vault.chrome.closeTab(7);
    await vault.settle();

    expect(vault.chrome.windows.map((window) => window.open)).toEqual([false]);
  });

  it('waits for the user to ask before opening an autofill sign-in’s window', async () => {
    await openInWindow('req-1', { deferWindow: true });
    await vault.settle();
    expect(opened).toEqual([]);

    expect(
      (
        await vault.send(
          { type: 'PASSKEY_DIALOG_LAUNCH', requestId: 'req-1' },
          { ...PAGE, frameId: 2 }
        )
      ).success
    ).toBe(false);
    expect(
      (await vault.send({ type: 'PASSKEY_DIALOG_LAUNCH', requestId: 'req-1' }, PAGE)).success
    ).toBe(true);
    await vault.settle();

    expect(opened).toHaveLength(1);
  });
});
