/**
 * The dialog page itself: what it shows, and that only the user's own
 * input decides.
 */

import * as fs from 'fs';
import * as path from 'path';
import { VaultDialog, receiveTokenFromParent, type ConsentGate } from '../src/ui/vault-dialog';
import type { VaultDialogView } from '../src/utils/vault-dialog';
import { trustedClick, trustedKey } from './helpers/trusted-input';

const HTML = fs.readFileSync(path.join(__dirname, '../src/ui/vault-dialog.html'), 'utf8');

const GET_VIEW: VaultDialogView = {
  kind: 'get',
  rpId: 'bank.example',
  passkeys: [
    { id: 'cred-alice', userName: 'alice@bank.example', userDisplayName: 'Alice' },
    { id: 'cred-bob', userName: 'bob@bank.example', userDisplayName: 'Bob' },
  ],
};

const CREATE_VIEW: VaultDialogView = { kind: 'create', rpId: 'bank.example', userName: 'Carol' };

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function openGate(): ConsentGate {
  return { isReady: () => true, onChange: () => undefined, dispose: () => undefined };
}

async function show(
  view: VaultDialogView | null,
  gate: () => ConsentGate = openGate
): Promise<jest.Mock> {
  document.documentElement.innerHTML = HTML.replace(/^<!doctype html>/i, '');
  const send = jest.fn(async (message: Record<string, unknown>) => {
    if (message.type === 'PASSKEY_DIALOG_ATTACH') {
      return view ? { success: true, view } : { success: false };
    }
    return { success: true };
  });
  const dialog = new VaultDialog({
    window,
    token: async () => 'token-1',
    send,
    createGate: gate,
  });
  await dialog.start();
  return send;
}

const decisions = (send: jest.Mock) =>
  send.mock.calls
    .map(([message]) => message)
    .filter((message) => message.type === 'PASSKEY_DIALOG_DECIDE');

const byId = (id: string) => document.getElementById(id)!;

describe('the passkey picker', () => {
  it('lists the passkeys, the first one selected', async () => {
    await show(GET_VIEW);

    const items = Array.from(document.querySelectorAll('.passkey-item'));
    expect(items.map((item) => item.textContent)).toEqual([
      expect.stringContaining('Alice'),
      expect.stringContaining('Bob'),
    ]);
    expect(items.map((item) => item.getAttribute('aria-checked'))).toEqual(['true', 'false']);
    expect(byId('subtitle').textContent).toContain('bank.example');
  });

  it('signs in with the passkey the user picked', async () => {
    const send = await show(GET_VIEW);

    trustedClick(document.querySelectorAll('.passkey-item')[1]);
    trustedClick(byId('pkv-continue'));
    await flush();

    expect(decisions(send)).toEqual([
      {
        type: 'PASSKEY_DIALOG_DECIDE',
        token: 'token-1',
        decision: { action: 'use', id: 'cred-bob' },
      },
    ]);
  });

  it('moves the selection with the arrow keys', async () => {
    const send = await show(GET_VIEW);

    trustedKey(document.querySelectorAll('.passkey-item')[0], 'ArrowDown');
    trustedClick(byId('pkv-continue'));
    await flush();

    expect(decisions(send)[0].decision).toEqual({ action: 'use', id: 'cred-bob' });
    expect(document.activeElement).toBe(document.querySelectorAll('.passkey-item')[1]);
  });

  it('ignores clicks and keys that script made up', async () => {
    const send = await show(GET_VIEW);

    (document.querySelectorAll('.passkey-item')[1] as HTMLElement).click();
    byId('pkv-continue').click();
    byId('pkv-continue').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await flush();

    expect(decisions(send)).toEqual([]);
  });

  it.each([
    ['pkv-cancel', { action: 'cancel' }],
    ['pkv-passthrough', { action: 'passthrough' }],
  ])('passes on %s', async (button, decision) => {
    const send = await show(GET_VIEW);

    trustedClick(byId(button));
    await flush();

    expect(decisions(send).map((message) => message.decision)).toEqual([decision]);
  });

  it('cancels on Escape', async () => {
    const send = await show(GET_VIEW);

    trustedKey(document, 'Escape');
    await flush();

    expect(decisions(send).map((message) => message.decision)).toEqual([{ action: 'cancel' }]);
  });

  it('takes one decision', async () => {
    const send = await show(GET_VIEW);

    trustedClick(byId('pkv-continue'));
    trustedClick(byId('pkv-cancel'));
    await flush();

    expect(decisions(send)).toHaveLength(1);
  });

  it('starts with focus on the selection, not on a button that confirms', async () => {
    await show(GET_VIEW);

    expect(document.activeElement).toBe(document.querySelector('.passkey-item'));
  });
});

describe('the create confirmation', () => {
  it('names the account and the site, and creates on Create', async () => {
    const send = await show(CREATE_VIEW);

    expect(byId('subtitle').textContent).toBe('Create a passkey for Carol on bank.example?');
    trustedClick(byId('pkv-create'));
    await flush();

    expect(decisions(send).map((message) => message.decision)).toEqual([{ action: 'create' }]);
  });

  it('starts with focus on the dialog, not on Create', async () => {
    await show(CREATE_VIEW);

    expect(document.activeElement).toBe(byId('card'));
  });
});

describe('a dialog whose request is gone', () => {
  it('says so, and offers nothing to click', async () => {
    const send = await show(null);

    expect(byId('subtitle').textContent).toBe('This request is no longer active.');
    expect(document.querySelectorAll('button')).toHaveLength(0);
    expect(decisions(send)).toEqual([]);
  });
});

describe('the token', () => {
  function fakeWindow() {
    const listeners: Array<(event: MessageEvent) => void> = [];
    const parent = {} as Window;
    const win = {
      parent,
      addEventListener: (_type: string, listener: (event: MessageEvent) => void) =>
        listeners.push(listener),
      removeEventListener: jest.fn(),
    } as unknown as Window;
    const post = (data: unknown, source: unknown) =>
      listeners.forEach((listener) => listener({ data, source } as MessageEvent));
    return { win, parent, post };
  }

  it('is taken only from the parent frame, in the expected shape', async () => {
    const { win, parent, post } = fakeWindow();
    let token: string | undefined;
    void receiveTokenFromParent(win).then((value) => (token = value));

    post({ type: 'fenko-vault-dialog-token', token: 'from-elsewhere' }, {});
    post({ type: 'something-else', token: 'wrong-type' }, parent);
    post({ type: 'fenko-vault-dialog-token', token: 42 }, parent);
    post({ type: 'fenko-vault-dialog-token', token: 'real' }, parent);
    await flush();

    expect(token).toBe('real');
  });

  it('is never taken in a top-level window', async () => {
    const { win, post } = fakeWindow();
    (win as { parent: Window }).parent = win;
    let token: string | undefined;
    void receiveTokenFromParent(win).then((value) => (token = value));

    post({ type: 'fenko-vault-dialog-token', token: 'self' }, win);
    await flush();

    expect(token).toBeUndefined();
  });
});
