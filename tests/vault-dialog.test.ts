/**
 * The dialog page itself: what it shows, and that only the user's own
 * input decides.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  VaultDialog,
  receiveTokenFromParent,
  takeTokenFromUrl,
  type ConsentGate,
  type GateContext,
} from '../src/ui/vault-dialog';
import type { VaultDialogView } from '../src/utils/vault-dialog';
import { trustedClick, trustedKey } from './helpers/trusted-input';

const HTML = fs.readFileSync(path.join(__dirname, '../src/ui/vault-dialog.html'), 'utf8');

const GET_VIEW: VaultDialogView = {
  kind: 'get',
  mode: 'frame',
  rpId: 'bank.example',
  passkeys: [
    { id: 'cred-alice', userName: 'alice@bank.example', userDisplayName: 'Alice' },
    { id: 'cred-bob', userName: 'bob@bank.example', userDisplayName: 'Bob' },
  ],
};

const CREATE_VIEW: VaultDialogView = {
  kind: 'create',
  mode: 'frame',
  rpId: 'bank.example',
  userName: 'Carol',
};

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function openGate(): ConsentGate {
  return {
    isReady: () => true,
    onChange: () => undefined,
    refresh: () => undefined,
    dispose: () => undefined,
  };
}

async function show(
  view: VaultDialogView | null,
  gate: (card: HTMLElement, context: GateContext) => ConsentGate = openGate,
  inWindow = false
): Promise<jest.Mock> {
  document.documentElement.innerHTML = HTML.replace(/^<!doctype html>/i, '');
  const send = jest.fn(async (message: Record<string, unknown>) => {
    if (message.type === 'PASSKEY_DIALOG_ATTACH') {
      return view ? { success: true, view } : { success: false };
    }
    if (message.type === 'PASSKEY_DIALOG_METRICS') return { success: true, dpr: 2 };
    return { success: true };
  });
  const dialog = new VaultDialog({
    window,
    inWindow,
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

describe('consent while the dialog cannot show it is visible', () => {
  /** A gate the test opens and closes, as the browser's visibility reports would. */
  function heldGate() {
    let ready = false;
    let listener = () => undefined as void;
    let context: GateContext | undefined;
    const factory = (_card: HTMLElement, given: GateContext): ConsentGate => {
      context = given;
      return {
        isReady: () => ready,
        onChange: (callback) => (listener = callback),
        refresh: () => undefined,
        dispose: () => undefined,
      };
    };
    const set = (value: boolean) => {
      ready = value;
      listener();
    };
    return { factory, set, context: () => context! };
  }

  afterEach(() => jest.useRealTimers());

  it('ignores Continue until the gate opens, and says so to assistive tech', async () => {
    const gate = heldGate();
    const send = await show(GET_VIEW, gate.factory);

    expect(byId('pkv-continue').getAttribute('aria-disabled')).toBe('true');
    trustedClick(byId('pkv-continue'));
    await flush();
    expect(decisions(send)).toEqual([]);

    gate.set(true);
    expect(byId('pkv-continue').getAttribute('aria-disabled')).toBe('false');
    trustedClick(byId('pkv-continue'));
    await flush();
    expect(decisions(send).map((message) => message.decision)).toEqual([
      { action: 'use', id: 'cred-alice' },
    ]);
  });

  it('ignores Create until the gate opens', async () => {
    const gate = heldGate();
    const send = await show(CREATE_VIEW, gate.factory);

    trustedClick(byId('pkv-create'));
    await flush();
    expect(decisions(send)).toEqual([]);

    gate.set(true);
    trustedClick(byId('pkv-create'));
    await flush();
    expect(decisions(send)).toHaveLength(1);
  });

  it('always lets the user cancel', async () => {
    const gate = heldGate();
    const send = await show(GET_VIEW, gate.factory);

    trustedClick(byId('pkv-cancel'));
    await flush();

    expect(decisions(send).map((message) => message.decision)).toEqual([{ action: 'cancel' }]);
  });

  it('checks its layout again when the selection changes', async () => {
    const refresh = jest.fn();
    let context: GateContext | undefined;
    await show(GET_VIEW, (_card, given) => {
      context = given;
      return { isReady: () => true, onChange: () => undefined, refresh, dispose: () => undefined };
    });

    trustedClick(document.querySelectorAll('.passkey-item')[1]);

    expect(refresh).toHaveBeenCalled();
    // jsdom lays nothing out, so everything is "in view" here.
    expect(context!.fits()).toBe(true);
  });

  it('measures itself against the top page through the background', async () => {
    const gate = heldGate();
    const send = await show(GET_VIEW, gate.factory);

    expect(await gate.context().reference()).toBe(2);
    expect(send).toHaveBeenCalledWith({ type: 'PASSKEY_DIALOG_METRICS', token: 'token-1' });
    expect(gate.context().mode).toBe('frame');
  });

  it('offers a window when it cannot show it is visible for a while', async () => {
    jest.useFakeTimers();
    const gate = heldGate();
    const send = await show(GET_VIEW, gate.factory);

    jest.advanceTimersByTime(1499);
    expect(byId('status').hidden).toBe(true);
    jest.advanceTimersByTime(1);
    expect(byId('status').hidden).toBe(false);
    expect(byId('status').textContent).toContain('Cannot confirm');

    trustedClick(byId('pkv-open-window'));
    for (let i = 0; i < 5; i++) await Promise.resolve();
    expect(send).toHaveBeenCalledWith({ type: 'PASSKEY_DIALOG_ESCALATE', token: 'token-1' });
    expect(decisions(send)).toEqual([]);
  });

  it('does not offer a window once it is visible', async () => {
    jest.useFakeTimers();
    const gate = heldGate();
    await show(GET_VIEW, gate.factory);
    gate.set(true);

    jest.advanceTimersByTime(5000);

    expect(byId('status').hidden).toBe(true);
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

describe('in a window of its own', () => {
  const inWindow = (view: VaultDialogView | null) => show(view, openGate, true);

  it('closes its window once the decision is in', async () => {
    const close = jest.spyOn(window, 'close').mockImplementation(() => undefined);
    await inWindow({ ...GET_VIEW, mode: 'window' });

    trustedClick(byId('pkv-continue'));
    await flush();

    expect(close).toHaveBeenCalled();
    close.mockRestore();
  });

  it('never offers to move to a window: it is one', async () => {
    jest.useFakeTimers();
    const closed = () =>
      ({
        isReady: () => false,
        onChange: () => undefined,
        refresh: () => undefined,
        dispose: () => undefined,
      }) as ConsentGate;
    await show({ ...GET_VIEW, mode: 'window' }, closed, true);

    jest.advanceTimersByTime(5000);
    jest.useRealTimers();

    expect(byId('status').hidden).toBe(true);
  });

  it('offers to close a window whose request is gone', async () => {
    const close = jest.spyOn(window, 'close').mockImplementation(() => undefined);
    await inWindow(null);

    trustedClick(byId('pkv-close'));

    expect(close).toHaveBeenCalled();
    close.mockRestore();
  });

  it('takes its token from the URL, and drops it from the address', () => {
    const replaceState = jest.fn();
    const win = {
      location: { hash: '#the-token', pathname: '/vault-dialog.html' },
      history: { replaceState },
    } as unknown as Window;

    expect(takeTokenFromUrl(win)).toBe('the-token');
    expect(replaceState).toHaveBeenCalledWith(null, '', '/vault-dialog.html');
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
