/**
 * The whole extension in one jsdom page: the page-world shim, the content
 * script and the background worker, wired together the way Chrome wires them.
 *
 *   page script ── navigator.credentials.create/get (hooked by webauthn-inject)
 *        │  window.postMessage (structured clone, event.source === window)
 *   content script ── RP ID checks, domain rules
 *        │  chrome.runtime.sendMessage (JSON both ways)
 *   background ── key generation, signing, storage (in-memory chrome.storage)
 *        │  chrome.runtime messages, with the dialog page's own sender
 *   dialog page ── the picker and create confirmation (scripted: `vault.user`)
 *
 * Only the user is simulated. Where the content script would frame the
 * vault's dialog page, a scripted dialog speaks the real protocol to the
 * background instead: it claims the session with the token the content
 * script was given, shows `vault.user` what the background sent, and sends
 * the decision back as the dialog page would. `vault.dialogs` records the
 * frames the content script mounted. The relay-facing sync service is
 * stubbed; everything else is the real code.
 *
 * A test file calls `setupVault()` once at module level. The shim and content
 * script stay loaded for the file, as they do for a page; `vault.reset()`
 * gives each test fresh storage and a fresh background worker.
 */

import {
  FakeChrome,
  EXTENSION_ID,
  EXTENSION_ORIGIN,
  type MessageSender,
  type StorageData,
} from './fake-chrome';
import { installNativeWebAuthn, type NativeAuthenticator } from './native-webauthn';
import { installPostMessage, type PostedMessage } from './post-message';

export interface PasskeyOption {
  id: string;
  credentialId: string;
  userName: string;
  userDisplayName: string;
  rpId: string;
  createdAt: number;
}

export type SelectorResult =
  | { action: 'use'; id: string }
  | { action: 'cancel' }
  | { action: 'passthrough' };

export interface UserScript {
  /**
   * Answer to "Create a passkey for <user> on <rp>?":
   * (rpId, userName, signal) => boolean | Promise<boolean>.
   */
  confirmCreate: jest.Mock;
  /**
   * Answer to the passkey picker, defaulting to the first passkey offered:
   * (options: PasskeyOption[], rpId, signal) => SelectorResult | Promise<SelectorResult>.
   */
  choosePasskey: jest.Mock;
  /**
   * Answer to the in-page card that offers an autofill sign-in where the
   * dialog opens in a window: (rpId) => 'open' | 'cancel' | 'passthrough'.
   */
  launch: jest.Mock;
  createdToast: jest.Mock;
  usedToast: jest.Mock;
  errorToast: jest.Mock;
}

export interface Vault {
  chrome: FakeChrome;
  native: NativeAuthenticator;
  posted: PostedMessage[];
  user: UserScript;
  /** Raw chrome.storage.local, for set-up and assertions. */
  storage: StorageData;
  /** Move the page to another URL (and origin). */
  goto(url: string): void;
  /** Fresh storage, a fresh worker, default user behaviour. */
  reset(seed?: StorageData): Promise<void>;
  /** Terminate the worker and start a new one, as Chrome does after 30s idle. */
  restartWorker(): Promise<void>;
  killWorker(): void;
  /** Send to the background as an extension page (popup/options). */
  send(message: Record<string, unknown>, sender?: MessageSender): Promise<any>;
  /** Wait for in-flight work (timers at zero delay, promise chains) to drain. */
  settle(ticks?: number): Promise<void>;
  /** Passkeys as stored, read through the background. */
  passkeys(): Promise<any[]>;
  /** The current worker's stubbed sync service (its calls, and the vault adapter it was given). */
  syncService: Record<string, jest.Mock>;
  /** The dialogs shown, as frames or windows, in order. */
  dialogs: MountedDialog[];
  /**
   * Where dialogs open: in a frame (Chrome, with IntersectionObserver v2)
   * or in a popup window (Firefox). Reset to 'frame'.
   */
  dialogMode: 'frame' | 'window';
  /** RP IDs of the autofill launcher cards shown (window mode). */
  launchers: string[];
}

export interface MountedDialog {
  token: string;
  kind: string;
  focus: boolean;
  mode: 'frame' | 'window';
  /** What the background showed the dialog, once it claimed its session. */
  view?: any;
  /** The frame is off the page, or the window closed. */
  unmounted: boolean;
  /** Stand in for the page removing the frame, or the user closing the window. */
  remove(): void;
}

const BACKGROUND = '../../src/background/background';
const CONTENT = '../../src/content/content';
const INJECT = '../../src/content/webauthn-inject';
const DIALOG_FRAME = '../../src/content/vault-dialog-frame';
const LAUNCHER = '../../src/content/vault-launcher';
const SYNC_SERVICE = '../../src/sync/sync-service';

export const EXTENSION_PAGE: MessageSender = {
  id: EXTENSION_ID,
  url: `${EXTENSION_ORIGIN}/popup.html`,
  origin: EXTENSION_ORIGIN,
};

/** The vault's dialog page in frame `frameId` of the page's tab. */
export function dialogSender(frameId: number): MessageSender {
  return {
    id: EXTENSION_ID,
    url: `${EXTENSION_ORIGIN}/vault-dialog.html`,
    origin: EXTENSION_ORIGIN,
    tab: { id: 7, url: window.location.href },
    frameId,
  };
}

function syncServiceStub() {
  return {
    syncService: {
      initialize: jest.fn(async () => undefined),
      disconnect: jest.fn(async () => undefined),
      requestSync: jest.fn(async () => undefined),
      broadcastPasskeyUpdate: jest.fn(async () => undefined),
      retryPending: jest.fn(),
      getStatus: jest.fn(() => ({ connected: false, lastError: null })),
      getDebugInfo: jest.fn(() => ({})),
      getDebugLogs: jest.fn(() => []),
      clearDebugLogs: jest.fn(),
    },
  };
}

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function defaultUser(): UserScript {
  return {
    confirmCreate: jest.fn(() => true),
    choosePasskey: jest.fn(
      (options: PasskeyOption[]): SelectorResult =>
        options.length > 0 ? { action: 'use', id: options[0].id } : { action: 'cancel' }
    ),
    launch: jest.fn(() => 'open'),
    createdToast: jest.fn(),
    usedToast: jest.fn(),
    errorToast: jest.fn(),
  };
}

/**
 * Load the extension into this test file's jsdom window. Requires the
 * vault environment (tests/helpers/vault-environment.js) for `goto`.
 */
export function setupVault(
  initialUrl = 'https://example.com/login',
  options: {
    /**
     * Mount the real dialog frame instead of the scripted dialog page. jsdom
     * does not load the frame, so nobody answers the dialog: for tests of
     * what the page itself can see.
     */
    realDialogFrame?: boolean;
  } = {}
): Vault {
  const chrome = new FakeChrome();
  chrome.install();
  const native = installNativeWebAuthn();
  const posted = installPostMessage();
  const user = defaultUser();
  const win = window as unknown as Record<string, unknown> & {
    __setPageUrl?: (url: string) => void;
  };

  const goto = (url: string) => {
    if (!win.__setPageUrl) {
      throw new Error('goto() needs @jest-environment ./tests/helpers/vault-environment.js');
    }
    win.__setPageUrl(url);
  };
  goto(initialUrl);

  chrome.contentSender = () => ({
    id: EXTENSION_ID,
    url: window.location.href,
    origin: window.location.origin,
    tab: { id: 7, url: window.location.href },
    frameId: 0,
  });

  // The in-page notices are bound when content.js loads, so install
  // forwarding stubs that consult whatever `vault.user` holds at call time.
  const vault = {
    user,
    dialogs: [] as MountedDialog[],
    dialogMode: 'frame',
    launchers: [] as string[],
  } as Vault;
  win.showPasskeyCreatedNotification = (...args: unknown[]) => vault.user.createdToast(...args);
  win.showPasskeyUsedNotification = (...args: unknown[]) => vault.user.usedToast(...args);
  win.showErrorNotification = (...args: unknown[]) => vault.user.errorToast(...args);

  const startWorker = () => {
    chrome.startWorker(() => {
      jest.isolateModules(() => {
        jest.doMock(SYNC_SERVICE, syncServiceStub);
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        require(BACKGROUND);
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        vault.syncService = require(SYNC_SERVICE).syncService;
      });
    });
  };

  // Drain timers at zero delay and promise chains, then keep going until the
  // worker has answered every message it was sent, so work started by one
  // test cannot land in the next test's storage.
  const settle = async (ticks = 25) => {
    for (let i = 0; i < ticks; i++) await tick();
    for (let i = 0; i < 2000 && chrome.pendingMessages > 0; i++) await tick();
    for (let i = 0; i < ticks; i++) await tick();
  };

  Object.assign(vault, {
    chrome,
    native,
    posted,
    storage: chrome.local.data,
    goto,
    settle,
    async reset(seed: StorageData = {}) {
      await settle();
      chrome.killWorker();
      chrome.faults.length = 0;
      chrome.local.seed(seed);
      chrome.sessionArea.seed({});
      chrome.sentToBackground.length = 0;
      chrome.sentToTabs.length = 0;
      posted.length = 0;
      vault.dialogs.length = 0;
      vault.dialogMode = 'frame';
      vault.launchers.length = 0;
      chrome.windows.length = 0;
      vault.user = defaultUser();
      native.reset();
      startWorker();
      await settle();
    },
    async restartWorker() {
      chrome.killWorker();
      startWorker();
      await settle();
    },
    killWorker() {
      chrome.killWorker();
    },
    send(message: Record<string, unknown>, sender: MessageSender = EXTENSION_PAGE) {
      return chrome.deliver(message, sender);
    },
    async passkeys() {
      const response = (await chrome.deliver({ type: 'LIST_PASSKEYS' }, EXTENSION_PAGE)) as {
        passkeys?: unknown[];
      };
      return response?.passkeys ?? [];
    },
  });

  /**
   * The dialog page with `vault.user` in front of it: claim the session with
   * the token, show the user what the background sent, send the decision.
   * Nothing is clicked once `closed` fires (the frame or window is gone).
   */
  const scriptDialog = (
    token: string,
    sender: MessageSender,
    closed: AbortSignal,
    mounted: MountedDialog
  ) => {
    const deliver = (message: Record<string, unknown>) =>
      chrome.deliver(message, sender).catch(() => undefined) as Promise<any>;
    void (async () => {
      await tick();
      const attached = await deliver({ type: 'PASSKEY_DIALOG_ATTACH', token });
      if (!attached?.success || closed.aborted) return;
      const view = attached.view;
      mounted.view = view;
      mounted.kind = view.kind;
      let decision: Record<string, unknown>;
      if (view.kind === 'get') {
        const offered: PasskeyOption[] = view.passkeys.map((passkey: any) => ({
          id: passkey.id,
          credentialId: passkey.id,
          userName: passkey.userName,
          userDisplayName: passkey.userDisplayName || passkey.userName || 'Unknown User',
          rpId: view.rpId,
          createdAt: 0,
        }));
        const choice: SelectorResult = await vault.user.choosePasskey(offered, view.rpId, closed);
        decision = choice;
      } else {
        const confirmed = await vault.user.confirmCreate(
          view.rpId,
          view.userName || 'Unknown User',
          closed
        );
        decision = { action: confirmed ? 'create' : 'cancel' };
      }
      if (closed.aborted) return;
      await deliver({ type: 'PASSKEY_DIALOG_DECIDE', token, decision });
    })();
  };

  let nextFrameId = 100;
  /** The dialog page in a frame the content script mounted. */
  const mountDialogFrame = (options: { token: string; kind: string; focus: boolean }) => {
    const unmounted = new AbortController();
    let removed!: () => void;
    const gone = new Promise<void>((resolve) => (removed = resolve));
    const mounted: MountedDialog = {
      ...options,
      mode: 'frame',
      unmounted: false,
      remove: () => removed(),
    };
    vault.dialogs.push(mounted);
    scriptDialog(options.token, dialogSender(nextFrameId++), unmounted.signal, mounted);
    return {
      gone,
      unmount() {
        mounted.unmounted = true;
        unmounted.abort();
      },
    };
  };
  if (!options.realDialogFrame) {
    jest.doMock(DIALOG_FRAME, () => ({
      extensionOrigin: () => EXTENSION_ORIGIN,
      supportsFrameDialogs: () => vault.dialogMode === 'frame',
      mountDialogFrame,
    }));
  }
  jest.doMock(LAUNCHER, () => ({
    showLauncher: (rpId: string) => {
      vault.launchers.push(rpId);
      return {
        choice: Promise.resolve(vault.user.launch(rpId)),
        remove: () => undefined,
      };
    },
  }));

  /** The dialog page in a popup window the background opened. */
  chrome.onWindowOpened = (opened) => {
    const closed = new AbortController();
    const mounted: MountedDialog = {
      token: new URL(opened.url).hash.slice(1),
      kind: '',
      focus: true,
      mode: 'window',
      unmounted: false,
      remove: () => chrome.closeWindow(opened.id),
    };
    vault.dialogs.push(mounted);
    chrome.whenWindowCloses(opened.id, () => {
      mounted.unmounted = true;
      closed.abort();
    });
    const sender: MessageSender = {
      id: EXTENSION_ID,
      url: opened.url,
      origin: EXTENSION_ORIGIN,
      tab: { id: opened.tabId, url: opened.url },
      frameId: 0,
    };
    scriptDialog(mounted.token, sender, closed.signal, mounted);
  };

  startWorker();
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require(CONTENT);
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require(INJECT);
  return vault;
}

/** Resolve once the content script listens to the page (its set-up is async). */
export async function vaultReady(vault: Vault): Promise<void> {
  await vault.settle(50);
}
