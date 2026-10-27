/**
 * Sessions for the vault's ceremony dialogs (see src/utils/vault-dialog.ts).
 *
 * A content script opens a session for one of its page's requests and gets
 * back a token, which it hands to the dialog page it frames. The dialog page
 * claims the session with that token, gets what to show, and sends the
 * user's decision here. Nothing the dialog shows passes through the page or
 * the content script, and only the dialog page can decide.
 *
 * Where the content script cannot frame the dialog (no IntersectionObserver
 * v2 to prove the frame is visible), the session opens the dialog page in
 * a popup window of its own, with the token in its URL, and only that
 * window may claim it.
 *
 * Sessions live in chrome.storage.session, which content scripts cannot
 * read, so a service worker that Chrome stops while the user is choosing
 * hands the session to the next one.
 */

import { arrayBufferToBase64URL } from '../utils/base64';
import {
  DIALOG_MESSAGES,
  DIALOG_WINDOW_SIZE,
  VAULT_DIALOG_PAGE,
  isVaultDialogSender,
  type VaultDialogDecision,
  type VaultDialogKind,
  type VaultDialogMode,
  type VaultDialogOutcome,
  type VaultDialogPasskey,
  type VaultDialogView,
} from '../utils/vault-dialog';

type Payload = Record<string, unknown>;

export interface DialogSender {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number; url?: string };
  frameId?: number;
  documentId?: string;
}

/** A content script's request, after the background bound it to the sender. */
export interface BoundRequest {
  type: string;
  payload?: Payload;
  requestId?: string;
  requester?: string;
}

interface DialogSession {
  id: string;
  token: string;
  kind: VaultDialogKind;
  state: 'pending' | 'approved';
  /** The requesting content script: tab, frame, and "tab:frame:origin". */
  tabId: number;
  frameId: number;
  requester: string;
  requestId: string;
  rpId: string;
  /** What the user's approval covers; the ceremony must match it exactly. */
  binding: string;
  view: VaultDialogView;
  /** Passkeys the picker offered; the only ones the user can approve. */
  passkeyIds: string[];
  approvedPasskeyId?: string;
  /** The dialog document that claimed the session. */
  dialog?: { tabId: number; frameId: number; documentId?: string };
  /** Window mode: where the dialog page was opened, once it was. */
  window?: DialogWindow;
  expiresAt: number;
  decidedAt?: number;
}

interface DialogWindow {
  /** A conditional sign-in waits for the user to ask for the window. */
  deferred: boolean;
  opened: boolean;
  windowId?: number;
  tabId?: number;
  /** Opened as a tab, where the browser has no popup windows (Android). */
  asTab?: boolean;
}

export interface DialogBrokerDeps {
  /** Throws (with the vault's locked error) when the vault is locked. */
  assertUnlocked(): Promise<void>;
  /** The passkeys stored for an RP ID. */
  passkeysFor(rpId: string): Promise<
    Array<{
      id: string;
      credentialId?: string;
      user?: { name?: string; displayName?: string };
    }>
  >;
}

const STORAGE_KEY = 'vault_dialog_sessions';
/** A dialog nobody answers is dropped after this; the page gives up sooner. */
const SESSION_TTL_MS = 10 * 60 * 1000;
/** How long an approval waits for the content script's ceremony message. */
const APPROVAL_TTL_MS = 2 * 60 * 1000;

function randomToken(): string {
  return arrayBufferToBase64URL(crypto.getRandomValues(new Uint8Array(32)).buffer);
}

/**
 * The part of a ceremony the user approves: the origin and frame it runs
 * in, and every option the page passed. The ceremony message must carry the
 * same, so an approval for one request cannot sign or create for another.
 */
export function ceremonyBinding(payload: Payload): string {
  return JSON.stringify([
    payload.origin ?? null,
    payload.crossOrigin === true,
    payload.topOrigin ?? null,
    payload.publicKey ?? null,
  ]);
}

function rpIdOf(payload: Payload): string {
  const publicKey = (payload.publicKey as Payload | undefined) ?? {};
  return String(publicKey.rpId ?? '');
}

export class DialogBroker {
  private queue: Promise<unknown> = Promise.resolve();
  private memory: Record<string, DialogSession> = {};

  /** Windows being opened; a claim from one waits until its IDs are known. */
  private opening = new Set<Promise<void>>();

  constructor(private readonly deps: DialogBrokerDeps) {
    // Closing the dialog's window is the user saying no.
    chrome.windows?.onRemoved?.addListener((windowId: number) => {
      void this.closed((session) => session.window?.windowId === windowId);
    });
    chrome.tabs?.onRemoved?.addListener((tabId: number) => {
      void this.closed(
        (session) =>
          (session.window?.asTab === true && session.window.tabId === tabId) ||
          session.tabId === tabId
      );
    });
  }

  // ==================== STORAGE ====================

  private area(): chrome.storage.StorageArea | null {
    return (chrome.storage as { session?: chrome.storage.StorageArea }).session ?? null;
  }

  /** Run `change` on the sessions, one change at a time, and save them. */
  private update<T>(change: (sessions: Record<string, DialogSession>) => T | Promise<T>) {
    const run = this.queue.then(async () => {
      const area = this.area();
      const sessions: Record<string, DialogSession> = area
        ? (((await area.get(STORAGE_KEY))[STORAGE_KEY] as Record<string, DialogSession>) ?? {})
        : this.memory;
      const now = Date.now();
      const expired = Object.values(sessions).filter((session) => session.expiresAt <= now);
      for (const session of expired) delete sessions[session.id];
      const result = await change(sessions);
      if (area) await area.set({ [STORAGE_KEY]: sessions });
      for (const session of expired) void this.closeWindow(session);
      return result;
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  // ==================== CONTENT SCRIPT ====================

  /**
   * Open a session for a page request. For a sign-in, the passkeys come from
   * the vault here and go only to the dialog: the content script learns
   * whether there is one to offer, not which.
   */
  async open(message: BoundRequest, sender: DialogSender): Promise<unknown> {
    const payload = message.payload ?? {};
    const kind = payload.kind;
    const mode: VaultDialogMode = payload.mode === 'window' ? 'window' : 'frame';
    const requestId = message.requestId;
    const tabId = sender.tab?.id;
    if (
      (kind !== 'get' && kind !== 'create') ||
      typeof requestId !== 'string' ||
      !requestId ||
      typeof tabId !== 'number' ||
      typeof sender.frameId !== 'number' ||
      !message.requester
    ) {
      return { success: false, error: 'Invalid dialog request' };
    }
    const rpId = rpIdOf(payload);
    const publicKey = (payload.publicKey as Payload | undefined) ?? {};

    let view: VaultDialogView;
    let passkeyIds: string[] = [];
    if (kind === 'get') {
      await this.deps.assertUnlocked();
      const allowed = ((publicKey.allowCredentials as Array<{ id?: unknown }> | undefined) ?? [])
        .map((credential) => credential?.id)
        .filter((id): id is string => typeof id === 'string' && id.length > 0);
      const offered = (await this.deps.passkeysFor(rpId)).filter(
        (passkey) => allowed.length === 0 || allowed.includes(passkey.credentialId || passkey.id)
      );
      if (offered.length === 0) {
        return { success: true, status: 'none' };
      }
      passkeyIds = offered.map((passkey) => passkey.id);
      const passkeys: VaultDialogPasskey[] = offered.map((passkey) => ({
        id: passkey.id,
        userName: passkey.user?.name || '',
        userDisplayName: passkey.user?.displayName || '',
      }));
      view = { kind, mode, rpId, passkeys };
    } else {
      const user = (publicKey.user as Payload | undefined) ?? {};
      const userName = String(user.displayName || user.name || '');
      view = { kind, mode, rpId, userName };
    }

    const session: DialogSession = {
      id: randomToken(),
      token: randomToken(),
      kind,
      state: 'pending',
      tabId,
      frameId: sender.frameId,
      requester: message.requester,
      requestId,
      rpId,
      binding: ceremonyBinding(payload),
      view,
      passkeyIds,
      ...(mode === 'window' && {
        window: { deferred: payload.deferWindow === true, opened: false },
      }),
      expiresAt: Date.now() + SESSION_TTL_MS,
    };
    const replaced = await this.update((sessions) => {
      // One dialog per frame, as on screen: a new request replaces any
      // dialog the same frame still has open.
      const previous = Object.values(sessions).filter(
        (other) => other.requester === session.requester && other.state === 'pending'
      );
      for (const other of previous) delete sessions[other.id];
      sessions[session.id] = session;
      return previous;
    });
    for (const other of replaced) this.ended(other, 'cancel');
    if (mode === 'window') {
      if (!session.window?.deferred) await this.openWindow(session.id);
      // The token is for the window the background opens, not the page.
      return { success: true, status: 'open', dialogId: session.id };
    }
    return { success: true, status: 'open', dialogId: session.id, token: session.token };
  }

  /** The user asked for the window of a deferred (autofill) sign-in. */
  async launch(message: BoundRequest): Promise<unknown> {
    const session = await this.update((sessions) =>
      Object.values(sessions).find(
        (candidate) =>
          candidate.requester === message.requester &&
          candidate.requestId === message.requestId &&
          candidate.state === 'pending' &&
          candidate.window?.deferred === true
      )
    );
    if (!session) return { success: false, error: 'This request is no longer active' };
    await this.openWindow(session.id);
    return { success: true };
  }

  /** The page stopped waiting: close the request's dialog. */
  async cancel(message: BoundRequest): Promise<unknown> {
    const closed = await this.update((sessions) => {
      const found = Object.values(sessions).filter(
        (session) =>
          session.requester === message.requester && session.requestId === message.requestId
      );
      for (const session of found) delete sessions[session.id];
      return found;
    });
    for (const session of closed) void this.closeWindow(session);
    return { success: closed.length > 0 };
  }

  /**
   * The approval a ceremony message needs: the dialog approved this request
   * (same tab, frame, origin and request ID) for these exact options, and it
   * has not been used yet. Returns the passkey the user picked, for a
   * sign-in. Throws otherwise.
   */
  async consumeApproval(message: BoundRequest, kind: VaultDialogKind): Promise<string | undefined> {
    const binding = ceremonyBinding(message.payload ?? {});
    // Used up even when it does not match: one approval, one attempt.
    const session = await this.update((sessions) => {
      const found = Object.values(sessions).find(
        (candidate) =>
          candidate.requester === message.requester &&
          candidate.requestId === message.requestId &&
          candidate.kind === kind &&
          candidate.state === 'approved'
      );
      if (found) delete sessions[found.id];
      return found;
    });
    if (
      !session ||
      session.binding !== binding ||
      Date.now() - (session.decidedAt ?? 0) > APPROVAL_TTL_MS
    ) {
      throw new Error('The user did not approve this request');
    }
    return session.approvedPasskeyId;
  }

  // ==================== DIALOG PAGE ====================

  /** Route a message from the dialog page. Anything else it sends is refused. */
  async handleDialogMessage(message: Payload, sender: DialogSender): Promise<unknown> {
    if (!isVaultDialogSender(sender, chrome.runtime.id)) {
      throw new Error('Not the vault dialog');
    }
    const token = typeof message.token === 'string' ? message.token : '';
    switch (message.type) {
      case DIALOG_MESSAGES.ATTACH:
        return this.attach(token, sender);
      case DIALOG_MESSAGES.DECIDE:
        return this.decide(token, sender, message.decision as VaultDialogDecision | undefined);
      case DIALOG_MESSAGES.METRICS:
        return this.metrics(token, sender);
      case DIALOG_MESSAGES.ESCALATE:
        return this.escalate(token, sender);
      default:
        throw new Error(`${String(message.type)} is not available to the vault dialog`);
    }
  }

  /**
   * Claim a session. The token reached the dialog only through the content
   * script, by postMessage to the extension's origin; a page that frames the
   * dialog page itself has no token to give it. The claim also has to come
   * from a frame of the requesting tab other than the requester's own, and
   * only the first claim counts.
   */
  private async attach(token: string, sender: DialogSender): Promise<unknown> {
    await Promise.all(this.opening);
    const view = await this.update((sessions) => {
      const session = Object.values(sessions).find((candidate) => candidate.token === token);
      if (!session || !token || session.state !== 'pending' || session.dialog) return undefined;
      if (!this.mayClaim(session, sender)) return undefined;
      session.dialog = {
        tabId: sender.tab!.id!,
        frameId: sender.frameId!,
        documentId: sender.documentId,
      };
      return session.view;
    });
    if (!view) {
      return { success: false, error: 'This request is no longer active' };
    }
    return { success: true, view };
  }

  private mayClaim(session: DialogSession, sender: DialogSender): boolean {
    if (session.view.mode === 'window') {
      // Only the top frame of the window the background opened.
      return (
        session.window?.tabId !== undefined &&
        sender.tab?.id === session.window.tabId &&
        sender.frameId === 0
      );
    }
    return (
      sender.tab?.id === session.tabId &&
      typeof sender.frameId === 'number' &&
      sender.frameId !== 0 &&
      sender.frameId !== session.frameId
    );
  }

  private async decide(
    token: string,
    sender: DialogSender,
    decision: VaultDialogDecision | undefined
  ): Promise<unknown> {
    const decided = await this.update((sessions) => {
      const session = Object.values(sessions).find((candidate) => candidate.token === token);
      if (!session || !token || session.state !== 'pending' || !this.isClaimant(session, sender)) {
        return undefined;
      }
      const outcome = this.apply(session, decision);
      if (!outcome) return undefined;
      if (outcome === 'approved') {
        session.state = 'approved';
        session.decidedAt = Date.now();
      } else {
        delete sessions[session.id];
      }
      return { session: { ...session }, outcome };
    });
    if (!decided) {
      return { success: false, error: 'This request is no longer active' };
    }
    this.ended(decided.session, decided.outcome);
    return { success: true };
  }

  /**
   * The top-level page's devicePixelRatio, which a framed dialog compares
   * with its own: CSS zoom on any ancestor of the frame changes the
   * frame's ratio but not the top page's. Read from the top frame's content
   * script, in its isolated world, so the page cannot answer for it.
   */
  private async metrics(token: string, sender: DialogSender): Promise<unknown> {
    const session = await this.update((sessions) =>
      Object.values(sessions).find(
        (candidate) =>
          !!token &&
          candidate.token === token &&
          candidate.state === 'pending' &&
          this.isClaimant(candidate, sender)
      )
    );
    if (!session) return { success: false, error: 'This request is no longer active' };
    try {
      const answer = (await chrome.tabs.sendMessage(
        session.tabId,
        { type: DIALOG_MESSAGES.TOP_METRICS },
        { frameId: 0 }
      )) as { dpr?: unknown } | undefined;
      if (typeof answer?.dpr === 'number' && answer.dpr > 0) {
        return { success: true, dpr: answer.dpr };
      }
    } catch {
      // No content script in the top frame (a page the vault does not run
      // on): the dialog cannot vouch for its size, and offers a window.
    }
    return { success: false, error: 'The top page did not answer' };
  }

  /**
   * Move a framed dialog that cannot show it is visible to a window. The
   * frame's claim and token end here; the window gets a new token.
   */
  private async escalate(token: string, sender: DialogSender): Promise<unknown> {
    const moved = await this.update((sessions) => {
      const session = Object.values(sessions).find((candidate) => candidate.token === token);
      if (
        !session ||
        !token ||
        session.state !== 'pending' ||
        session.view.mode !== 'frame' ||
        !this.isClaimant(session, sender)
      ) {
        return undefined;
      }
      session.token = randomToken();
      session.dialog = undefined;
      session.view = { ...session.view, mode: 'window' };
      session.window = { deferred: false, opened: false };
      return { ...session };
    });
    if (!moved) return { success: false, error: 'This request is no longer active' };
    void this.notify(moved, 'escalated');
    await this.openWindow(moved.id);
    return { success: true };
  }

  private isClaimant(session: DialogSession, sender: DialogSender): boolean {
    const claimed = session.dialog;
    return (
      !!claimed &&
      claimed.tabId === sender.tab?.id &&
      claimed.frameId === sender.frameId &&
      (claimed.documentId === undefined || claimed.documentId === sender.documentId)
    );
  }

  /** What a decision means for a session, or undefined if it does not apply. */
  private apply(
    session: DialogSession,
    decision: VaultDialogDecision | undefined
  ): VaultDialogOutcome | undefined {
    switch (decision?.action) {
      case 'cancel':
        return 'cancel';
      case 'passthrough':
        return session.kind === 'get' ? 'passthrough' : undefined;
      case 'use':
        if (session.kind !== 'get' || !session.passkeyIds.includes(decision.id)) return undefined;
        session.approvedPasskeyId = decision.id;
        return 'approved';
      case 'create':
        return session.kind === 'create' ? 'approved' : undefined;
      default:
        return undefined;
    }
  }

  // ==================== WINDOWS ====================

  /** Open a window-mode session's dialog page in a popup window. */
  private openWindow(id: string): Promise<void> {
    const opening = this.placeWindow(id);
    this.opening.add(opening);
    return opening.finally(() => this.opening.delete(opening));
  }

  private async placeWindow(id: string): Promise<void> {
    const target = await this.update((sessions) => {
      const session = sessions[id];
      if (!session?.window || session.window.opened || session.state !== 'pending') return;
      session.window.opened = true;
      session.window.deferred = false;
      return { token: session.token, kind: session.kind, tabId: session.tabId };
    });
    if (!target) return;

    // Relative, so it resolves to the extension's own origin: getURL() gives
    // Chrome's per-session URL for this web-accessible page, which is for
    // the pages that frame it and does not load in a window.
    const url = `${VAULT_DIALOG_PAGE}#${target.token}`;
    let placed: Pick<DialogWindow, 'windowId' | 'tabId' | 'asTab'> | undefined;
    try {
      if (chrome.windows?.create) {
        const created = await this.createWindow(
          url,
          await this.windowBounds(target.tabId, target.kind)
        );
        placed = { windowId: created?.id, tabId: created?.tabs?.[0]?.id };
      } else {
        const tab = await chrome.tabs.create({ url, active: true });
        placed = { tabId: tab?.id, asTab: true };
      }
    } catch (error) {
      console.warn('Could not open the vault dialog window', error);
    }

    const kept = await this.update((sessions) => {
      const session = sessions[id];
      if (!session?.window) return undefined;
      if (placed?.tabId === undefined) {
        delete sessions[id];
        return { session, ok: false };
      }
      Object.assign(session.window, placed);
      return { session, ok: true };
    });
    if (!kept) {
      // The request ended while the window was opening.
      if (placed) void this.closeWindow({ window: { deferred: false, opened: true, ...placed } });
      return;
    }
    if (!kept.ok) void this.notify(kept.session, 'cancel');
  }

  /**
   * Open the dialog window at `bounds`, or at the browser's own position
   * when it refuses them. Chrome rejects bounds less than half on a visible
   * screen ("Bounds must be at least 50% within visible screen space"),
   * which a requesting window parked mostly off-screen or spanning
   * monitors produces; without the retry that cancelled the ceremony.
   */
  private async createWindow(
    url: string,
    bounds: { width: number; height: number; left?: number; top?: number }
  ): Promise<chrome.windows.Window | undefined> {
    const options = { url, type: 'popup' as const, focused: true };
    try {
      return await chrome.windows.create({ ...options, ...bounds });
    } catch (error) {
      if (bounds.left === undefined && bounds.top === undefined) throw error;
      console.warn('The browser refused the dialog window position; opening it unplaced', error);
      return chrome.windows.create({ ...options, width: bounds.width, height: bounds.height });
    }
  }

  /** Centre the dialog over the requesting tab's window, where the browser says where that is. */
  private async windowBounds(
    tabId: number,
    kind: VaultDialogKind
  ): Promise<{ width: number; height: number; left?: number; top?: number }> {
    const size = DIALOG_WINDOW_SIZE[kind];
    try {
      const tab = await chrome.tabs.get(tabId);
      const parent = await chrome.windows.get(tab.windowId);
      if (
        typeof parent.left === 'number' &&
        typeof parent.top === 'number' &&
        typeof parent.width === 'number'
      ) {
        return {
          ...size,
          left: Math.round(parent.left + (parent.width - size.width) / 2),
          top: parent.top + 80,
        };
      }
    } catch {
      // Let the browser place it.
    }
    return size;
  }

  private async closeWindow(session: Pick<DialogSession, 'window'>): Promise<void> {
    const placed = session.window;
    try {
      if (placed?.asTab && placed.tabId !== undefined) {
        await chrome.tabs.remove(placed.tabId);
      } else if (placed?.windowId !== undefined) {
        await chrome.windows.remove(placed.windowId);
      }
    } catch {
      // Already closed.
    }
  }

  /** A window or tab closed: end the pending dialogs it held. */
  private async closed(match: (session: DialogSession) => boolean): Promise<void> {
    const ended = await this.update((sessions) => {
      const found = Object.values(sessions).filter(
        (session) => session.state === 'pending' && match(session)
      );
      for (const session of found) delete sessions[session.id];
      return found;
    });
    for (const session of ended) this.ended(session, 'cancel');
  }

  // ==================== HELPERS ====================

  /** A dialog ended: close its window, and tell the content script. */
  private ended(session: DialogSession, outcome: VaultDialogOutcome): void {
    void this.closeWindow(session);
    void this.notify(session, outcome);
  }

  /** Tell the requesting content script how its dialog ended. */
  private async notify(session: DialogSession, outcome: VaultDialogOutcome): Promise<void> {
    try {
      await chrome.tabs.sendMessage(
        session.tabId,
        {
          type: DIALOG_MESSAGES.RESULT,
          dialogId: session.id,
          requestId: session.requestId,
          outcome,
        },
        { frameId: session.frameId }
      );
    } catch {
      // The frame navigated away or closed; nobody is waiting.
    }
  }
}
